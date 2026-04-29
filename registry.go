package caddymcp

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

var (
	ErrTunnelNotDeclared = errors.New("tunnel not declared in Caddyfile")
	ErrTunnelClaimed     = errors.New("tunnel already claimed by another client")
)

type tunnelState int

const (
	stateUndeclared tunnelState = iota
	stateUnclaimed
	stateClaimed
	stateDeprecated
)

const defaultMaxSessions = 50

type tunnelCapabilities struct {
	Tools     []string `json:"tools,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Prompts   []string `json:"prompts,omitempty"`
}

type tunnel struct {
	Name         string
	ID           uint32
	Conn         *quic.Conn
	state        tunnelState
	visitors     atomic.Int64
	capabilities *tunnelCapabilities
}

type tunnelSnapshot struct {
	ID          uint32
	Conn        *quic.Conn
	visitors    *atomic.Int64
	maxVisitors int64
}

func (s *tunnelSnapshot) TryAddVisitor() bool {
	if s.visitors.Add(1) > s.maxVisitors {
		s.visitors.Add(-1)
		return false
	}
	return true
}

func (s *tunnelSnapshot) VisitorDone() { s.visitors.Add(-1) }

type tunnelRegistry struct {
	mu      sync.RWMutex
	tunnels map[string]*tunnel
	nextID  uint32
}

func newTunnelRegistry() *tunnelRegistry {
	return &tunnelRegistry{
		tunnels: make(map[string]*tunnel),
	}
}

func (r *tunnelRegistry) declare(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tunnels[name]; exists {
		return
	}
	r.nextID++
	r.tunnels[name] = &tunnel{
		Name:  name,
		ID:    r.nextID,
		state: stateUnclaimed,
	}
	metricTunnelsDeclared.Inc()
}

func (r *tunnelRegistry) isDeclared(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tunnels[name]
	return ok
}

func (r *tunnelRegistry) claim(name string, conn *quic.Conn) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tunnels[name]
	if !ok || t.state == stateDeprecated {
		return 0, ErrTunnelNotDeclared
	}
	if t.state == stateClaimed {
		return 0, ErrTunnelClaimed
	}
	t.Conn = conn
	t.state = stateClaimed
	return t.ID, nil
}

func (r *tunnelRegistry) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tunnels[name]
	if !ok {
		return
	}
	t.Conn = nil
	t.capabilities = nil
	if t.state == stateClaimed {
		t.state = stateUnclaimed
	}
}

func (r *tunnelRegistry) clientFor(name string, maxVisitors int) (tunnelSnapshot, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[name]
	if !ok || t.state != stateClaimed || t.Conn == nil {
		return tunnelSnapshot{}, false
	}
	if maxVisitors <= 0 {
		maxVisitors = defaultMaxSessions
	}
	return tunnelSnapshot{
		ID:          t.ID,
		Conn:        t.Conn,
		visitors:    &t.visitors,
		maxVisitors: int64(maxVisitors),
	}, true
}

func (r *tunnelRegistry) status(name string) tunnelState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[name]
	if !ok {
		return stateUndeclared
	}
	return t.state
}

func (r *tunnelRegistry) setCapabilities(name string, caps *tunnelCapabilities) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tunnels[name]; ok {
		t.capabilities = caps
	}
}

func (r *tunnelRegistry) getCapabilities(name string) *tunnelCapabilities {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t, ok := r.tunnels[name]; ok {
		return t.capabilities
	}
	return nil
}

func (r *tunnelRegistry) reconcile(declared map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, t := range r.tunnels {
		if _, keep := declared[name]; !keep {
			if t.state == stateClaimed && t.Conn != nil {
				_ = (*t.Conn).CloseWithError(3, "tunnel removed from config")
			}
			delete(r.tunnels, name)
		} else if t.state == stateDeprecated {
			t.state = stateUnclaimed
		}
	}
	for name := range declared {
		if _, exists := r.tunnels[name]; !exists {
			r.nextID++
			r.tunnels[name] = &tunnel{
				Name:  name,
				ID:    r.nextID,
				state: stateUnclaimed,
			}
		}
	}
	r.updateDeclaredMetric()
}

func (r *tunnelRegistry) declaredNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tunnels))
	for name := range r.tunnels {
		names = append(names, name)
	}
	return names
}

type tunnelInfo struct {
	Name         string              `json:"name"`
	State        string              `json:"state"`
	Client       string              `json:"client,omitempty"`
	Capabilities *tunnelCapabilities `json:"capabilities,omitempty"`
}

func stateString(s tunnelState) string {
	switch s {
	case stateUnclaimed:
		return "unclaimed"
	case stateClaimed:
		return "claimed"
	case stateDeprecated:
		return "deprecated"
	default:
		return "unknown"
	}
}

func (r *tunnelRegistry) listTunnels() []tunnelInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]tunnelInfo, 0, len(r.tunnels))
	for name, t := range r.tunnels {
		info := tunnelInfo{
			Name:         name,
			State:        stateString(t.state),
			Capabilities: t.capabilities,
		}
		if t.Conn != nil {
			info.Client = (*t.Conn).RemoteAddr().String()
		}
		result = append(result, info)
	}
	return result
}

type clientInfo struct {
	TunnelName string `json:"tunnel_name"`
	RemoteAddr string `json:"remote_addr"`
}

func (r *tunnelRegistry) listClients() []clientInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]clientInfo, 0)
	for name, t := range r.tunnels {
		if t.state != stateClaimed || t.Conn == nil {
			continue
		}
		result = append(result, clientInfo{
			TunnelName: name,
			RemoteAddr: (*t.Conn).RemoteAddr().String(),
		})
	}
	return result
}

func (r *tunnelRegistry) updateDeclaredMetric() {
	count := 0
	for _, t := range r.tunnels {
		if t.state != stateDeprecated {
			count++
		}
	}
	metricTunnelsDeclared.Set(float64(count))
}
