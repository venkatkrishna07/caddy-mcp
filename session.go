package caddymcp

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	defaultSessionTTL       = 1 * time.Hour
	defaultMaxSessionsTotal = 10000
	sessionReapInterval     = 5 * time.Minute
)

type sessionEntry struct {
	SessionID  string
	TunnelName string
	Conn       *quic.Conn
	CreatedAt  time.Time
}

type sessionTable struct {
	mu          sync.RWMutex
	sessions    map[string]*sessionEntry
	maxSessions int
	sessionTTL  time.Duration
}

func newSessionTable() *sessionTable {
	return &sessionTable{
		sessions:    make(map[string]*sessionEntry),
		maxSessions: defaultMaxSessionsTotal,
		sessionTTL:  defaultSessionTTL,
	}
}

func (st *sessionTable) create(sessionID, tunnelName string, conn *quic.Conn) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.sessions) >= st.maxSessions {
		return false
	}
	st.sessions[sessionID] = &sessionEntry{
		SessionID:  sessionID,
		TunnelName: tunnelName,
		Conn:       conn,
		CreatedAt:  time.Now(),
	}
	metricSessionsActive.WithLabelValues(tunnelName).Inc()
	return true
}

func (st *sessionTable) lookup(sessionID string) (*sessionEntry, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	e, ok := st.sessions[sessionID]
	if ok && st.sessionTTL > 0 && time.Since(e.CreatedAt) > st.sessionTTL {
		return nil, false
	}
	return e, ok
}

func (st *sessionTable) remove(sessionID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if e, ok := st.sessions[sessionID]; ok {
		metricSessionsActive.WithLabelValues(e.TunnelName).Dec()
		metricSessionDuration.WithLabelValues(e.TunnelName).Observe(time.Since(e.CreatedAt).Seconds())
		delete(st.sessions, sessionID)
	}
}

func (st *sessionTable) removeByTunnel(tunnelName string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	var count int
	for id, e := range st.sessions {
		if e.TunnelName == tunnelName {
			metricSessionsActive.WithLabelValues(tunnelName).Dec()
			metricSessionDuration.WithLabelValues(tunnelName).Observe(time.Since(e.CreatedAt).Seconds())
			delete(st.sessions, id)
			count++
		}
	}
	return count
}

// reapExpired removes sessions older than TTL. Returns count removed.
func (st *sessionTable) reapExpired() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sessionTTL <= 0 {
		return 0
	}
	now := time.Now()
	var count int
	for id, e := range st.sessions {
		if now.Sub(e.CreatedAt) > st.sessionTTL {
			metricSessionsActive.WithLabelValues(e.TunnelName).Dec()
			metricSessionDuration.WithLabelValues(e.TunnelName).Observe(now.Sub(e.CreatedAt).Seconds())
			delete(st.sessions, id)
			count++
		}
	}
	return count
}

func (st *sessionTable) countForTunnel(tunnelName string) int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	count := 0
	for _, e := range st.sessions {
		if e.TunnelName == tunnelName {
			count++
		}
	}
	return count
}

type sessionInfo struct {
	SessionID  string    `json:"session_id"`
	TunnelName string    `json:"tunnel_name"`
	Client     string    `json:"client,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func (st *sessionTable) list() []sessionInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()
	result := make([]sessionInfo, 0, len(st.sessions))
	for _, e := range st.sessions {
		si := sessionInfo{
			SessionID:  e.SessionID,
			TunnelName: e.TunnelName,
			CreatedAt:  e.CreatedAt,
		}
		if e.Conn != nil {
			si.Client = (*e.Conn).RemoteAddr().String()
		}
		result = append(result, si)
	}
	return result
}
