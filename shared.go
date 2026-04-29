package caddymcp

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	sharedMu sync.Mutex
	shared   = map[string]*sharedState{}
)

type sharedState struct {
	listener  *quic.Listener
	transport *quic.Transport
	registry  *tunnelRegistry
	sessions  *sessionTable
	refCount  int
}

func getOrCreateRegistry(addr string) *tunnelRegistry {
	if addr == "" {
		addr = ":4443"
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if s, ok := shared[addr]; ok {
		return s.registry
	}
	return newTunnelRegistry()
}

func getOrCreateSessionTable(addr string) *sessionTable {
	if addr == "" {
		addr = ":4443"
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if s, ok := shared[addr]; ok {
		return s.sessions
	}
	return newSessionTable()
}

func acquireShared(addr string, tlsCfg *tls.Config, reg *tunnelRegistry, sess *sessionTable) (*sharedState, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()

	if s, ok := shared[addr]; ok {
		s.refCount++
		return s, nil
	}

	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"mcp-v1"}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind UDP %s: %w", addr, err)
	}

	tr := &quic.Transport{
		Conn: udpConn,
	}
	ln, err := tr.Listen(tlsCfg, &quic.Config{
		MaxIdleTimeout:    30 * time.Second,
		KeepAlivePeriod:   15 * time.Second,
		MaxIncomingStreams: 1000,
		Allow0RTT:         false,
	})
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("QUIC listen: %w", err)
	}

	s := &sharedState{
		listener:  ln,
		transport: tr,
		registry:  reg,
		sessions:  sess,
		refCount:  1,
	}
	shared[addr] = s
	return s, nil
}

func releaseShared(addr string) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	s, ok := shared[addr]
	if !ok {
		return
	}
	s.refCount--
	if s.refCount <= 0 {
		if err := s.listener.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "caddy-mcp: close QUIC listener: %v\n", err)
		}
		if err := s.transport.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "caddy-mcp: close QUIC transport: %v\n", err)
		}
		delete(shared, addr)
	}
}
