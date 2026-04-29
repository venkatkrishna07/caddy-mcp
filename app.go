package caddymcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishnas/caddy-mcp/proto"
)

func init() {
	caddy.RegisterModule(new(App))
}

type App struct {
	Listen               string `json:"listen,omitempty"`
	Dev                  bool   `json:"dev,omitempty"`
	TLSCert              string `json:"tls_cert,omitempty"`
	TLSKey               string `json:"tls_key,omitempty"`
	MaxConnsPerIP        int    `json:"max_conns_per_ip,omitempty"`
	MaxTunnelsPerConn    int    `json:"max_tunnels_per_conn,omitempty"`
	MaxTotalConns        int    `json:"max_total_conns,omitempty"`
	MaxSessionsPerTunnel int    `json:"max_sessions_per_tunnel,omitempty"`
	StreamTimeout        string `json:"stream_timeout,omitempty"`
	DrainTimeout         string `json:"drain_timeout,omitempty"`
	SSEKeepalive         string `json:"sse_keepalive,omitempty"`
	TokenFile            string `json:"token_file,omitempty"`
	TokenBackend         string `json:"token_backend,omitempty"`
	DefaultTokenTTL      string `json:"default_token_ttl,omitempty"`
	EnableDiscovery      bool   `json:"discovery,omitempty"`
	DiscoveryPath        string `json:"discovery_path,omitempty"`

	tokens        TokenStore
	defaultTTL    time.Duration
	shared        *sharedState
	registry      *tunnelRegistry
	sessions      *sessionTable
	audit         *auditLogger
	logger        *zap.Logger
	ctx           caddy.Context
	cancel        context.CancelFunc
	workers       *workerGroup
	connMu        sync.Mutex
	connByIP      map[string]int
	totalConns    atomic.Int64
	streamTimeout time.Duration
	drainTimeout  time.Duration
	sseKeepalive  time.Duration
	authLimiter   *authRateLimiter
	tokenConnsMu  sync.Mutex
	tokenConns    map[string]map[*quic.Conn]struct{}
}

var _ caddy.App = (*App)(nil)

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "mcp",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()
	a.audit = newAuditLogger(a.logger)
	a.workers = newWorkerGroup(a.logger)

	if a.Listen == "" {
		a.Listen = ":4443"
	}

	a.registry = getOrCreateRegistry(a.Listen)
	a.sessions = getOrCreateSessionTable(a.Listen)
	a.connByIP = make(map[string]int)
	a.tokenConns = make(map[string]map[*quic.Conn]struct{})
	if a.MaxConnsPerIP <= 0 {
		a.MaxConnsPerIP = 5
	}
	if a.MaxTunnelsPerConn <= 0 {
		a.MaxTunnelsPerConn = 10
	}
	if a.MaxTotalConns <= 0 {
		a.MaxTotalConns = 1000
	}
	if a.MaxSessionsPerTunnel <= 0 {
		a.MaxSessionsPerTunnel = 50
	}
	if a.DiscoveryPath == "" {
		a.DiscoveryPath = "/.well-known/mcp-servers"
	}

	a.drainTimeout = 5 * time.Second
	if a.DrainTimeout != "" {
		d, err := caddy.ParseDuration(a.DrainTimeout)
		if err != nil {
			return fmt.Errorf("invalid drain_timeout: %w", err)
		}
		a.drainTimeout = d
	}

	a.authLimiter = newAuthRateLimiter(5, 30*time.Second)

	a.streamTimeout = 30 * time.Minute
	if a.StreamTimeout != "" {
		d, err := caddy.ParseDuration(a.StreamTimeout)
		if err != nil {
			return fmt.Errorf("parsing stream_timeout: %w", err)
		}
		a.streamTimeout = d
	}

	a.sseKeepalive = 30 * time.Second
	if a.SSEKeepalive != "" {
		d, err := caddy.ParseDuration(a.SSEKeepalive)
		if err != nil {
			return fmt.Errorf("parsing sse_keepalive: %w", err)
		}
		a.sseKeepalive = d
	}

	if a.DefaultTokenTTL != "" {
		d, err := caddy.ParseDuration(a.DefaultTokenTTL)
		if err != nil {
			return fmt.Errorf("invalid default_token_ttl: %w", err)
		}
		a.defaultTTL = d
	}

	if !a.Dev {
		ts, err := a.openTokenStore()
		if err != nil {
			return fmt.Errorf("init token store: %w", err)
		}
		a.tokens = ts
	}

	return nil
}

func (a *App) Validate() error {
	if a.TLSCert != "" && a.TLSKey == "" {
		return fmt.Errorf("tls_cert requires tls_key")
	}
	if a.TLSKey != "" && a.TLSCert == "" {
		return fmt.Errorf("tls_key requires tls_cert")
	}
	return nil
}

func (a *App) Start() error {
	tlsCfg, err := a.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("mcp TLS config: %w", err)
	}

	s, err := acquireShared(a.Listen, tlsCfg, a.registry, a.sessions)
	if err != nil {
		return fmt.Errorf("acquire shared listener: %w", err)
	}
	a.shared = s
	a.registry = s.registry
	a.sessions = s.sessions

	declared := make(map[string]struct{})
	for _, name := range a.registry.declaredNames() {
		declared[name] = struct{}{}
	}
	a.registry.reconcile(declared)

	var ctx context.Context
	ctx, a.cancel = context.WithCancel(a.ctx)

	a.workers.Go("accept-loop", func() {
		a.acceptLoop(ctx)
	})

	if a.tokens != nil {
		a.workers.Go("token-cleanup", func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cleaned := a.tokens.CleanExpired()
					if cleaned > 0 {
						a.logger.Info("cleaned expired tokens", zap.Int("count", cleaned))
					}
				}
			}
		})
	}

	a.workers.Go("session-reaper", func() {
		ticker := time.NewTicker(sessionReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reaped := a.sessions.reapExpired()
				if reaped > 0 {
					a.logger.Info("reaped expired sessions", zap.Int("count", reaped))
				}
			}
		}
	})

	a.logger.Info("caddy-mcp QUIC listener started",
		zap.String("addr", a.Listen),
		zap.Bool("dev", a.Dev),
		zap.Bool("discovery", a.EnableDiscovery),
	)
	if a.Dev {
		a.logger.Warn("DEV MODE ENABLED — all authentication is bypassed, do NOT use in production")
	}
	return nil
}

func (a *App) Stop() error {
	if a.cancel != nil {
		a.cancel()
	}
	done := make(chan struct{})
	go func() {
		a.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(a.drainTimeout):
		a.logger.Warn("drain timeout expired, forcing shutdown",
			zap.Duration("timeout", a.drainTimeout),
			zap.Int64("active_workers", a.workers.Count()),
		)
	}
	if a.shared != nil {
		releaseShared(a.Listen)
	}
	if a.tokens != nil {
		if err := a.tokens.Close(); err != nil {
			a.logger.Error("close token store", zap.Error(err))
		}
	}
	return nil
}

func (a *App) acceptLoop(ctx context.Context) {
	for {
		conn, err := a.shared.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.logger.Error("QUIC accept error — retrying", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if a.totalConns.Load() >= int64(a.MaxTotalConns) {
			a.logger.Warn("global connection limit reached")
			_ = conn.CloseWithError(1, "server at capacity")
			continue
		}

		ip := extractIP(conn.RemoteAddr())
		if !a.allowConn(ip) {
			a.logger.Warn("per-IP connection limit reached", zap.String("ip", ip))
			_ = conn.CloseWithError(1, "too many connections from your IP")
			continue
		}

		a.totalConns.Add(1)
		metricClientsConnected.Inc()
		a.workers.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
			defer a.totalConns.Add(-1)
			defer metricClientsConnected.Dec()
			defer a.releaseConn(ip)

			select {
			case <-conn.HandshakeComplete():
			case <-ctx.Done():
				return
			}

			connCtx, connCancel := context.WithCancel(ctx)
			defer connCancel()
			context.AfterFunc(conn.Context(), connCancel)
			a.handleConn(connCtx, conn)
		})
	}
}

func (a *App) handleConn(ctx context.Context, conn *quic.Conn) {
	ip := extractIP(conn.RemoteAddr())
	a.logger.Debug("handling connection", zap.String("ip", ip))
	defer a.logger.Debug("connection handler exited", zap.String("ip", ip))

	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		a.logger.Error("accept control stream", zap.Error(err))
		return
	}
	defer ctrl.Close()

	msg, err := proto.ReadMsg(ctrl)
	if err != nil || msg.Type != proto.TypeAuth {
		a.logger.Warn("bad auth frame", zap.String("ip", ip), zap.Error(err))
		_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected auth"})
		_ = conn.CloseWithError(2, "auth failed")
		return
	}

	var authedToken *TokenInfo
	if a.Dev {
		msg.Token = ""
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
			_ = conn.CloseWithError(2, "auth failed")
			return
		}
		metricClientConnects.WithLabelValues("success").Inc()
		a.logger.Info("dev mode auth accepted", zap.String("ip", ip))
	} else {
		if !a.authLimiter.allow(ip) {
			metricClientConnects.WithLabelValues("rate_limited").Inc()
			a.logger.Warn("auth rate limited", zap.String("ip", ip))
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "too many auth failures, try again later"})
			_ = conn.CloseWithError(2, "rate limited")
			return
		}
		if a.tokens == nil {
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "token store not configured"})
			_ = conn.CloseWithError(2, "auth failed")
			return
		}
		tokenInfo, ok := a.tokens.Validate(ctx, msg.Token)
		msg.Token = ""
		if !ok {
			a.authLimiter.recordFailure(ip)
			metricTokenAuthFailures.Inc()
			metricClientConnects.WithLabelValues("failure").Inc()
			a.logger.Warn("auth rejected", zap.String("ip", ip))
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "invalid token"})
			_ = conn.CloseWithError(2, "auth failed")
			return
		}
		a.authLimiter.recordSuccess(ip)
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
			_ = conn.CloseWithError(2, "auth failed")
			return
		}
		metricClientConnects.WithLabelValues("success").Inc()
		a.logger.Info("client authenticated",
			zap.String("ip", ip),
			zap.String("token_name", tokenInfo.Name),
		)

		authedToken = tokenInfo
		a.trackTokenConn(tokenInfo.Name, conn)
		defer a.untrackTokenConn(tokenInfo.Name, conn)

		if !tokenInfo.ExpiresAt.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, tokenInfo.ExpiresAt)
			defer cancel()
			context.AfterFunc(ctx, func() {
				if ctx.Err() == context.DeadlineExceeded {
					a.logger.Info("token expired, closing connection",
						zap.String("ip", ip),
						zap.String("token_name", tokenInfo.Name),
					)
					_ = conn.CloseWithError(3, "token expired")
				}
			})
		}
	}

	var claimed []string
	defer func() {
		for _, name := range claimed {
			a.registry.release(name)
			a.sessions.removeByTunnel(name)
			metricTunnelsClaimed.Dec()
			a.logger.Info("tunnel released", zap.String("tunnel", name), zap.String("ip", ip))
		}
	}()

	for {
		msg, err := proto.ReadMsg(ctrl)
		if err != nil {
			if ctx.Err() == nil {
				a.logger.Debug("control stream closed", zap.String("ip", ip), zap.Error(err))
			}
			return
		}

		switch msg.Type {
		case proto.TypeRegister:
			if len(claimed) >= a.MaxTunnelsPerConn {
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
					Type:  proto.TypeError,
					Error: fmt.Sprintf("max %d tunnels per client", a.MaxTunnelsPerConn),
				})
				continue
			}

			for _, reg := range msg.Tunnels {
				name := reg.Name
				if name == "" {
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "tunnel name required"})
					continue
				}
				if err := validateTunnelName(name); err != nil {
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "invalid tunnel name"})
					continue
				}
				if authedToken != nil && !checkACL(authedToken, name) {
					a.logger.Warn("tunnel ACL denied",
						zap.String("ip", ip),
						zap.String("tunnel", name),
						zap.String("token_name", authedToken.Name),
					)
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "acl denied"})
					continue
				}
				tunnelID, err := a.registry.claim(name, conn)
				if err != nil {
					errMsg := "tunnel unavailable"
					if errors.Is(err, ErrTunnelNotDeclared) {
						errMsg = "tunnel not found"
					} else if errors.Is(err, ErrTunnelClaimed) {
						errMsg = "tunnel already in use"
					}
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: errMsg})
					continue
				}
				claimed = append(claimed, name)
				metricTunnelsClaimed.Inc()
				a.logger.Info("tunnel claimed",
					zap.String("ip", ip),
					zap.String("tunnel", name),
					zap.Uint32("tunnel_id", tunnelID),
				)
			}
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:              proto.TypeRegisterOK,
				RegisteredTunnels: claimed,
			})

		case proto.TypeCapabilities:
			if msg.Tunnel == "" {
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "tunnel name required"})
				continue
			}
			owned := false
			for _, name := range claimed {
				if name == msg.Tunnel {
					owned = true
					break
				}
			}
			if !owned {
				a.logger.Warn("capabilities update denied — tunnel not owned by this connection",
					zap.String("tunnel", msg.Tunnel),
					zap.String("ip", ip),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "not your tunnel"})
				continue
			}
			caps := &tunnelCapabilities{
				Tools:     msg.Tools,
				Resources: msg.Resources,
				Prompts:   msg.Prompts,
			}
			a.registry.setCapabilities(msg.Tunnel, caps)
			a.logger.Info("capabilities updated",
				zap.String("tunnel", msg.Tunnel),
				zap.Int("tools", len(msg.Tools)),
				zap.Int("resources", len(msg.Resources)),
			)

		case proto.TypeHeartbeat:
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeHeartbeat})

		default:
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "unexpected message type"})
		}
	}
}

func (a *App) allowConn(ip string) bool {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.connByIP[ip] >= a.MaxConnsPerIP {
		return false
	}
	a.connByIP[ip]++
	return true
}

func (a *App) releaseConn(ip string) {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	a.connByIP[ip]--
	if a.connByIP[ip] <= 0 {
		delete(a.connByIP, ip)
	}
}

func (a *App) openTokenStore() (TokenStore, error) {
	switch a.TokenBackend {
	case "bolt", "bbolt":
		path := a.TokenFile
		if path == "" {
			path = "/var/lib/caddy-mcp/tokens.db"
		}
		return newBBoltTokenStore(path)
	case "json", "":
		return newJSONTokenStore(a.TokenFile)
	default:
		return nil, fmt.Errorf("unknown token_backend %q (use json or bolt)", a.TokenBackend)
	}
}

func (a *App) trackTokenConn(tokenName string, conn *quic.Conn) {
	a.tokenConnsMu.Lock()
	defer a.tokenConnsMu.Unlock()
	if a.tokenConns[tokenName] == nil {
		a.tokenConns[tokenName] = make(map[*quic.Conn]struct{})
	}
	a.tokenConns[tokenName][conn] = struct{}{}
}

func (a *App) untrackTokenConn(tokenName string, conn *quic.Conn) {
	a.tokenConnsMu.Lock()
	defer a.tokenConnsMu.Unlock()
	if conns, ok := a.tokenConns[tokenName]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(a.tokenConns, tokenName)
		}
	}
}

func (a *App) killTokenSessions(tokenName string) int {
	a.tokenConnsMu.Lock()
	conns := a.tokenConns[tokenName]
	delete(a.tokenConns, tokenName)
	a.tokenConnsMu.Unlock()

	for conn := range conns {
		_ = (*conn).CloseWithError(2, "token revoked")
	}
	return len(conns)
}

func (a *App) buildTLSConfig() (*tls.Config, error) {
	if a.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(a.TLSCert, a.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}, nil
	}
	if !a.Dev {
		return nil, fmt.Errorf("tls_cert and tls_key are required in production mode; use 'dev' for self-signed certificates")
	}
	return devTLSConfig()
}

func devTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mcp-dev"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal dev key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load dev cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
