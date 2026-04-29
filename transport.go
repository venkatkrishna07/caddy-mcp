package caddymcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishnas/caddy-mcp/policy"
	"github.com/venkatkrishnas/caddy-mcp/proto"
)

func init() {
	caddy.RegisterModule(Transport{})
}

type Transport struct {
	Tunnel         string   `json:"tunnel"`
	Mode           string   `json:"mode,omitempty"`
	PolicyFile     string   `json:"policy,omitempty"`
	AllowTools     []string `json:"allow_tools,omitempty"`
	DenyTools      []string `json:"deny_tools,omitempty"`
	AllowResources []string `json:"allow_resources,omitempty"`
	DenyResources  []string `json:"deny_resources,omitempty"`

	app    *App
	engine *policy.Engine
	logger *zap.Logger
}

func (Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.mcp",
		New: func() caddy.Module { return new(Transport) },
	}
}

func (t *Transport) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()

	appIface, err := ctx.App("mcp")
	if err != nil {
		return fmt.Errorf("mcp app not loaded — add a global 'mcp' block to your Caddyfile: %w", err)
	}
	t.app = appIface.(*App)

	if t.Tunnel == "" {
		return fmt.Errorf("tunnel name is required")
	}
	if t.Mode == "" {
		t.Mode = policy.ModeTransparent
	}

	t.app.registry.declare(t.Tunnel)
	t.logger.Info("tunnel declared", zap.String("tunnel", t.Tunnel), zap.String("mode", t.Mode))

	tunnelRules := policy.RuleSet{
		AllowTools:     t.AllowTools,
		DenyTools:      t.DenyTools,
		AllowResources: t.AllowResources,
		DenyResources:  t.DenyResources,
	}

	var userPolicy *policy.PolicyFile
	if t.PolicyFile != "" {
		data, err := os.ReadFile(t.PolicyFile)
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}
		pf, err := policy.LoadPolicyFile(data)
		if err != nil {
			return fmt.Errorf("parse policy file: %w", err)
		}
		userPolicy = pf
	}

	t.engine = &policy.Engine{
		Mode:        t.Mode,
		TunnelRules: tunnelRules,
		UserPolicy:  userPolicy,
	}

	return nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch t.app.registry.status(t.Tunnel) {
	case stateUndeclared:
		return nil, fmt.Errorf("tunnel %q is not declared", t.Tunnel)
	case stateUnclaimed:
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header:     http.Header{"X-Mcp-Status": {"unclaimed"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	case stateDeprecated:
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Header:     http.Header{"X-Mcp-Status": {"deprecated"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}

	tun, ok := t.app.registry.clientFor(t.Tunnel, t.app.MaxSessionsPerTunnel)
	if !ok {
		return nil, fmt.Errorf("tunnel %q is not connected", t.Tunnel)
	}

	if !tun.TryAddVisitor() {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header:     http.Header{"X-Mcp-Status": {"at-capacity"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}

	start := time.Now()
	metricStreamsActive.WithLabelValues(t.Tunnel).Inc()

	mcpMethod := ""
	if t.Mode == policy.ModeAware && req.Body != nil && req.Method == http.MethodPost {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
		if err != nil {
			tun.VisitorDone()
			metricStreamsActive.WithLabelValues(t.Tunnel).Dec()
			return nil, fmt.Errorf("read request body: %w", err)
		}

		user := req.Header.Get("X-Auth-User")
		decision := t.engine.Evaluate(user, bodyBytes)
		mcpMethod = decision.Method

		t.app.audit.logRequest(auditEvent{
			User:       user,
			Tunnel:     t.Tunnel,
			SessionID:  req.Header.Get(MCPSessionHeader),
			MCPMethod:  decision.Method,
			Tool:       decision.Tool,
			Resource:   decision.Resource,
			Status:     decision.Action,
			DenyReason: decision.Reason,
		})

		if decision.Action == policy.ActionDeny {
			tun.VisitorDone()
			metricStreamsActive.WithLabelValues(t.Tunnel).Dec()
			metricPolicyDecisions.WithLabelValues(t.Tunnel, "deny", decision.Reason).Inc()

			mcpReq, _ := parseMCPRequest(bodyBytes)
			var id []byte
			if mcpReq != nil {
				id = mcpReq.ID
			}
			errBody := mcpErrorResponse(id, -32600, "access denied: "+decision.Reason)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(string(errBody))),
				Request:    req,
			}, nil
		}
		metricPolicyDecisions.WithLabelValues(t.Tunnel, "allow", decision.Reason).Inc()

		req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		req.ContentLength = int64(len(bodyBytes))
	}

	sessionID := req.Header.Get(MCPSessionHeader)
	var sessionUUID [16]byte
	if sessionID != "" {
		parsed, err := parseUUID(sessionID)
		if err == nil {
			sessionUUID = parsed
		}
	}

	stream, err := t.openStream(req.Context(), tun.Conn, tun.ID, sessionUUID)
	if err != nil {
		tun.VisitorDone()
		metricStreamsActive.WithLabelValues(t.Tunnel).Dec()
		metricRequests.WithLabelValues(t.Tunnel, mcpMethod, "error").Inc()
		return nil, err
	}

	bodyDone := make(chan struct{})
	t.app.workers.Go(fmt.Sprintf("ctx-watch-%s-%d", t.Tunnel, stream.StreamID()), func() {
		select {
		case <-req.Context().Done():
			stream.CancelRead(0)
			stream.CancelWrite(0)
		case <-stream.Context().Done():
		case <-bodyDone:
		}
	})

	outReq := t.prepareRequest(req)

	if err := outReq.Write(stream); err != nil {
		_ = stream.Close()
		tun.VisitorDone()
		metricStreamsActive.WithLabelValues(t.Tunnel).Dec()
		return nil, fmt.Errorf("write request to tunnel: %w", err)
	}

	streamBuf := bufio.NewReader(stream)
	resp, err := http.ReadResponse(streamBuf, req)
	if err != nil {
		_ = stream.Close()
		tun.VisitorDone()
		metricStreamsActive.WithLabelValues(t.Tunnel).Dec()
		return nil, fmt.Errorf("read response from tunnel: %w", err)
	}

	metricRequestDuration.WithLabelValues(t.Tunnel, mcpMethod).Observe(time.Since(start).Seconds())
	metricRequests.WithLabelValues(t.Tunnel, mcpMethod, statusBucket(resp.StatusCode)).Inc()

	if sessionID == "" && resp.Header.Get(MCPSessionHeader) != "" {
		newSessionID := resp.Header.Get(MCPSessionHeader)
		if !t.app.sessions.create(newSessionID, t.Tunnel, tun.Conn) {
			t.logger.Warn("session table full, could not create session",
				zap.String("session", newSessionID),
				zap.String("tunnel", t.Tunnel),
			)
		} else {
			t.logger.Debug("session created",
				zap.String("session", newSessionID),
				zap.String("tunnel", t.Tunnel),
			)
		}
	}

	isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
	isUpgrade := resp.StatusCode == http.StatusSwitchingProtocols

	// SSE and WebSocket streams are long-lived — clear the absolute deadline
	// so they don't get killed by stream_timeout.
	if isSSE || isUpgrade {
		_ = stream.SetDeadline(time.Time{})
	}

	if isSSE {
		metricSSEStreamsActive.WithLabelValues(t.Tunnel).Inc()
	}

	resp.Body = &streamBody{
		ReadCloser: resp.Body,
		stream:     stream,
		tunnel:     t.Tunnel,
		tun:        &tun,
		isUpgrade:  isUpgrade,
		isSSE:      isSSE,
		logger:     t.logger,
		done:       bodyDone,
	}
	return resp, nil
}

func (t *Transport) openStream(ctx context.Context, conn *quic.Conn, tunnelID uint32, sessionID [16]byte) (*quic.Stream, error) {
	openCtx, openCancel := context.WithTimeout(ctx, 10*time.Second)
	defer openCancel()

	stream, err := conn.OpenStreamSync(openCtx)
	if err != nil {
		return nil, fmt.Errorf("open QUIC stream: %w", err)
	}

	if t.app.streamTimeout > 0 {
		_ = stream.SetDeadline(time.Now().Add(t.app.streamTimeout))
	}

	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tunnelID, SessionID: sessionID}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("write tunnel header: %w", err)
	}

	return stream, nil
}

func (t *Transport) prepareRequest(req *http.Request) *http.Request {
	outReq := req.Clone(req.Context())
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	outReq.RequestURI = ""
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1

	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", "websocket")
	}

	return outReq
}

type streamBody struct {
	io.ReadCloser
	stream    *quic.Stream
	tunnel    string
	tun       *tunnelSnapshot
	isUpgrade bool
	isSSE     bool
	logger    *zap.Logger
	once      sync.Once
	done      chan struct{}
}

func (b *streamBody) Write(p []byte) (int, error) {
	return (*b.stream).Write(p)
}

func (b *streamBody) Close() error {
	var bodyErr error
	b.once.Do(func() {
		bodyErr = b.ReadCloser.Close()
		_ = (*b.stream).Close()
		b.tun.VisitorDone()
		metricStreamsActive.WithLabelValues(b.tunnel).Dec()
		if b.isSSE {
			metricSSEStreamsActive.WithLabelValues(b.tunnel).Dec()
		}
		close(b.done)
	})
	return bodyErr
}

func statusBucket(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

var _ http.RoundTripper = (*Transport)(nil)

func (t *Transport) TLSEnabled() bool { return false }

func (t *Transport) EnableTLS(_ *reverseproxy.TLSConfig) error { return nil }

func (t *Transport) Cleanup() error { return nil }
