package caddymcp

import (
	"go.uber.org/zap"
)

type auditEvent struct {
	TokenName      string
	User           string
	Tunnel         string
	SessionID      string
	MCPMethod      string
	Tool           string
	Resource       string
	Status         string
	DenyReason     string
	UpstreamStatus int
	LatencyMs      int64
}

type auditLogger struct {
	log *zap.Logger
}

func newAuditLogger(log *zap.Logger) *auditLogger {
	return &auditLogger{log: log.Named("audit")}
}

func (a *auditLogger) logRequest(e auditEvent) {
	fields := []zap.Field{
		zap.String("token", e.TokenName),
		zap.String("user", e.User),
		zap.String("tunnel", e.Tunnel),
		zap.String("session", e.SessionID),
		zap.String("status", e.Status),
		zap.Int64("latency_ms", e.LatencyMs),
	}
	if e.MCPMethod != "" {
		fields = append(fields, zap.String("mcp_method", e.MCPMethod))
	}
	if e.Tool != "" {
		fields = append(fields, zap.String("tool", e.Tool))
	}
	if e.Resource != "" {
		fields = append(fields, zap.String("resource", e.Resource))
	}
	if e.DenyReason != "" {
		fields = append(fields, zap.String("deny_reason", e.DenyReason))
	}
	if e.UpstreamStatus > 0 {
		fields = append(fields, zap.Int("upstream_status", e.UpstreamStatus))
	}
	a.log.Info("mcp_request", fields...)
}
