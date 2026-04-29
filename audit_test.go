package caddymcp

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuditLogger_LogRequest(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	al := &auditLogger{log: logger}
	al.logRequest(auditEvent{
		TokenName:      "team-a",
		User:           "alice",
		Tunnel:         "code-server",
		SessionID:      "abc-123",
		MCPMethod:      "tools/call",
		Tool:           "read_file",
		Status:         "allowed",
		UpstreamStatus: 200,
		LatencyMs:      45,
	})

	if logs.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Message != "mcp_request" {
		t.Errorf("message = %q, want %q", entry.Message, "mcp_request")
	}

	fields := make(map[string]any)
	for _, f := range entry.Context {
		fields[f.Key] = f.String
	}
	if fields["tunnel"] != "code-server" {
		t.Errorf("tunnel = %v, want %q", fields["tunnel"], "code-server")
	}
	if fields["user"] != "alice" {
		t.Errorf("user = %v, want %q", fields["user"], "alice")
	}
}
