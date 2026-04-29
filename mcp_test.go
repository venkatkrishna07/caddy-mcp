package caddymcp

import (
	"testing"
)

func TestParseMCPMethod(t *testing.T) {
	tests := []struct {
		body       string
		wantMethod string
		wantErr    bool
	}{
		{`{"jsonrpc":"2.0","method":"initialize","id":1}`, "initialize", false},
		{`{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"read_file"}}`, "tools/call", false},
		{`{"jsonrpc":"2.0","method":"resources/read","id":3}`, "resources/read", false},
		{`not json`, "", true},
		{`{}`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			req, err := parseMCPRequest([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Method != tt.wantMethod {
				t.Errorf("method = %q, want %q", req.Method, tt.wantMethod)
			}
		})
	}
}

func TestExtractToolName(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"read_file","arguments":{"path":"/tmp"}}}`
	req, err := parseMCPRequest([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	name := req.ToolName()
	if name != "read_file" {
		t.Errorf("ToolName = %q, want %q", name, "read_file")
	}
}

func TestExtractResourceURI(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"resources/read","id":1,"params":{"uri":"file:///repo/main.go"}}`
	req, err := parseMCPRequest([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	uri := req.ResourceURI()
	if uri != "file:///repo/main.go" {
		t.Errorf("ResourceURI = %q, want %q", uri, "file:///repo/main.go")
	}
}

func TestMCPErrorResponse(t *testing.T) {
	resp := mcpErrorResponse([]byte("42"), -32600, "access denied")
	if len(resp) == 0 {
		t.Error("response should not be empty")
	}
}
