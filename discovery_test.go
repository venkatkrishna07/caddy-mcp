package caddymcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryHandler_ListsConnectedServers(t *testing.T) {
	reg := newTunnelRegistry()
	reg.declare("code-server")
	reg.declare("db-tools")
	reg.claim("code-server", nil)
	reg.setCapabilities("code-server", &tunnelCapabilities{
		Tools: []string{"read_file", "search"},
	})

	h := &DiscoveryHandler{
		registry: reg,
		basePath: "/.well-known/mcp-servers",
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/mcp-servers", nil)
	rec := httptest.NewRecorder()

	err := h.serveDiscovery(rec, req)
	if err != nil {
		t.Fatalf("serveDiscovery: %v", err)
	}

	var resp discoveryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Servers) != 2 {
		t.Errorf("servers len = %d, want 2", len(resp.Servers))
	}
}
