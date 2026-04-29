package caddymcp

import (
	"encoding/json"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(DiscoveryHandler{})
	httpcaddyfile.RegisterHandlerDirective("mcp_discovery", parseMCPDiscovery)
}

type DiscoveryHandler struct {
	registry *tunnelRegistry
	basePath string
}

func (DiscoveryHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.mcp_discovery",
		New: func() caddy.Module { return new(DiscoveryHandler) },
	}
}

func (h *DiscoveryHandler) Provision(ctx caddy.Context) error {
	appIface, err := ctx.App("mcp")
	if err != nil {
		return err
	}
	app := appIface.(*App)
	h.registry = app.registry
	h.basePath = app.DiscoveryPath
	return nil
}

func (h DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == h.basePath && r.Method == http.MethodGet {
		return h.serveDiscovery(w, r)
	}
	return next.ServeHTTP(w, r)
}

type discoveryServer struct {
	Name         string              `json:"name"`
	Status       string              `json:"status"`
	Capabilities *tunnelCapabilities `json:"capabilities,omitempty"`
}

type discoveryResponse struct {
	Servers []discoveryServer `json:"servers"`
}

func (h *DiscoveryHandler) serveDiscovery(w http.ResponseWriter, _ *http.Request) error {
	tunnels := h.registry.listTunnels()
	servers := make([]discoveryServer, 0, len(tunnels))
	for _, t := range tunnels {
		servers = append(servers, discoveryServer{
			Name:   t.Name,
			Status: t.State,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(discoveryResponse{Servers: servers})
}

func (h *DiscoveryHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func parseMCPDiscovery(_ httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(DiscoveryHandler), nil
}
