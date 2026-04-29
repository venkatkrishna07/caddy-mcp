package caddymcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

type AdminAPI struct {
	app *App
}

func (AdminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.mcp",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

func (a *AdminAPI) Provision(ctx caddy.Context) error {
	appIface, err := ctx.App("mcp")
	if err != nil {
		return err
	}
	a.app = appIface.(*App)
	return nil
}

func (a *AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/mcp/tokens", Handler: caddy.AdminHandlerFunc(a.handleTokens)},
		{Pattern: "/mcp/tunnels", Handler: caddy.AdminHandlerFunc(a.handleTunnels)},
		{Pattern: "/mcp/clients", Handler: caddy.AdminHandlerFunc(a.handleClients)},
		{Pattern: "/mcp/sessions", Handler: caddy.AdminHandlerFunc(a.handleSessions)},
		{Pattern: "/mcp/status", Handler: caddy.AdminHandlerFunc(a.handleStatus)},
	}
}

func (a *AdminAPI) handleTokens(w http.ResponseWriter, r *http.Request) error {
	if a.app.tokens == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Err:        fmt.Errorf("token store not configured (dev mode or no token_file)"),
		}
	}

	switch r.Method {
	case http.MethodGet:
		return jsonResponse(w, a.app.tokens.List())

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req struct {
			Name           string   `json:"name"`
			AllowedTunnels []string `json:"allowed_tunnels,omitempty"`
			TTL            string   `json:"ttl,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: err}
		}
		if req.Name == "" || len(req.Name) > 256 {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("name must be 1-256 characters")}
		}
		for _, pattern := range req.AllowedTunnels {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("invalid tunnel pattern %q: %w", pattern, err)}
			}
		}

		var ttl time.Duration
		if req.TTL != "" {
			d, err := caddy.ParseDuration(req.TTL)
			if err != nil {
				return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: err}
			}
			ttl = d
		} else {
			ttl = a.app.defaultTTL
		}

		token, err := a.app.tokens.Issue(req.Name, ttl, req.AllowedTunnels)
		if err != nil {
			return caddy.APIError{HTTPStatus: http.StatusInternalServerError, Err: err}
		}

		w.WriteHeader(http.StatusCreated)
		return jsonResponse(w, map[string]any{"name": req.Name, "token": token, "ttl": ttl.String()})

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("name query parameter required")}
		}
		if err := a.app.tokens.Revoke(name); err != nil {
			return caddy.APIError{HTTPStatus: http.StatusInternalServerError, Err: err}
		}
		killed := a.app.killTokenSessions(name)
		w.WriteHeader(http.StatusNoContent)
		if killed > 0 {
			a.app.logger.Info("revoked token and killed active sessions",
				zap.String("token_name", name),
				zap.Int("sessions_killed", killed),
			)
		}
		return nil

	default:
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
}

func (a *AdminAPI) handleTunnels(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	return jsonResponse(w, a.app.registry.listTunnels())
}

func (a *AdminAPI) handleClients(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	return jsonResponse(w, a.app.registry.listClients())
}

func (a *AdminAPI) handleSessions(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	return jsonResponse(w, a.app.sessions.list())
}

func (a *AdminAPI) handleStatus(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}
	return jsonResponse(w, map[string]any{
		"listener_addr":     a.app.Listen,
		"dev_mode":          a.app.Dev,
		"total_connections": a.app.totalConns.Load(),
		"discovery":         a.app.EnableDiscovery,
		"tunnels":           a.app.registry.listTunnels(),
		"sessions":          a.app.sessions.list(),
	})
}

func jsonResponse(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}
