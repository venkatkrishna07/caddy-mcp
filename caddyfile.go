package caddymcp

import (
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("mcp", parseMCPGlobalOption)
}

func parseMCPGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "listen":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Listen = d.Val()
			case "dev":
				app.Dev = true
			case "tls_cert":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.TLSCert = d.Val()
			case "tls_key":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.TLSKey = d.Val()
			case "max_conns_per_ip":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, d.Errf("invalid max_conns_per_ip: %v", err)
				}
				app.MaxConnsPerIP = val
			case "max_tunnels_per_conn":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, d.Errf("invalid max_tunnels_per_conn: %v", err)
				}
				app.MaxTunnelsPerConn = val
			case "max_total_conns":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, d.Errf("invalid max_total_conns: %v", err)
				}
				app.MaxTotalConns = val
			case "max_sessions_per_tunnel":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, d.Errf("invalid max_sessions_per_tunnel: %v", err)
				}
				app.MaxSessionsPerTunnel = val
			case "stream_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.StreamTimeout = d.Val()
			case "drain_timeout":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.DrainTimeout = d.Val()
			case "sse_keepalive":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.SSEKeepalive = d.Val()
			case "token_backend":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.TokenBackend = d.Val()
			case "token_file":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.TokenFile = d.Val()
			case "default_token_ttl":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.DefaultTokenTTL = d.Val()
			case "discovery":
				app.EnableDiscovery = true
			case "discovery_path":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.DiscoveryPath = d.Val()
			default:
				return nil, d.Errf("unrecognized mcp option: %s", d.Val())
			}
		}
	}

	return httpcaddyfile.App{
		Name:  "mcp",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

func (t *Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "tunnel":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.Tunnel = d.Val()
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.Mode = d.Val()
				if t.Mode != "transparent" && t.Mode != "aware" {
					return d.Errf("mode must be 'transparent' or 'aware', got %q", t.Mode)
				}
			case "policy":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.PolicyFile = d.Val()
			case "allow_tools":
				t.AllowTools = append(t.AllowTools, d.RemainingArgs()...)
			case "deny_tools":
				t.DenyTools = append(t.DenyTools, d.RemainingArgs()...)
			case "allow_resources":
				t.AllowResources = append(t.AllowResources, d.RemainingArgs()...)
			case "deny_resources":
				t.DenyResources = append(t.DenyResources, d.RemainingArgs()...)
			default:
				return d.Errf("unrecognized mcp transport option: %s", d.Val())
			}
		}
	}
	if t.Tunnel == "" {
		return fmt.Errorf("tunnel name is required in transport mcp block")
	}
	return nil
}
