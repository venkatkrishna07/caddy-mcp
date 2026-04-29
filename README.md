<div align="center">

# caddy-mcp

Expose private MCP servers through your existing Caddy. No inbound ports, no vendor in the request path.

[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

caddy-mcp is a Caddy plugin that tunnels [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers through QUIC. A [rift client](https://github.com/venkatkrishna07/rift) on the private network dials out to Caddy — no inbound firewall rules needed. Caddy presents standard Streamable HTTP endpoints to MCP clients on the public side.

```
MCP client ──HTTP──> Caddy :443 ──> QUIC stream ──> rift client ──> localhost:9090
  (Claude, etc.)     your domain                     private net     your MCP server
```

Two operational modes per tunnel:
- **Transparent:** Caddy forwards HTTP bytes untouched. MCP server handles session management and auth.
- **Aware:** Caddy parses MCP JSON-RPC, enforces tool/resource ACLs, logs audit trail. Denied requests never reach the MCP server.

Status: Beta. Works for personal and small-team use. Single Caddy instance for now; no HA yet.

## The problem

You run MCP servers on private networks — development machines, internal infrastructure, VPCs with no public ingress — and you want AI assistants (Claude Code, Cursor, custom agents) to reach them securely.

Today every option has a catch:

- **Open an inbound firewall rule.** Security review, network-boundary changes, doesn't work behind NAT or restrictive ISPs.
- **Use a generic tunnel.** ngrok, Cloudflare Tunnel work but give you no MCP-level controls — no tool filtering, no resource ACLs, no audit trail of which tools were called.
- **Expose directly on the internet.** No firewall protection, no middleware, no centralized logging.

caddy-mcp covers the gap. The rift client dials out over QUIC, and caddy-mcp makes the tunnel look like a normal upstream to Caddy's `reverse_proxy`. In aware mode, it also understands MCP — filtering tools, restricting resources, and logging every JSON-RPC call.

## How it works

```
              Public Internet
                    |
                    v
         +--------------------+
         |   Caddy :443       |   TLS, routing, middleware
         |   reverse_proxy    |
         +--------+-----------+
                  |
                  v
         +--------------------+
         |  caddy-mcp plugin  |   QUIC listener :4443
         |  tunnel registry   |   token store
         |  policy engine     |   MCP-aware ACLs
         |  audit logger      |   structured logging
         +--------+-----------+
                  |
                  | QUIC connection (TLS 1.3, multiplexed streams)
                  v
         +--------------------+
         |   rift client      |   runs on private network
         |   --protocol mcp   |   dials out — no inbound ports
         +--------+-----------+
                  |
                  v
         +--------------------+
         |   MCP server       |   tools, resources, prompts
         |   localhost:9090   |
         +--------------------+
```

Two listeners in one process. `:443` takes public HTTPS. `:4443` accepts rift client connections over QUIC with ALPN `mcp-v1`. When an MCP client sends a request, Caddy matches the site, hands it to the mcp transport, and the transport opens a QUIC stream to whichever client has claimed that tunnel.

## Quickstart

**1. Build Caddy with the plugin**

```bash
xcaddy build v2.11.2 --with github.com/venkatkrishnas/caddy-mcp=/path/to/caddy-mcp
```

Or build directly (no remote dependency):
```bash
cd caddy-mcp && go build -o caddy ./cmd/caddy-mcp/
```

**2. Caddyfile**

```caddyfile
{
    mcp {
        listen :4443
        dev
        discovery
    }
}

:8080 {
    reverse_proxy mcp-tunnel {
        transport mcp {
            tunnel code-server
        }
    }
}
```

**3. Run the [rift client](https://github.com/venkatkrishna07/rift) on the private box**

```bash
rift client --server localhost:4443 --protocol mcp --insecure \
    --expose 9090:http:code-server
```

That's it. `http://localhost:8080` now proxies MCP requests through the QUIC tunnel to whatever MCP server is on `localhost:9090` on the client machine.

`dev` mode uses a self-signed TLS cert for the QUIC listener and accepts any token.

## Transparent mode

Default mode. Caddy forwards HTTP bytes untouched — the MCP server handles everything:

```caddyfile
code-tools.example.com {
    reverse_proxy mcp-tunnel {
        transport mcp {
            tunnel code-server
        }
    }
}
```

All Caddy middleware works as normal — access logs, rate limiting, auth, headers.

## Aware mode

Caddy parses MCP JSON-RPC and enforces ACLs before forwarding. Denied requests get a JSON-RPC error response and never reach the MCP server:

```caddyfile
code-tools.example.com {
    basicauth {
        alice $2a$14$...
    }

    reverse_proxy mcp-tunnel {
        transport mcp {
            tunnel code-server
            mode aware

            allow_tools read_file list_files search
            deny_tools execute_command shell_exec
            allow_resources "file:///repo/*"
            deny_resources "file:///etc/*"

            policy /etc/caddy/mcp-policies.json
        }
    }
}
```

Policy file for per-user ACLs:

```json
{
    "policies": [
        {
            "users": ["alice", "team-frontend-*"],
            "allow_tools": ["read_file", "search"],
            "deny_tools": ["execute_command"],
            "allow_resources": ["file:///repo/frontend/*"]
        }
    ]
}
```

Effective permissions = tunnel ACLs ∩ user ACLs (most restrictive wins). Glob matching via `filepath.Match()`.

## Tokens and ACLs

Managed through Caddy's admin API (loopback-only by default):

```bash
# Issue a token restricted to specific tunnels
curl localhost:2019/mcp/tokens \
    -X POST -H "Content-Type: application/json" \
    -d '{"name": "team-a", "allowed_tunnels": ["team-a-*"], "ttl": "720h"}'

# List (secrets never returned)
curl localhost:2019/mcp/tokens

# Revoke — kills active sessions
curl -X DELETE "localhost:2019/mcp/tokens?name=team-a"
```

ACLs are globs. A token with `["team-a-*"]` can claim `team-a-code` but not `team-b-anything`.

## Discovery

When `discovery` is enabled, `/.well-known/mcp-servers` lists connected tunnels:

```bash
curl localhost:8080/.well-known/mcp-servers | jq
```

```json
{
    "servers": [
        {"name": "code-server", "status": "claimed"},
        {"name": "db-tools", "status": "unclaimed"}
    ]
}
```

## Audit logging

Aware mode emits structured events via zap namespace `mcp.audit`. Route via Caddy's log config:

```caddyfile
{
    log mcp_audit {
        include mcp.audit
        output file /var/log/caddy/mcp-audit.json
    }
}
```

Each request logs: token name, user identity, tunnel, session ID, MCP method, tool/resource name, policy decision, upstream status, latency.

## Monitoring

Prometheus metrics at Caddy's metrics endpoint:

```
mcp_tunnels_registered
mcp_tunnels_claimed
mcp_clients_connected
mcp_sessions_active{tunnel}
mcp_requests_total{tunnel, mcp_method, status}
mcp_request_duration_seconds{tunnel, mcp_method}
mcp_streams_active{tunnel}
mcp_policy_decisions_total{tunnel, decision, reason}
mcp_sse_streams_active{tunnel}
mcp_auth_failures_total
```

Live state:

```bash
curl localhost:2019/mcp/status | jq
curl localhost:2019/mcp/tunnels | jq
curl localhost:2019/mcp/sessions | jq
```

## Configuration reference

```caddyfile
{
    mcp {
        listen :4443

        # Dev mode: self-signed TLS, any token accepted
        dev

        # Production TLS
        tls_cert /etc/caddy/mcp-cert.pem
        tls_key  /etc/caddy/mcp-key.pem

        # Token storage
        token_backend bolt        # json (default) or bolt
        token_file /var/lib/mcp/tokens.db
        default_token_ttl 720h

        # Limits
        max_conns_per_ip 5
        max_total_conns 1000
        max_tunnels_per_conn 10
        max_sessions_per_tunnel 50

        # Timeouts
        stream_timeout 30m
        drain_timeout 30s
        sse_keepalive 30s

        # Discovery
        discovery
        discovery_path /.well-known/mcp-servers
    }
}
```

Transport inside `reverse_proxy`:

```caddyfile
reverse_proxy mcp-tunnel {
    transport mcp {
        tunnel <name>
        mode transparent|aware
        policy /path/to/policies.json
        allow_tools tool1 tool2 ...
        deny_tools tool1 tool2 ...
        allow_resources pattern1 pattern2 ...
        deny_resources pattern1 pattern2 ...
    }
}
```

The `<name>` must match what the rift client passes in `--expose PORT:http:NAME`. A client can't claim a tunnel that isn't declared in the Caddyfile.

## Security

- **Transport:** TLS 1.3 via QUIC. ALPN `mcp-v1` prevents cross-protocol attacks. 0-RTT disabled to prevent auth token replay.
- **Token auth:** `mcp_` prefixed, SHA256 hashed, never stored in plaintext. TTL expiration + manual revocation via admin API.
- **Rate limiting:** Per-IP auth failure tracking with backoff on the QUIC listener.
- **Tunnel ACLs:** Token-scoped tunnel access via glob patterns. Checked on every claim.
- **MCP ACLs (aware mode):** Tool/resource allow/deny lists per tunnel and per user. Malformed JSON-RPC rejected. Empty tool names/URIs denied.
- **Audit trail:** Structured logging of every MCP request via zap namespace.
- **Session management:** In-memory with TTL (1h default), max size cap (10k), periodic reaper. Bounded by design.
- **HTTP auth:** Delegated to Caddy's auth middleware (basic_auth, JWT, mTLS, OAuth).
- **Admin API:** Caddy's default loopback-only binding. Token revocation kills active sessions immediately.

## Limitations

- Single Caddy instance. No multi-node HA in v1.
- Tunnels must be pre-declared in the Caddyfile.
- QUIC runs over UDP. Some corporate networks block outbound UDP — no TCP fallback yet.
- One tunnel per rift client connection in MCP mode.
- No MCP server process management (client connects to existing servers only).

## Development

```bash
go build -o caddy ./cmd/caddy-mcp/    # build
go build -o test-mcp-server ./cmd/test-mcp-server/  # test server
CGO_ENABLED=1 go test ./... -race     # test
go vet ./...                           # lint
```

Test MCP server exposes: echo, add, current_time, slow_task (with SSE progress), list_resources, resources, prompts, completion.

## License

MIT
