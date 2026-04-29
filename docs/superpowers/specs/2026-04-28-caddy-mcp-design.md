# caddy-mcp Design Specification

**Date:** 2026-04-28
**Status:** Draft
**Author:** Venkat Krishna S

## Overview

caddy-mcp is a Caddy plugin that exposes MCP (Model Context Protocol) servers through Caddy using a dial-out QUIC tunnel. MCP servers on private networks connect outbound to Caddy — no inbound firewall rules needed. Caddy presents standard Streamable HTTP endpoints to MCP clients on the public side.

Two operational modes per tunnel:
- **Transparent:** Caddy forwards HTTP bytes untouched. MCP server handles session management and auth.
- **Aware:** Caddy parses MCP JSON-RPC, enforces tool/resource ACLs, logs audit trail. Then forwards.

## Goals

- Zero inbound connections for MCP server operators
- Full Caddy middleware compatibility (auth, rate limiting, logging)
- MCP protocol-aware ACLs (tool filtering, resource restrictions)
- Structured audit logging via Caddy's zap infrastructure
- Discovery endpoint for multi-server deployments
- Production-grade security (TLS 1.3, token auth, rate limiting, resource limits)

## Non-Goals

- MCP server process management (client connects to existing servers only)
- HTTP-side authentication (delegated to Caddy's auth middleware)
- HTTP-side rate limiting (delegated to caddy-ratelimit)
- Custom log output configuration (delegated to Caddy's log routing)
- Shared library with caddy-rift (independent project, same patterns)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Caddy Server                          │
│                                                          │
│  :443 (public)              :4443 (QUIC listener)       │
│  ┌──────────────┐           ┌──────────────────┐        │
│  │ reverse_proxy │           │ MCP tunnel       │        │
│  │ transport mcp │           │ auth + register  │        │
│  └──────┬───────┘           └────────▲─────────┘        │
│         │                            │                   │
│         ▼                            │                   │
│  ┌──────────────┐    ┌──────────┐    │                   │
│  │ MCP Policy   │    │ Registry │    │                   │
│  │ Engine       │    │          │    │                   │
│  │ (aware mode) │    └──────────┘    │                   │
│  └──────┬───────┘         ▲          │                   │
│         │                 │          │                   │
│         ▼                 │          │                   │
│  ┌──────────────┐         │          │                   │
│  │ Audit Logger │         │          │                   │
│  │ (zap mcp.audit)        │          │                   │
│  └──────────────┘         │          │                   │
│                           │          │                   │
│  ┌────────────────────────┘          │                   │
│  │ Discovery Endpoint                │                   │
│  │ /.well-known/mcp-servers          │                   │
│  └───────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────┘
                               ▲
                               │ QUIC dial-out (TLS 1.3)
                               │
                    ┌──────────┴──────────┐
                    │  caddy-mcp client   │
                    │  (private network)  │
                    │                     │
                    │  connects to:       │
                    │  - HTTP MCP server  │
                    │  - stdio MCP server │
                    └─────────────────────┘
```

**Public-facing protocol:** Streamable HTTP (standard MCP transport). MCP clients connect normally — tunnel is invisible.

**Wire protocol (QUIC):** TunnelHeader prefix on each stream, then HTTP request/response bytes. Control messages on stream 0 for auth, registration, capabilities.

## Components

### 1. App (`app.go` — module ID: `mcp`)

Main Caddy app module. Implements `caddy.App` (Provision/Start/Stop/Cleanup).

Owns:
- QUIC listener on configurable port (default `:4443`)
- Tunnel registry
- Token store (JSON or BoltDB backend)
- Auth rate limiter
- Shared state across Caddy reloads via `caddy.UsagePool`

Configuration:
- `listen` — QUIC listener address
- `tls_cert` / `tls_key` — production TLS certificates
- `dev` — development mode (self-signed TLS, no token auth)
- `token_file` — JSON token file path
- `token_backend` — "json" (default) or "bolt"
- `default_token_ttl` — default token expiration
- `max_conns_per_ip` — per-IP QUIC connection limit
- `max_total_conns` — global QUIC connection cap
- `max_tunnels_per_conn` — tunnels per client connection
- `max_sessions_per_tunnel` — concurrent MCP sessions per tunnel
- `stream_timeout` — idle QUIC stream deadline (default 30m, longer than rift due to MCP session longevity)
- `drain_timeout` — graceful shutdown wait
- `sse_keepalive` — SSE heartbeat interval for dead connection detection

### 2. Transport (`transport.go` — module ID: `http.reverse_proxy.transport.mcp`)

HTTP RoundTripper for Caddy's `reverse_proxy`. Session-aware routing.

Routing logic:
1. Request has `Mcp-Session-Id` header → look up session table → route to bound QUIC connection
2. No session header (initialize request) → route to tunnel by name → create session entry on response
3. Session not found → HTTP 404

Mode selection:
- `transparent` — forward HTTP bytes directly to QUIC stream
- `aware` — parse JSON-RPC, run through policy engine, then forward

Returns `TLSEnabled() → false` — QUIC streams already TLS 1.3 encrypted.

### 3. Registry (`registry.go`)

Maps tunnel name → QUIC connection + metadata. Tunnel states: unclaimed → claimed → deprecated.

Extended from caddy-rift pattern with:
- Capabilities cache per tunnel (tools, resources, prompts) populated on registration
- Reference to session table for session-aware lookups

### 4. Session Table (`session.go`)

Maps MCP session ID → tunnel name + QUIC connection.

```
┌────────────────────┬──────────────┬─────────────┬────────────┐
│ Session ID (UUID)  │ Tunnel Name  │ QUIC Conn   │ Created At │
└────────────────────┴──────────────┴─────────────┴────────────┘
```

Sessions created when MCP `initialize` response returns session ID. Cleaned up when QUIC connection drops or session explicitly closed.

### 5. Token Store (`tokens.go`, `tokens_bbolt.go`)

Same pattern as caddy-rift. Tokens for QUIC tunnel client authentication only.

```go
type TokenStore interface {
    Validate(ctx context.Context, token string) (*TokenInfo, bool)
    Issue(name string, ttl time.Duration, allowedTunnels []string) (string, error)
    Revoke(name string) error
    List() []TokenInfo
    Close() error
    CleanExpired() int
}
```

Token format: `mcp_` prefix + 32 random bytes (base64url).
Storage: SHA256 hash only — plaintext never persisted or logged.

**Scope:** QUIC tunnel client auth only. HTTP-side MCP client auth is delegated to Caddy's auth middleware (basic_auth, JWT via caddy-security, mTLS, etc.).

### 6. Policy Engine (`policy/engine.go`, `policy/rules.go`)

Aware mode only. Sits between transport and QUIC stream.

Parses JSON-RPC request body:
- Extracts `method` and `params`
- For `tools/call` — checks tool name against allowed/denied tools
- For `resources/read` / `resources/subscribe` — checks resource URI against allowed/denied patterns
- Deny → returns JSON-RPC error response, request never reaches MCP server
- Allow → forwards unchanged (no re-serialization)

ACL sources (two layers):
1. **Caddyfile tunnel config** — `allow_tools`, `deny_tools`, `allow_resources`, `deny_resources`
2. **Policy file** — maps Caddy-authenticated user identity (`{http.auth.user.id}`) to per-user ACLs

Effective permissions = intersection of tunnel ACLs ∩ user ACLs (most restrictive wins).

Policy file format:
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

Glob matching via `filepath.Match()` (safe, no regex injection).

### 7. Discovery Handler (`discovery.go` — module ID: `http.handlers.mcp_discovery`)

HTTP handler registered in Caddy's handler chain. Serves `/.well-known/mcp-servers` (path configurable).

Response:
```json
{
    "servers": [
        {
            "name": "code-server",
            "url": "https://code-tools.example.com/mcp",
            "capabilities": {
                "tools": ["read_file", "search", "list_files"],
                "resources": ["file:///repo/*"]
            },
            "status": "connected"
        }
    ]
}
```

Access control:
- With Caddy auth middleware in front: filters list by authenticated user's policy (only shows servers they can access)
- Without auth middleware: returns all connected servers (operator's choice to protect or leave open)

Registered as `http.handlers.mcp_discovery` so it composes with Caddy's handler chain. Auth middleware, if configured, runs before discovery.

### 8. Audit Logger (`audit.go`)

Emits structured events via `zap.Logger` with namespace `mcp.audit`. Caddy operators route these logs via standard log config:

```caddyfile
{
    log mcp_audit {
        include mcp.audit
        output file /var/log/caddy/mcp-audit.json
    }
}
```

Event structure:
```json
{
    "ts": "2026-04-28T10:15:30Z",
    "level": "info",
    "logger": "mcp.audit",
    "msg": "mcp_request",
    "token": "team-frontend",
    "user": "alice",
    "tunnel": "code-server",
    "session": "abc-123-def",
    "mcp_method": "tools/call",
    "tool": "read_file",
    "status": "allowed",
    "upstream_status": 200,
    "latency_ms": 45
}
```

Transparent mode: logs HTTP-level fields (method, path, status, latency, caller identity).
Aware mode: adds MCP-level fields (mcp_method, tool/resource name, policy decision).

### 9. Admin API (`admin.go` — module ID: `admin.api.mcp`)

Registered on Caddy's admin endpoint (localhost:2019). Body size limit: 4KB.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/mcp/status` | GET | Overall status |
| `/mcp/tunnels` | GET | Connected tunnels + capabilities |
| `/mcp/clients` | GET | Connected QUIC clients |
| `/mcp/sessions` | GET | Active MCP sessions |
| `/mcp/tokens` | GET | List tokens |
| `/mcp/tokens` | POST | Issue new token |
| `/mcp/tokens/{name}` | DELETE | Revoke token |

### 10. Metrics (`metrics.go`)

Prometheus metrics with namespace `mcp_`. Exposed via Caddy's `/metrics` admin endpoint.

```
# Connection metrics
mcp_clients_connected              gauge
mcp_client_connects_total          counter  {result}
mcp_auth_failures_total            counter

# Tunnel metrics
mcp_tunnels_registered             gauge
mcp_tunnels_claimed                gauge

# Session metrics
mcp_sessions_active                gauge    {tunnel}
mcp_session_duration_seconds       histogram {tunnel}

# Request metrics
mcp_requests_total                 counter  {tunnel, mcp_method, status}
mcp_request_duration_seconds       histogram {tunnel, mcp_method}
mcp_streams_active                 gauge    {tunnel}

# Policy metrics (aware mode)
mcp_policy_decisions_total         counter  {tunnel, decision, reason}

# SSE metrics
mcp_sse_streams_active             gauge    {tunnel}
mcp_sse_events_total               counter  {tunnel}
```

## Wire Protocol

### ALPN

`mcp-v1` — distinct from caddy-rift's `rift-v1`. Prevents cross-protocol connection.

### Control Messages (Stream 0)

```
┌─────────┬──────────┬─────────────────────────┐
│ Type    │ Size     │ Payload                 │
│ (1 byte)│ (4 bytes)│ (variable, JSON)        │
└─────────┴──────────┴─────────────────────────┘
```

| Type | Direction | Payload |
|------|-----------|---------|
| `0x01` Auth | client→server | `{"token": "mcp_abc..."}` |
| `0x02` AuthOK | server→client | `{"ok": true}` |
| `0x03` Register | client→server | `{"tunnels": [{"name": "code-server", "capabilities": {...}}]}` |
| `0x04` RegisterOK | server→client | `{"tunnels": ["code-server"]}` |
| `0x05` Error | bidirectional | `{"code": 401, "message": "..."}` |
| `0x06` Heartbeat | bidirectional | `{}` |
| `0x07` Capabilities | client→server | `{"tunnel": "code-server", "tools": [...], "resources": [...]}` |

### Tunnel Header (per data stream)

```
┌──────────┬──────────┬──────────┐
│ TunnelID │ SessionID│ Reserved │
│ (4 bytes)│ (16 bytes│ (4 bytes)│
│          │  UUID)   │          │
└──────────┴──────────┴──────────┘
Total: 24 bytes
```

SessionID embedded in tunnel header for session-sticky routing without parsing HTTP headers at transport layer. Reserved 4 bytes for future metadata (mode flags, protocol version).

### Stream Lifecycle

1. Caddy opens new QUIC stream
2. Writes 24-byte TunnelHeader
3. Writes HTTP request bytes (request line + headers + body)
4. Client reads header → routes to correct local MCP server
5. Client forwards HTTP request to upstream, reads response
6. Client writes HTTP response bytes back on stream
7. Stream closes (POST request-response) OR stays open (SSE long-lived GET)

### SSE Stream Handling

SSE streams for MCP server→client notifications require special handling:
- QUIC stream stays open indefinitely
- `sse_keepalive` interval sends empty comment (`: keepalive\n\n`) to detect dead connections
- `stream_timeout` does NOT apply to active SSE streams (only idle streams)
- Client-side: reads SSE events from local MCP server, writes to QUIC stream
- Server-side: reads from QUIC stream, writes to HTTP response as SSE events

## Caddyfile Configuration

### Global Block

```caddyfile
{
    mcp {
        # QUIC listener
        listen :4443

        # TLS (production)
        tls_cert /path/to/cert.pem
        tls_key /path/to/key.pem

        # Dev mode — self-signed TLS, no token auth
        dev

        # Token backend
        token_file /etc/caddy/mcp-tokens.json
        token_backend bolt
        default_token_ttl 24h

        # Connection limits
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

### Transport Block (Transparent Mode)

```caddyfile
code-tools.example.com {
    reverse_proxy {
        transport mcp {
            tunnel code-server
        }
    }
}
```

### Transport Block (Aware Mode)

```caddyfile
code-tools.example.com {
    authorize with mypolicy

    reverse_proxy {
        transport mcp {
            tunnel code-server
            mode aware
            policy /etc/caddy/mcp-policies.json

            # Tunnel-level ACLs (apply to all users)
            allow_tools read_file list_files search
            deny_tools execute_command shell_exec
            allow_resources "file:///repo/*"
            deny_resources "file:///etc/*" "file:///**/secret*"
        }
    }
}
```

### Multi-Server Example

```caddyfile
{
    mcp {
        listen :4443
        token_file /etc/caddy/mcp-tokens.json
        discovery
    }

    log mcp_audit {
        include mcp.audit
        output file /var/log/caddy/mcp-audit.json
    }
}

code-tools.example.com {
    basicauth {
        alice $2a$14$...
    }
    reverse_proxy {
        transport mcp {
            tunnel code-server
            mode aware
            deny_tools execute_command
        }
    }
}

db-tools.example.com {
    reverse_proxy {
        transport mcp {
            tunnel db-server
            mode transparent
        }
    }
}
```

### Token File Format

```json
{
    "tokens": [
        {
            "name": "team-frontend",
            "token_hash": "sha256:abcdef...",
            "allowed_tunnels": ["code-server", "docs-*"],
            "expires_at": "2026-05-28T00:00:00Z"
        }
    ]
}
```

Token ACLs are tunnel-level only. MCP-level ACLs (tools, resources) are in the policy file referenced by Caddyfile `policy` directive.

## Client CLI

```bash
# Connect to HTTP MCP server
caddy-mcp client \
    --server mcp.example.com:4443 \
    --token mcp_abc123... \
    --tunnel code-server \
    --upstream http://localhost:8080

# Connect to stdio MCP server (already running, via unix socket or named pipe)
caddy-mcp client \
    --server mcp.example.com:4443 \
    --token mcp_abc123... \
    --tunnel code-server \
    --upstream-stdio /tmp/mcp-server.sock

# Multiple tunnels
caddy-mcp client \
    --server mcp.example.com:4443 \
    --token mcp_abc123... \
    --tunnel code-server=http://localhost:8080 \
    --tunnel db-tools=http://localhost:9090
```

## Security Model

### Layer 1: Transport Security (QUIC/TLS 1.3)
- All QUIC connections TLS 1.3 encrypted (protocol mandate)
- ALPN `mcp-v1` prevents cross-protocol attacks
- Production: user-provided certificates
- Dev: self-signed ECDSA cert (24h lifetime, P-256)
- No double encryption — transport returns `TLSEnabled() → false`

### Layer 2: QUIC Token Authentication
- Token format: `mcp_` prefix + 32 random bytes (base64url) = 48 chars
- Stored as SHA256 hash only — plaintext never persisted
- Validated on QUIC connection setup (control stream)
- TTL-based expiration + manual revocation via admin API
- Redacted in all structured logs

### Layer 3: Auth Rate Limiting
- Per-IP auth failure tracking on QUIC connections
- Exponential backoff after 3 failures → cooldown
- Prometheus metric: `mcp_auth_failures_total`

### Layer 4: Tunnel-Level ACLs
- Token → allowed tunnels (glob patterns via `filepath.Match`)
- Checked on registration AND every request routing
- Prevents rogue clients claiming unauthorized tunnels

### Layer 5: HTTP-Side Authentication (Caddy Native)
- Delegated entirely to Caddy's auth middleware
- `basic_auth`, JWT (caddy-security), mTLS, OAuth — all work naturally
- caddy-mcp reads authenticated identity from `{http.auth.user.id}` for policy evaluation
- HTTP-side rate limiting via caddy-ratelimit (not reimplemented)

### Layer 6: MCP-Level ACLs (Aware Mode)
- Tool filtering: allow/deny lists per tunnel + per user
- Resource filtering: URI glob patterns
- Effective ACL = tunnel config ∩ user policy (most restrictive wins)
- Deny → JSON-RPC error, request never reaches MCP server

### Layer 7: Audit Trail
- Every request logged via zap namespace `mcp.audit`
- Transparent: HTTP-level fields
- Aware: adds MCP method, tool/resource, policy decision
- Operators route via Caddy log config

### Layer 8: Resource Limits

| Limit | Default | Purpose |
|-------|---------|---------|
| `max_conns_per_ip` | 5 | Prevent QUIC connection spam |
| `max_total_conns` | 1000 | Global QUIC connection cap |
| `max_tunnels_per_conn` | 10 | Tunnels per client |
| `max_sessions_per_tunnel` | 50 | Concurrent MCP sessions |
| `stream_timeout` | 30m | Idle stream deadline |
| `sse_keepalive` | 30s | Dead SSE detection |
| Admin body limit | 4KB | POST abuse prevention |

### Layer 9: Input Validation
- Tunnel names: alphanumeric + `-_`, max 64 chars
- ACL patterns: validated via `filepath.Match()` (safe glob)
- Token names: 1-256 chars, unique enforced
- JSON-RPC (aware mode): strict parsing — malformed → reject
- Session IDs: UUID v4 format validation

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Token brute-force | Rate limiter + exponential backoff per IP |
| Stolen token | TTL expiry + revocation + audit trail |
| Rogue tunnel registration | Token ACL restricts claimable tunnels |
| Tool abuse | Aware mode deny_tools + per-user policy |
| Resource exfiltration | Resource URI ACLs |
| Session hijacking | UUID v4 (128-bit entropy), tied to auth identity |
| QUIC connection flood | max_conns_per_ip + max_total_conns |
| Malformed JSON-RPC | Strict parsing, reject before forward |
| Admin API abuse | Caddy localhost:2019 + body size limit |
| Cross-protocol attack | ALPN mcp-v1 isolation |

## Project Structure

```
caddy-mcp/
├── cmd/caddy-mcp/main.go           # xcaddy build entry
├── proto/
│   ├── proto.go                     # ControlMsg, TunnelHeader
│   └── proto_test.go
├── policy/
│   ├── engine.go                    # JSON-RPC parsing, ACL evaluation
│   ├── engine_test.go
│   ├── rules.go                     # Rule types, glob matching
│   └── rules_test.go
├── examples/
│   ├── Caddyfile.dev
│   ├── Caddyfile.prod
│   ├── Caddyfile.aware
│   ├── Caddyfile.transparent
│   ├── Caddyfile.multi
│   ├── Caddyfile.discovery
│   ├── Caddyfile.basicauth
│   └── Caddyfile.jwt
├── app.go                           # caddy.App — QUIC listener, lifecycle
├── transport.go                     # reverse_proxy transport
├── registry.go                      # Tunnel registry
├── session.go                       # MCP session table
├── tokens.go                        # TokenStore + JSON backend
├── tokens_bbolt.go                  # BoltDB backend
├── admin.go                         # Admin API routes
├── caddyfile.go                     # Caddyfile parsing
├── discovery.go                     # Discovery HTTP handler
├── audit.go                         # Audit logger (zap mcp.audit)
├── metrics.go                       # Prometheus metrics
├── ratelimit.go                     # QUIC auth rate limiter
├── shared.go                        # Shared state across reloads
├── worker.go                        # Worker pool
├── validate.go                      # Input validation
├── mcp.go                           # MCP protocol types
├── go.mod / go.sum
├── Makefile / Dockerfile / .goreleaser.yaml
├── LICENSE / README.md / .gitignore
└── *_test.go                        # Tests for each file
```

## Dependencies

```
github.com/caddyserver/caddy/v2       — Core framework
github.com/quic-go/quic-go            — QUIC protocol
go.etcd.io/bbolt                       — BoltDB token backend
go.uber.org/zap                        — Structured logging (via Caddy)
github.com/prometheus/client_golang    — Metrics (via Caddy)
golang.org/x/sync                      — Worker pool (errgroup)
```

## Future Work (Planned, Not in V1)

1. **Per-tool rate limiting** — max N calls/minute per tool per user
2. **Argument sanitization** — validate/filter tool arguments (block path traversal, injection)
3. **Prompt restrictions** — limit which MCP prompts a user can invoke
4. **CertMagic integration** — automatic TLS for QUIC listener via Caddy's ACME
5. **Shared library extraction** — common QUIC tunnel code shared with caddy-rift once both stabilize
6. **MCP server process spawning** — client manages MCP server lifecycle (spawn, restart, health check)
7. **Distributed session state** — session table backed by external store for multi-instance Caddy
8. **WebSocket fallback** — for environments where QUIC is blocked
