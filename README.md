# mitmproxy_mcp

An MCP server that exposes **mitmproxy-captured web traffic** as tools an LLM can use — inspect requests, analyze patterns, block domains, and more.

## Architecture

```
┌───────────────┐         ┌──────────────┐          ┌───────────────┐
│   Browser /   │  HTTP   │  mitmproxy   │  write   │               │
│   App traffic ├────────►│  + addon     ├─────────►│ Elasticsearch │
│               │         │  (proxy_     │          │  (search &    │
└───────────────┘         │   addon.py)  │          │   analytics)  │
                          └──────────────┘          └───────┬───────┘
                                                            │ read
                                                    ┌───────▼───────┐
                                                    │  MCP Server   │
                                                    │  (mcp_server  │
                                                    │   .py)        │
                                                    └───────┬───────┘
                                                            │ MCP protocol
                                                    ┌───────▼───────┐
                                                    │  LLM Client   │
                                                    │  (Claude, etc)│
                                                    └───────────────┘
                                                    ┌───────▲───────┐
                                                    │   Dashboard   │
                                                    │  (web UI on   │
                                                    │   port 8002)  │
                                                    └───────────────┘
```

The **proxy** and the **MCP server** run as separate containers. The proxy writes captured request/response data to a shared **Elasticsearch** instance (full-text search, aggregations, concurrent access), and the MCP server reads from it. A write buffer batches proxy inserts via the ES bulk API for maximum throughput under heavy traffic.

The **Dashboard** provides a web UI for visualizing traffic, security findings, performance analysis, and managing proxy rules — no LLM client required.

## Quick Start

### Option A: Docker (recommended)

```bash
docker compose up -d
```

This starts:
- **Proxy** on `http://localhost:8080` — point your browser/app here
- **MCP server** (Streamable HTTP) on `http://localhost:8001` — connect your LLM client here
- **Dashboard** on `http://localhost:8002` — web UI for traffic visualization

Both connect to a shared Elasticsearch instance (started automatically).

The mitmproxy CA certificate is persisted in a Docker volume (`mitmproxy-certs`), so you only need to install it once via `http://mitm.it` — it survives rebuilds and restarts.

To stop:

```bash
docker compose down
```

### Multi-Tenant Deployment

To deploy with **per-user token isolation** (each user only sees their own traffic):

1. Create a `.env` file (or export env vars):

```bash
LLMPROXY_ADMIN_TOKEN=your-secret-admin-token-here
LLMPROXY_AUTH_REQUIRED=1
```

2. Start the stack:

```bash
docker compose up -d
```

3. Create user tokens via the Admin CLI:

```bash
docker compose exec mcp python admin_cli.py create "User Name"
```

The CLI prints the raw token and a ready-to-paste MCP client config.

#### How Auth Works

**Proxy (mitmproxy):** Users authenticate via `Proxy-Authorization` header using HTTP Basic auth — the **username** is the user's token, the password is ignored.

```
Proxy-Authorization: Basic <base64(token:)>
```

The proxy strips this header before forwarding upstream. If auth is required and the token is invalid, the proxy returns **407 Proxy Authentication Required**.

**Proxy (HTTPS / CONNECT):** For HTTPS traffic, the proxy validates the token during the CONNECT tunnel handshake. Chrome and other browsers send `Proxy-Authorization` only on CONNECT — the proxy stashes the tenant for all subsequent requests in that tunnel. Configure your browser proxy as `127.0.0.1:8080` (no credentials in URL) and enter the token as username when prompted.

**MCP Server (Streamable HTTP):** Users authenticate via Bearer token in the `Authorization` header or a `?token=` query parameter.

```
Authorization: Bearer <user-token>
```
or
```
http://localhost:8001/mcp/?token=<user-token>
```

If the token is invalid or missing, the server returns **401 Unauthorized**.

**Admin token** has unrestricted access — it can see all traffic across all tenants and manage tokens. **User tokens** are scoped to their tenant — they can only see traffic captured under their own token.

#### Admin Tools

Manage tokens via the **Admin CLI** (`admin_cli.py`) or the MCP admin tools:

**CLI (recommended):**

```bash
# Create a token
docker compose exec mcp python admin_cli.py create "My App"

# List all tokens (values are masked)
docker compose exec mcp python admin_cli.py list

# Revoke a token
docker compose exec mcp python admin_cli.py revoke <token>
```

For local (non-Docker) usage:

```bash
LLMPROXY_ES_URL=http://localhost:9200 python admin_cli.py create "My App"
LLMPROXY_ES_URL=http://localhost:9200 python admin_cli.py list
LLMPROXY_ES_URL=http://localhost:9200 python admin_cli.py revoke <token>
```

The `create` command prints the raw token (shown only once), tenant ID, and a ready-to-paste MCP client config snippet.

**MCP tools (from LLM client, admin token required):**

| Tool | Description |
|------|-------------|
| `create_token` | Create a new user token |
| `list_tokens` | List all tokens with masked values |
| `revoke_token` | Revoke / deactivate a token |

#### Backward Compatibility

When `LLMPROXY_AUTH_REQUIRED` is `0` (the default), auth is completely disabled — no tokens required, all traffic is visible to everyone. This preserves the original single-user behavior.

### Option B: Local (pipenv)

### 1. Install dependencies

```bash
pipenv install
```

This creates a virtual environment and installs all dependencies from the `Pipfile`. To activate the shell:

```bash
pipenv shell
```

### 2. Start the proxy

```bash
# Interactive UI
pipenv run mitmproxy -s proxy_addon.py

# Headless
pipenv run mitmdump -s proxy_addon.py

# Browser UI
pipenv run mitmweb -s proxy_addon.py
```

Configure your browser/app to use `http://localhost:8080` as its HTTP proxy. Install the mitmproxy CA certificate for HTTPS interception (see [mitmproxy docs](https://docs.mitmproxy.org/stable/concepts-certificates/)).

### 3. Start the MCP server

**Stdio transport** (for Claude Desktop, Cursor, etc.):

```bash
pipenv run python mcp_server.py
```

**Streamable HTTP transport** (for VS Code, web-based MCP clients):

```bash
pipenv run python mcp_server.py --transport streamable-http --port 8000
```

**SSE transport** (for legacy MCP clients):

```bash
pipenv run python mcp_server.py --transport sse --port 8000
```

### 4. Configure your MCP client

#### VS Code / Cursor (`.vscode/mcp.json`)

**Docker (Streamable HTTP):**

```json
{
  "servers": {
    "llmproxy": {
      "url": "http://localhost:8001/mcp/"
    }
  }
}
```

**Docker with auth:**

```json
{
  "servers": {
    "llmproxy": {
      "url": "http://localhost:8001/mcp/?token=YOUR_TOKEN_HERE"
    }
  }
}
```

**Local (stdio):**

```json
{
  "servers": {
    "llmproxy": {
      "command": "python",
      "args": ["path/to/mcp_server.py"],
      "env": {
        "LLMPROXY_ES_URL": "http://localhost:9200"
      }
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)

**Docker:**

```json
{
  "mcpServers": {
    "llmproxy": {
      "url": "http://localhost:8001/mcp/"
    }
  }
}
```

**Local (stdio):**

```json
{
  "mcpServers": {
    "llmproxy": {
      "command": "python",
      "args": ["path/to/mcp_server.py"],
      "env": {
        "LLMPROXY_ES_URL": "http://localhost:9200"
      }
    }
  }
}
```

## MCP Tools

### Core Traffic Tools

| Tool | Description |
|------|-------------|
| `get_recent_requests` | List recent captured requests with optional filters (method, host, status, URL search) |
| `get_request_detail` | Full details of a single request (headers, body, timing) |
| `search_requests` | Search by pattern on url, host, path, request/response body, or content type |
| `get_domain_summary` | Traffic stats grouped by domain |
| `get_traffic_stats` | Overall statistics (totals, averages, error counts) |
| `find_errors` | Find 4xx/5xx responses |
| `block_domain` | Add a domain to the block list (proxy returns 403) |
| `unblock_domain` | Remove a domain from the block list |
| `list_blocked_domains` | Show all blocked domains |
| `tag_request` | Attach a label to a request |
| `get_request_tags` | Retrieve tags for a request |
| `get_live_feed` | Poll-based live stream — returns new HTTP + WS traffic since last cursor |

### API Mapping & WebSocket

| Tool | Description |
|------|-------------|
| `map_api` | Discover and map API endpoints from captured traffic (auto-normalizes paths) |
| `get_endpoint_detail` | Drill into a specific endpoint — recent requests matching host + path |
| `get_ws_connections` | List captured WebSocket connections with message counts and bytes |
| `get_ws_messages` | List WebSocket messages with filters (flow, host, direction, search) |
| `get_ws_stats` | Overall WebSocket statistics |

### Security & Penetration Testing

| Tool | Description |
|------|-------------|
| `scan_vulnerabilities` | Scan traffic for SQL injection leaks, XSS, path traversal, plaintext creds, exposed paths, stack traces |
| `analyze_security_headers` | Check response for HSTS, CSP, X-Frame-Options, etc. |
| `detect_pii` | Scan bodies for PII: emails, credit cards, SSNs, phones, JWTs, AWS keys |
| `extract_session_tokens` | Find auth tokens, session cookies, API keys across traffic |
| `detect_session_issues` | Cross-host cookie reuse, missing CSRF, insecure cookie flags |
| `detect_c2_patterns` | Detect C2 beaconing (regular-interval requests) and encoded payloads |

### Privacy & Compliance

| Tool | Description |
|------|-------------|
| `audit_third_parties` | List all external domains with stats, categorized as ads/tracking, social, CDN |
| `analyze_cookies` | Parse and categorize cookies: session, tracking, CSRF, preference; reports security flags |

### Debugging & Development

| Tool | Description |
|------|-------------|
| `compare_requests` | Side-by-side diff of two requests (headers, body, status, timing) |
| `generate_openapi_spec` | Generate OpenAPI 3.0 spec from observed traffic patterns |
| `analyze_performance` | Find slow endpoints (P95), large payloads, redundant requests, error hotspots |
| `generate_curl` | Generate a curl command that reproduces a captured request |

### Monitoring & Analysis

| Tool | Description |
|------|-------------|
| `detect_anomalies` | Status distribution, timing outliers (>3σ), rare hosts, error bursts |
| `summarize_activity` | Activity dashboard: totals, top hosts/paths, hourly breakdown |
| `bandwidth_analysis` | Top bandwidth consumers by host and content type |

### Active Traffic Manipulation

| Tool | Description |
|------|-------------|
| `replay_request` | Replay a captured request with modified headers, body, method, or URL |
| `create_traffic_rule` | Create real-time proxy rules: inject headers, throttle, block patterns, modify bodies |
| `list_traffic_rules` | List all active traffic manipulation rules |
| `remove_traffic_rule` | Remove a traffic rule by ID |
| `toggle_traffic_rule` | Enable/disable a rule without deleting it |

### Fuzzing & Endpoint Discovery

| Tool | Description |
|------|-------------|
| `fuzz_request` | Fuzz a captured request's parameters with SQLi, XSS, path traversal, and command injection payloads |
| `discover_endpoints` | Brute-force common paths on a host (admin panels, backups, config files, API endpoints) |

### External Scanning

| Tool | Description |
|------|-------------|
| `nmap_scan` | Run nmap port/service scans against a target (parsed XML output) |
| `nikto_scan` | Run nikto web vulnerability scanner against a target |
| `sslyze_scan` | Analyze TLS/SSL configuration of a host |
| `subfinder_scan` | Discover subdomains for a domain using passive sources |
| `scan_available_tools` | Check which external scanning tools are installed in the container |

### Reconnaissance & Asset Discovery

| Tool | Description |
|------|-------------|
| `discover_hosts` | Discover live hosts on a network/subnet via nmap (ping, ARP, SYN, connect, or service scan) |
| `fingerprint_services` | Deep service + OS fingerprinting on a single host |
| `http_probe` | Probe hosts for web servers using httpx — reports status, title, tech stack, CDN |
| `dns_enum` | Enumerate DNS records (A, AAAA, MX, NS, CNAME, TXT, SOA) with optional subdomain brute-force |
| `full_recon` | Chained pipeline: subfinder → dnsx → httpx for complete domain asset mapping |

### Admin (requires admin token)

| Tool | Description |
|------|-------------|
| `create_token` | Create a new user token |
| `list_tokens` | List all tokens with masked values |
| `revoke_token` | Revoke / deactivate a token |
| `clear_tenant_data` | Delete all captured data for a tenant (requests, websockets, tags, rules, blocked domains) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLMPROXY_ES_URL` | `http://elasticsearch:9200` | Elasticsearch connection URL |
| `LLMPROXY_MAX_BODY` | `524288` (512 KB) | Max response body size stored per request |
| `LLMPROXY_CAPTURE_BODY` | `1` | Set to `0` to skip storing request/response bodies |
| `LLMPROXY_FLUSH_SIZE` | `100` | Rows in write buffer before auto-flush |
| `LLMPROXY_FLUSH_INTERVAL` | `1.0` | Seconds before timer-based buffer flush |
| `LLMPROXY_AUTH_REQUIRED` | `0` | Set to `1` to enable multi-tenant token authentication |
| `LLMPROXY_ADMIN_TOKEN` | *(empty)* | Admin token for unrestricted access and token management |

## Dashboard

The **Dashboard** is a web-based UI available at `http://localhost:8002` that provides full visibility into captured traffic without needing an LLM client.

### Features

| Page | Description |
|------|-------------|
| **Overview** | Real-time stats, request timeline, top hosts/domains charts |
| **Live Feed** | Auto-refreshing stream of HTTP and WebSocket traffic |
| **Requests** | Searchable request table with full detail modal (headers, body, timing) |
| **Domains** | Domain breakdown with request counts and traffic volume |
| **Errors** | Filtered view of 4xx/5xx responses |
| **WebSocket** | WebSocket connections and message inspector |
| **Performance** | Slow endpoints, large payloads, and performance analysis |
| **Security** | Vulnerability scan results, security header checks |
| **Privacy** | Third-party audit, cookie analysis, PII detection |
| **API Map** | Discovered API endpoints per domain with OpenAPI spec generation |
| **Blocked** | Manage blocked domains |
| **Rules** | Create, toggle, and remove traffic manipulation rules |

### Authentication

When `LLMPROXY_AUTH_REQUIRED=1`, the dashboard shows a **login screen** prompting for a token:

- **Admin token** — full access to all data plus a tenant selector to filter by user
- **User token** — scoped view showing only that user's own traffic

The user badge in the sidebar shows the token's **name** (set during token creation) with a logout button.

When auth is disabled (`LLMPROXY_AUTH_REQUIRED=0`), the dashboard loads directly with full access and a tenant selector dropdown.

## Files

| File | Purpose |
|------|---------|
| `db.py` | Shared database module (schema, inserts, queries) |
| `proxy_addon.py` | mitmproxy addon — captures traffic, enforces domain blocking |
| `mcp_server.py` | MCP server entry point — slim core with auth middleware |
| `admin_cli.py` | Admin CLI — create, list, and revoke API tokens |
| `tools/__init__.py` | Tool module auto-registration |
| `tools/traffic.py` | Traffic browsing, search, and live feed tools |
| `tools/security.py` | Vulnerability scanning, PII detection, session analysis, C2 detection |
| `tools/websocket.py` | WebSocket connection and message tools |
| `tools/api_mapping.py` | API mapping and OpenAPI spec generation |
| `tools/debugging.py` | Request comparison, cURL generation, performance analysis, replay |
| `tools/privacy.py` | Third-party audit and cookie analysis |
| `tools/monitoring.py` | Anomaly detection, activity summaries, bandwidth analysis |
| `tools/control.py` | Domain blocking, tagging, and traffic rule management |
| `tools/admin.py` | Token management and tenant data clearing (admin-only) |
| `tools/fuzzing.py` | Parameter fuzzing and endpoint discovery |
| `tools/scanning.py` | External scanner wrappers (nmap, nikto, sslyze, subfinder) |
| `tools/recon.py` | Asset discovery and reconnaissance (host discovery, HTTP probing, DNS enum) |
| `Pipfile` | Python dependencies (pipenv) |
| `Pipfile.lock` | Locked dependency versions |
| `Dockerfile` | Multi-stage build (proxy + mcp + dashboard targets) with nmap, nikto, httpx, dnsx, subfinder, sslyze |
| `docker-compose.yml` | Runs proxy + MCP server + Dashboard + Elasticsearch together |
| `dashboard_server.py` | Dashboard REST API server + static file server (Starlette/Uvicorn) |
| `dashboard/static/index.html` | Dashboard single-page application shell |
| `dashboard/static/style.css` | Dashboard dark theme styles |
| `dashboard/static/app.js` | Dashboard client-side logic, charts, auth flow |

## Example Prompts

Once connected, you can ask your LLM things like:

**Traffic inspection:**
- *"Show me the last 10 requests to api.example.com"*
- *"Are there any requests returning 500 errors?"*
- *"Summarize which domains are getting the most traffic"*
- *"Stream the live traffic and tell me what’s happening"*

**Security & pen testing:**
- *"Scan all captured traffic for vulnerabilities"*
- *"Check if any requests are leaking PII like emails or credit cards"*
- *"Extract all session tokens and API keys from the traffic"*
- *"Look for C2 beaconing patterns in outbound traffic"*
- *"Check the security headers on request #42"*
- *"Are any cookies missing Secure or HttpOnly flags?"*

**Privacy & compliance:**
- *"Audit all third-party domains – which ones are trackers?"*
- *"Categorize all cookies being set and check their security flags"*

**Debugging & development:**
- *"Compare request #10 with request #15 – why did one fail?"*
- *"Generate an OpenAPI spec from the api.example.com traffic"*
- *"Find performance bottlenecks – which endpoints are slowest?"*
- *"Generate a curl command for request #42"*
- *"Map out all the API endpoints on api.example.com"*

**Monitoring:**
- *"Detect any anomalies in the traffic"*
- *"Give me an activity summary for the last 4 hours"*
- *"Which hosts are consuming the most bandwidth?"*

**Active manipulation:**
- *"Replay request #42 but change the Authorization header"*
- *"Add an X-Frame-Options: DENY header to all responses from example.com"*
- *"Throttle requests to slow-api.com by 2 seconds"*
- *"Block all requests matching /ads/*"*
- *"List all active traffic rules"*

**Fuzzing & scanning:**
- *"Fuzz request #42 for XSS and SQL injection"*
- *"Discover hidden endpoints on example.com"*
- *"Run an nmap scan on 192.168.1.0/24"*
- *"Scan example.com with nikto"*
- *"Check the TLS configuration on example.com"*
- *"Find all subdomains of example.com"*

**Reconnaissance:**
- *"Discover all live hosts on 10.0.0.0/24"*
- *"Fingerprint the services on 192.168.1.1"*
- *"Probe these hosts for web servers and detect their tech stack"*
- *"Enumerate DNS records for example.com"*
- *"Run full recon on example.com — find subdomains, resolve DNS, and probe for web servers"*

**Admin:**
- *"List all tokens"*
- *"Clear all data for tenant abc123"*

**WebSocket:**
- *"List all WebSocket connections"*
- *"Show me the WebSocket messages for flow abc123"*
- *"Give me overall WebSocket stats"*
