# LLMProxy

An MCP server that exposes **mitmproxy-captured web traffic** as tools an LLM can use — inspect requests, analyze patterns, block domains, and more.

## Architecture

```
┌───────────────┐         ┌──────────────┐         ┌───────────────┐
│   Browser /   │  HTTP   │  mitmproxy   │  write   │               │
│   App traffic ├────────►│  + addon     ├─────────►│  DuckDB       │
│               │         │  (proxy_     │          │  (traffic.    │
└───────────────┘         │   addon.py)  │          │               │
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
```

The **proxy** and the **MCP server** run as separate processes. The proxy writes captured request/response data to a shared **DuckDB** database (columnar, high-throughput), and the MCP server reads from it. A write buffer batches proxy inserts for maximum performance under heavy traffic.

## Quick Start

### Option A: Docker (recommended)

```bash
docker compose up -d
```

This starts:
- **Proxy** on `http://localhost:8080` — point your browser/app here
- **MCP server** (SSE) on `http://localhost:8000` — connect your LLM client here

Both share a DuckDB volume (`llmproxy-data`) automatically.

To stop:

```bash
docker compose down
```

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

**SSE transport** (for web-based MCP clients):

```bash
pipenv run python mcp_server.py --transport sse --port 8000
```

### 4. Configure your MCP client

#### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "llmproxy": {
      "command": "python",
      "args": ["path/to/mcp_server.py"],
      "env": {
        "LLMPROXY_DB": "path/to/traffic.db"
      }
    }
  }
}
```

#### VS Code / Cursor (`.vscode/mcp.json`)

```json
{
  "servers": {
    "llmproxy": {
      "command": "python",
      "args": ["path/to/mcp_server.py"],
      "env": {
        "LLMPROXY_DB": "path/to/traffic.db"
      }
    }
  }
}
```

## MCP Tools

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
| `analyze_security_headers` | Check response for HSTS, CSP, X-Frame-Options, etc. |
| `map_api` | Discover and map API endpoints from captured traffic (auto-normalizes paths) |
| `get_endpoint_detail` | Drill into a specific endpoint — see recent requests matching a host + path pattern |
| `get_ws_connections` | List captured WebSocket connections with message counts and bytes |
| `get_ws_messages` | List WebSocket messages with filters (flow, host, direction, content search) |
| `get_ws_stats` | Overall WebSocket statistics (messages, connections, bytes, send/receive) |
| `get_live_feed` | Poll-based live stream — returns new HTTP + WS traffic since last cursor |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLMPROXY_DB` | `./traffic.duckdb` | Path to the shared DuckDB database |
| `LLMPROXY_MAX_BODY` | `524288` (512 KB) | Max response body size stored per request |
| `LLMPROXY_CAPTURE_BODY` | `1` | Set to `0` to skip storing request/response bodies || `LLMPROXY_FLUSH_SIZE` | `100` | Rows in write buffer before auto-flush |
| `LLMPROXY_FLUSH_INTERVAL` | `1.0` | Seconds before timer-based buffer flush |
## Files

| File | Purpose |
|------|---------|
| `db.py` | Shared database module (schema, inserts, queries) |
| `proxy_addon.py` | mitmproxy addon — captures traffic, enforces domain blocking |
| `mcp_server.py` | MCP server — exposes captured traffic as LLM tools |
| `Pipfile` | Python dependencies (pipenv) |
| `Pipfile.lock` | Locked dependency versions |
| `Dockerfile` | Multi-stage build (proxy + mcp targets) |
| `docker-compose.yml` | Runs proxy + MCP server together |
| `old/` | Backup of previous versions (`old_db.py`, `old_mcp.py`, `old_addon.py`) |

## Example Prompts

Once connected, you can ask your LLM things like:

- *"Show me the last 10 requests to api.example.com"*
- *"Are there any requests returning 500 errors?"*
- *"Summarize which domains are getting the most traffic"*
- *"Block ads.tracker.com — it's an analytics tracker"*
- *"Check the security headers on request #42"*
- *"Search for any requests containing 'password' in the request body"*
- *"Tag request #15 as 'suspicious'"*
- *"Map out all the API endpoints on api.example.com"*
- *"Show me the details for GET /users/{id} on that API"*
- *"List all WebSocket connections"*
- *"Show me the WebSocket messages for flow abc123"*
- *"Give me overall WebSocket stats"*
- *"Stream the live traffic — keep calling get_live_feed and tell me what's happening"*
- *"Watch the traffic feed and alert me if you see any 500 errors"*
