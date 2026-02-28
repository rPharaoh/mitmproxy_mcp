# mitmproxy_mcp — Standalone (All-in-One)

Single container running **Elasticsearch + mitmproxy + MCP server** together. No multi-service orchestration — just one container.

## Quick Start

```bash
cd standalone
docker compose up -d
```

| Service     | Port | Description                    |
|-------------|------|--------------------------------|
| Proxy       | 8080 | Point your browser/app here    |
| MCP Server  | 8001 | Connect your LLM client here   |
| Dashboard   | 8002 | Web UI for traffic visualization |
| Elasticsearch | *(internal)* | 127.0.0.1:9200 inside container |

## Setup

1. **Start the container:**
   ```bash
   docker compose up -d
   ```

2. **Configure your browser** to use `http://localhost:8080` as HTTP proxy

3. **Install the CA certificate** via `http://mitm.it` (one-time, persisted in volume)

4. **Connect your MCP client** to `http://localhost:8001/mcp/`

5. **Open the Dashboard** at `http://localhost:8002`

   VS Code `.vscode/mcp.json`:
   ```json
   {
     "servers": {
       "mitmproxy_mcp": {
         "url": "http://localhost:8001/mcp/"
       }
     }
   }
   ```

## With Authentication

```bash
# .env file in standalone/
LLMPROXY_AUTH_REQUIRED=1
LLMPROXY_ADMIN_TOKEN=your-secret-admin-token
```

```bash
docker compose up -d

# Create user tokens
docker compose exec mitmproxy-mcp python admin_cli.py create "User Name"
```

## Data Persistence

Two volumes are created automatically:

| Volume | Purpose |
|--------|---------|
| `es-data` | Elasticsearch indices (all captured traffic) |
| `mitmproxy-certs` | mitmproxy CA certificate |

Data survives container rebuilds and restarts.

## Resource Tuning

Elasticsearch memory (default 512MB heap):

```yaml
environment:
  ES_JAVA_OPTS: "-Xms1g -Xmx1g"
```

## Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose exec mitmproxy-mcp supervisorctl status
docker compose exec mitmproxy-mcp supervisorctl tail -f proxy
docker compose exec mitmproxy-mcp supervisorctl tail -f mcp
docker compose exec mitmproxy-mcp supervisorctl tail -f dashboard
docker compose exec mitmproxy-mcp supervisorctl tail -f elasticsearch
```

## When to Use This vs. the Multi-Container Setup

| | Standalone | Multi-Container (`../docker-compose.yml`) |
|---|---|---|
| Containers | 1 | 4 |
| Setup | Simpler | More flexible |
| Best for | Local dev, demos, single user | Production, teams, scaling |
| ES management | Built-in | Separate container |
| Resource isolation | Shared | Independent |

## Stopping

```bash
docker compose down          # stop, keep data
docker compose down -v       # stop and delete all data
```
