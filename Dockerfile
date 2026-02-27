FROM python:3.11-slim AS base

RUN pip install --no-cache-dir pipenv

WORKDIR /app

COPY Pipfile Pipfile.lock ./
RUN pipenv install --deploy --system && \
    pip cache purge

COPY db.py proxy_addon.py mcp_server.py admin_cli.py ./

ENV LLMPROXY_ES_URL=http://elasticsearch:9200

# ---------------------------------------------------------------------------
# Proxy target  –  mitmdump with the capture addon
# ---------------------------------------------------------------------------
FROM base AS proxy

EXPOSE 8080
ENTRYPOINT ["mitmdump", "-s", "proxy_addon.py", "--set", "listen_port=8080"]

# ---------------------------------------------------------------------------
# MCP server target  –  stdio by default, override for SSE
# ---------------------------------------------------------------------------
FROM base AS mcp

EXPOSE 8000
ENTRYPOINT ["python", "mcp_server.py"]
