FROM python:3.11-slim AS base

RUN pip install --no-cache-dir pipenv

WORKDIR /app

COPY Pipfile Pipfile.lock ./
RUN pipenv install --deploy --system && \
    pip cache purge

COPY db.py proxy_addon.py mcp_server.py ./

VOLUME /data
ENV LLMPROXY_DB=/data/traffic.duckdb

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
