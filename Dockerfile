FROM python:3.11-slim AS base

# Install external scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libnet-ssleay-perl \
        libjson-perl \
        libxml-writer-perl \
        perl \
        git \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Install ProjectDiscovery Go binaries (subfinder, httpx, dnsx)
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip \
    && unzip -oq subfinder_2.6.7_linux_amd64.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder_2.6.7_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \
    && unzip -oq httpx_1.6.9_linux_amd64.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm httpx_1.6.9_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip \
    && unzip -oq dnsx_1.2.1_linux_amd64.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/dnsx \
    && rm dnsx_1.2.1_linux_amd64.zip

RUN pip install --no-cache-dir pipenv sslyze

WORKDIR /app

COPY Pipfile Pipfile.lock ./
RUN pipenv install --deploy --system && \
    pip cache purge

COPY db.py proxy_addon.py mcp_server.py admin_cli.py dashboard_server.py ./
COPY tools/ ./tools/
COPY dashboard/ ./dashboard/

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

# ---------------------------------------------------------------------------
# Dashboard target  –  web UI for traffic visualization
# ---------------------------------------------------------------------------
FROM base AS dashboard

EXPOSE 8002
ENTRYPOINT ["python", "dashboard_server.py"]
