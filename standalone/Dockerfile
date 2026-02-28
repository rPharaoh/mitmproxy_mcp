# ---------------------------------------------------------------------------
# mitmproxy_mcp  –  All-in-one container
# Elasticsearch 8 + mitmproxy (capture) + MCP server in a single image
# ---------------------------------------------------------------------------

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System deps + scanning tools ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        nmap \
        libnet-ssleay-perl \
        libjson-perl \
        libxml-writer-perl \
        perl \
        git \
        wget \
        unzip \
        supervisor \
        gnupg \
        apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Elasticsearch 8.17 ─────────────────────────────────────────────────
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
        gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
        > /etc/apt/sources.list.d/elastic-8.x.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends elasticsearch=8.17.0 \
    && rm -rf /var/lib/apt/lists/*

# Elasticsearch config – single-node, no security, low memory
RUN echo 'cluster.name: mitmproxy-mcp'                >  /etc/elasticsearch/elasticsearch.yml && \
    echo 'discovery.type: single-node'                 >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'xpack.security.enabled: false'               >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'xpack.security.transport.ssl.enabled: false' >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'xpack.security.http.ssl.enabled: false'      >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'network.host: 127.0.0.1'                     >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'http.port: 9200'                             >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'path.data: /var/lib/elasticsearch'           >> /etc/elasticsearch/elasticsearch.yml && \
    echo 'path.logs: /var/log/elasticsearch'           >> /etc/elasticsearch/elasticsearch.yml && \
    mkdir -p /var/lib/elasticsearch /var/log/elasticsearch && \
    chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch /etc/elasticsearch

ENV ES_JAVA_OPTS="-Xms512m -Xmx512m"

# ── 3. nikto ───────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── 4. ProjectDiscovery Go binaries (subfinder, httpx, dnsx) ──────────────
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

# ── 5. Python deps ────────────────────────────────────────────────────────
RUN pip install --no-cache-dir pipenv sslyze

WORKDIR /app

COPY Pipfile Pipfile.lock ./
RUN pipenv install --deploy --system && pip cache purge

# ── 6. Application code ───────────────────────────────────────────────────
COPY db.py proxy_addon.py mcp_server.py admin_cli.py dashboard_server.py ./
COPY tools/ ./tools/
COPY dashboard/ ./dashboard/

# ── 7. Supervisor config ──────────────────────────────────────────────────
COPY standalone/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY standalone/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── 8. Environment defaults ───────────────────────────────────────────────
ENV LLMPROXY_ES_URL=http://127.0.0.1:9200 \
    LLMPROXY_MAX_BODY=524288 \
    LLMPROXY_CAPTURE_BODY=1 \
    LLMPROXY_FLUSH_SIZE=100 \
    LLMPROXY_FLUSH_INTERVAL=1.0 \
    LLMPROXY_AUTH_REQUIRED=0 \
    LLMPROXY_ADMIN_TOKEN=""

# Proxy: 8080  |  MCP: 8000  |  Dashboard: 8002
EXPOSE 8080 8000 8002

VOLUME ["/var/lib/elasticsearch", "/root/.mitmproxy"]

ENTRYPOINT ["/entrypoint.sh"]
