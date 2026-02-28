#!/bin/bash
set -e

# ── Start Elasticsearch (as elasticsearch user) ──────────────────────────
echo "[entrypoint] Starting Elasticsearch..."
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch

# ── Wait for ES to be ready, then hand off to supervisord ─────────────────
# supervisord manages all three processes with proper lifecycle
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
