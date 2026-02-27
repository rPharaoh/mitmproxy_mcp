"""
MCP server that exposes mitmproxy-captured web traffic as tools.

Run with:
    python mcp_server.py                          # stdio (default)
    python mcp_server.py --transport sse           # SSE on port 8000
    python mcp_server.py --transport sse --port 9000

Environment variables:
    LLMPROXY_DB   Path to the SQLite database (default: ./traffic.db)
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

import db

# ---------------------------------------------------------------------------

mcp = FastMCP("llmproxy")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS – enforces HTTPS",
    "content-security-policy": "CSP – mitigates XSS and injection",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "Prevents MIME-sniffing",
    "referrer-policy": "Controls Referer header leakage",
    "permissions-policy": "Controls browser feature access",
    "x-xss-protection": "Legacy XSS filter (deprecated but still checked)",
    "cross-origin-opener-policy": "COOP – isolates browsing context",
    "cross-origin-resource-policy": "CORP – restricts resource loading",
    "cross-origin-embedder-policy": "COEP – controls embedding",
}


def _json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_recent_requests(
    limit: int = 25,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
) -> str:
    """List recent captured HTTP requests.

    Supports optional filters by method, host, status_code,
    or URL substring search. Returns id, timestamp, method,
    url, host, status_code, duration_ms.
    """
    rows = db.get_recent_requests(
        limit=limit, method=method, host=host,
        status_code=status_code, search=search,
    )
    return _json({"count": len(rows), "requests": rows})


@mcp.tool()
def get_request_detail(request_id: int) -> str:
    """Get full details of a single captured request by ID, including headers, body, and timing."""
    req = db.get_request_by_id(request_id)
    if req is None:
        return _json({"error": "Request not found"})
    req["tags"] = db.get_tags_for_request(request_id)
    return _json(req)


@mcp.tool()
def search_requests(
    pattern: str,
    field: str = "url",
    limit: int = 50,
) -> str:
    """Search captured requests by substring match on a field.

    Allowed fields: url, host, path, request_body, response_body, content_type.
    """
    rows = db.search_requests(pattern=pattern, field=field, limit=limit)
    return _json({"count": len(rows), "requests": rows})


@mcp.tool()
def get_domain_summary(limit: int = 30) -> str:
    """Aggregate traffic statistics grouped by domain/host.

    Shows request count, methods used, average duration, total bytes, first/last seen.
    """
    rows = db.get_domain_summary(limit=limit)
    return _json({"count": len(rows), "domains": rows})


@mcp.tool()
def get_traffic_stats() -> str:
    """Return overall traffic statistics: total requests, unique hosts, avg duration, total bytes, error count."""
    return _json(db.get_traffic_stats())


@mcp.tool()
def find_errors(limit: int = 50) -> str:
    """Find requests that returned HTTP error status codes (4xx and 5xx)."""
    rows = db.find_errors(limit=limit)
    return _json({"count": len(rows), "errors": rows})


@mcp.tool()
def block_domain(domain: str, reason: str | None = None) -> str:
    """Add a domain to the proxy block list. Future requests will be rejected with 403."""
    added = db.add_blocked_domain(domain, reason)
    status = "blocked" if added else "already_blocked"
    return _json({"status": status, "domain": domain})


@mcp.tool()
def unblock_domain(domain: str) -> str:
    """Remove a domain from the proxy block list."""
    removed = db.remove_blocked_domain(domain)
    status = "unblocked" if removed else "not_found"
    return _json({"status": status, "domain": domain})


@mcp.tool()
def list_blocked_domains() -> str:
    """List all currently blocked domains."""
    rows = db.get_all_blocked_domains()
    return _json({"count": len(rows), "domains": rows})


@mcp.tool()
def tag_request(request_id: int, tag: str) -> str:
    """Add a descriptive tag/label to a captured request for later reference."""
    tag_id = db.add_tag(request_id, tag)
    return _json({"status": "tagged", "tag_id": tag_id})


@mcp.tool()
def get_request_tags(request_id: int) -> str:
    """Get all tags attached to a specific request."""
    tags = db.get_tags_for_request(request_id)
    return _json({"request_id": request_id, "tags": tags})


@mcp.tool()
def analyze_security_headers(request_id: int) -> str:
    """Check a response's security headers (HSTS, CSP, X-Frame-Options, etc.) and report present/missing."""
    req = db.get_request_by_id(request_id)
    if req is None:
        return _json({"error": "Request not found"})

    resp_headers = req.get("response_headers") or {}
    if isinstance(resp_headers, str):
        resp_headers = json.loads(resp_headers)

    lower_headers = {k.lower(): v for k, v in resp_headers.items()}
    present = {}
    missing = []
    for header, desc in SECURITY_HEADERS.items():
        if header in lower_headers:
            present[header] = {"value": lower_headers[header], "description": desc}
        else:
            missing.append({"header": header, "description": desc})

    return _json({
        "url": req["url"],
        "present": present,
        "missing": missing,
        "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
    })


# ---------------------------------------------------------------------------
# API Mapping Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def map_api(host: str | None = None, limit: int = 100) -> str:
    """Discover and map API endpoints from captured traffic.

    Automatically normalizes paths (replaces numeric IDs and UUIDs with
    placeholders) to group similar endpoints. Shows methods, status codes,
    hit count, and average duration per endpoint.
    """
    endpoints = db.get_api_map(host=host, limit=limit)
    return _json({"count": len(endpoints), "endpoints": endpoints})


@mcp.tool()
def get_endpoint_detail(host: str, path: str, limit: int = 50) -> str:
    """Get recent requests for a specific API endpoint (host + path pattern).

    Use after map_api to drill into a particular endpoint.
    """
    rows = db.get_endpoint_detail(host=host, path=path, limit=limit)
    return _json({"count": len(rows), "requests": rows})


# ---------------------------------------------------------------------------
# WebSocket Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_ws_connections(limit: int = 50) -> str:
    """List captured WebSocket connections with message counts, bytes transferred, and timestamps."""
    rows = db.get_ws_connections(limit=limit)
    return _json({"count": len(rows), "connections": rows})


@mcp.tool()
def get_ws_messages(
    flow_id: str | None = None,
    host: str | None = None,
    direction: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> str:
    """List captured WebSocket messages with optional filters.

    Filters: flow_id (specific connection), host, direction (send/receive),
    search (content substring).
    """
    rows = db.get_ws_messages(
        flow_id=flow_id, host=host, direction=direction,
        search=search, limit=limit,
    )
    return _json({"count": len(rows), "messages": rows})


@mcp.tool()
def get_ws_stats() -> str:
    """Overall WebSocket statistics: total messages, connections, bytes, send/receive breakdown."""
    return _json(db.get_ws_stats())


# ---------------------------------------------------------------------------
# Live Feed
# ---------------------------------------------------------------------------

@mcp.tool()
def get_live_feed(
    after_id: int | None = None,
    after_ws_id: int | None = None,
    include_bodies: bool = False,
    limit: int = 100,
) -> str:
    """Poll-based live stream of HTTP requests and WebSocket messages.

    Returns new traffic since the given cursors.  On the first call, omit
    after_id and after_ws_id to get the latest traffic.  Each response
    includes updated cursor values — pass them back on the next call to
    receive only new items.

    Set include_bodies=True to include full request/response bodies
    (larger payloads).
    """
    feed = db.get_live_feed(
        after_id=after_id,
        after_ws_id=after_ws_id,
        include_bodies=include_bodies,
        limit=limit,
    )
    return _json(feed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
