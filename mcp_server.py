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
# Security & Penetration Testing Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_vulnerabilities(limit: int = 500) -> str:
    """Scan captured traffic for security vulnerabilities.

    Detects: SQL injection error leaks, XSS payloads, path traversal,
    plaintext credentials over HTTP, exposed sensitive paths (.git, .env, etc.),
    server version disclosure, and stack trace leaks.
    """
    return _json(db.scan_vulnerabilities(limit=limit))


@mcp.tool()
def detect_pii(limit: int = 500) -> str:
    """Scan request/response bodies for PII (Personally Identifiable Information).

    Detects: email addresses, credit card numbers, SSNs, phone numbers,
    JWTs, AWS access keys, and private keys.
    """
    return _json(db.detect_pii(limit=limit))


@mcp.tool()
def extract_session_tokens(limit: int = 300) -> str:
    """Extract authentication tokens, session cookies, and API keys from
    captured traffic. Finds Authorization headers, session cookies,
    Set-Cookie responses, and JWTs.
    """
    return _json(db.extract_session_tokens(limit=limit))


@mcp.tool()
def detect_session_issues(limit: int = 500) -> str:
    """Detect session security issues: cross-host cookie reuse, missing CSRF
    tokens on form submissions, and insecure cookie flags (missing
    Secure/HttpOnly/SameSite).
    """
    return _json(db.detect_session_issues(limit=limit))


@mcp.tool()
def detect_c2_patterns(limit: int = 1000) -> str:
    """Detect potential command-and-control (C2) beaconing patterns.

    Identifies hosts with regular-interval requests (low coefficient of
    variation) and suspiciously long encoded query parameters.
    """
    return _json(db.detect_c2_patterns(limit=limit))


# ---------------------------------------------------------------------------
# Privacy & Compliance Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def audit_third_parties(limit: int = 100) -> str:
    """List all external domains contacted, with traffic stats and automatic
    categorization (advertising/tracking, social media, CDN, other).
    """
    return _json(db.audit_third_parties(limit=limit))


@mcp.tool()
def analyze_cookies(limit: int = 300) -> str:
    """Parse and categorize all cookies from Set-Cookie headers.

    Reports category (session, tracking, CSRF, preference), security flags
    (Secure, HttpOnly, SameSite), and frequency.
    """
    return _json(db.analyze_cookies_in_traffic(limit=limit))


# ---------------------------------------------------------------------------
# Debugging & Development Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def compare_requests(id1: int, id2: int) -> str:
    """Compare two captured requests side-by-side.

    Highlights differences in method, URL, headers, body, status code, and timing.
    Useful for diagnosing why one request succeeds and another fails.
    """
    return _json(db.compare_requests(id1, id2))


@mcp.tool()
def generate_openapi_spec(host: str | None = None) -> str:
    """Generate an OpenAPI 3.0 specification from observed traffic.

    Automatically normalizes path parameters (IDs, UUIDs) and groups
    endpoints. Filter by host to generate a spec for a specific API.
    """
    return _json(db.generate_openapi_spec(host=host))


@mcp.tool()
def analyze_performance(limit: int = 100) -> str:
    """Analyze performance bottlenecks in captured traffic.

    Reports: slowest endpoints (with P95 latency), largest payloads,
    redundant/repeated requests, and error-prone endpoints.
    """
    return _json(db.analyze_performance(limit=limit))


@mcp.tool()
def generate_curl(request_id: int) -> str:
    """Generate a curl command that reproduces a captured request.

    Includes method, URL, headers, and body. Ready to paste into a terminal.
    """
    cmd = db.generate_curl_command(request_id)
    if not cmd:
        return _json({"error": "Request not found"})
    return _json({"request_id": request_id, "curl": cmd})


# ---------------------------------------------------------------------------
# Monitoring & Analysis Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def detect_anomalies(limit: int = 1000) -> str:
    """Detect traffic anomalies: status code distribution, timing outliers
    (beyond 3 standard deviations), rare one-off hosts, and error bursts
    (5+ errors in a single minute).
    """
    return _json(db.detect_anomalies(limit=limit))


@mcp.tool()
def summarize_activity(hours: int = 24) -> str:
    """High-level activity dashboard for a time window.

    Shows: total requests, unique hosts, bandwidth, top hosts/paths,
    and hourly breakdown.
    """
    return _json(db.summarize_activity(hours=hours))


@mcp.tool()
def bandwidth_analysis(limit: int = 50) -> str:
    """Identify top bandwidth consumers by host and content type.

    Lists the largest individual responses and overall byte totals.
    """
    return _json(db.bandwidth_analysis(limit=limit))


# ---------------------------------------------------------------------------
# Active Traffic Manipulation Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def replay_request(
    request_id: int,
    modify_headers: str | None = None,
    modify_body: str | None = None,
    modify_method: str | None = None,
    modify_url: str | None = None,
) -> str:
    """Replay a captured request with optional modifications.

    modify_headers: JSON object of headers to add/override, e.g. '{"X-Test": "1"}'
    modify_body: replacement request body
    modify_method: override HTTP method
    modify_url: override target URL

    Returns the live response (status, headers, body).
    """
    import urllib.request
    import urllib.error

    req = db.get_request_by_id(request_id)
    if not req:
        return _json({"error": "Request not found"})

    url = modify_url or req["url"]
    method = modify_method or req["method"]

    headers = req.get("request_headers") or {}
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in headers.items() if k.lower() not in skip}
    if modify_headers:
        try:
            headers.update(json.loads(modify_headers))
        except json.JSONDecodeError:
            return _json({"error": "modify_headers must be valid JSON"})

    body = modify_body or req.get("request_body")
    body_bytes = body.encode("utf-8") if body and not body.startswith("<") else None

    try:
        http_req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        with urllib.request.urlopen(http_req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return _json({
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp_body[:100000],
                "original_request_id": request_id,
            })
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return _json({
            "status": e.code,
            "headers": dict(e.headers),
            "body": err_body[:100000],
            "error": str(e.reason),
            "original_request_id": request_id,
        })
    except Exception as e:
        return _json({"error": str(e), "original_request_id": request_id})


@mcp.tool()
def create_traffic_rule(
    rule_type: str,
    action: str,
    match_host: str | None = None,
    match_path: str | None = None,
    match_url: str | None = None,
    description: str | None = None,
) -> str:
    """Create a traffic manipulation rule. The proxy applies it in real time.

    rule_type (one of):
      inject_request_header  — action: {"header": "X-Custom", "value": "test"}
      inject_response_header — action: {"header": "X-Frame-Options", "value": "DENY"}
      throttle               — action: {"delay_ms": 2000}
      block_pattern          — action: {"status": 403, "body": "Blocked"}
      modify_response_body   — action: {"find": "old", "replace": "new"}

    match_host/match_path/match_url: glob patterns (* = wildcard) to filter which requests the rule applies to.
    """
    try:
        action_dict = json.loads(action) if isinstance(action, str) else action
    except json.JSONDecodeError:
        return _json({"error": "action must be valid JSON"})
    rule_id = db.add_traffic_rule(
        rule_type=rule_type, action=action_dict,
        match_host=match_host, match_path=match_path,
        match_url=match_url, description=description,
    )
    return _json({"status": "created", "rule_id": rule_id})


@mcp.tool()
def list_traffic_rules(include_disabled: bool = False) -> str:
    """List all active traffic manipulation rules."""
    rules = db.get_traffic_rules(enabled_only=not include_disabled)
    return _json({"count": len(rules), "rules": rules})


@mcp.tool()
def remove_traffic_rule(rule_id: int) -> str:
    """Remove a traffic manipulation rule by ID."""
    removed = db.remove_traffic_rule(rule_id)
    return _json({"status": "removed" if removed else "not_found", "rule_id": rule_id})


@mcp.tool()
def toggle_traffic_rule(rule_id: int, enabled: bool) -> str:
    """Enable or disable a traffic rule without deleting it."""
    toggled = db.toggle_traffic_rule(rule_id, enabled)
    return _json({"status": "updated" if toggled else "not_found",
                  "rule_id": rule_id, "enabled": enabled})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
