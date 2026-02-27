"""Traffic browsing, search, and live feed tools."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

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
            tenant_id=_tid(),
        )
        return _json({"count": len(rows), "requests": rows})

    @mcp.tool()
    def get_request_detail(request_id: int) -> str:
        """Get full details of a single captured request by ID, including headers, body, and timing."""
        req = db.get_request_by_id(request_id, tenant_id=_tid())
        if req is None:
            return _json({"error": "Request not found"})
        req["tags"] = db.get_tags_for_request(request_id, tenant_id=_tid())
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
        rows = db.search_requests(pattern=pattern, field=field, limit=limit, tenant_id=_tid())
        return _json({"count": len(rows), "requests": rows})

    @mcp.tool()
    def get_domain_summary(limit: int = 30) -> str:
        """Aggregate traffic statistics grouped by domain/host.

        Shows request count, methods used, average duration, total bytes, first/last seen.
        """
        rows = db.get_domain_summary(limit=limit, tenant_id=_tid())
        return _json({"count": len(rows), "domains": rows})

    @mcp.tool()
    def get_traffic_stats() -> str:
        """Return overall traffic statistics: total requests, unique hosts, avg duration, total bytes, error count."""
        return _json(db.get_traffic_stats(tenant_id=_tid()))

    @mcp.tool()
    def find_errors(limit: int = 50) -> str:
        """Find requests that returned HTTP error status codes (4xx and 5xx)."""
        rows = db.find_errors(limit=limit, tenant_id=_tid())
        return _json({"count": len(rows), "errors": rows})

    @mcp.tool()
    def get_live_feed(
        after_id: int | None = None,
        after_ws_id: int | None = None,
        limit: int = 100,
    ) -> str:
        """Poll-based live stream of HTTP requests and WebSocket messages.

        Returns new traffic since the given cursors.  On the first call, omit
        after_id and after_ws_id to get the latest traffic.  Each response
        includes updated cursor values — pass them back on the next call to
        receive only new items.

        Always includes full request/response headers and bodies.
        """
        feed = db.get_live_feed(
            after_id=after_id,
            after_ws_id=after_ws_id,
            limit=limit,
            tenant_id=_tid(),
        )
        return _json(feed)
