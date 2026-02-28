"""Debugging and development tools: compare, curl, performance, replay."""

from __future__ import annotations

import json

import storage.db as db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def compare_requests(id1: int, id2: int) -> str:
        """Compare two captured requests side-by-side.

        Highlights differences in method, URL, headers, body, status code, and timing.
        Useful for diagnosing why one request succeeds and another fails.
        """
        return _json(db.compare_requests(id1, id2, tenant_id=_tid()))

    @mcp.tool()
    def generate_curl(request_id: int) -> str:
        """Generate a curl command that reproduces a captured request.

        Includes method, URL, headers, and body. Ready to paste into a terminal.
        """
        cmd = db.generate_curl_command(request_id, tenant_id=_tid())
        if not cmd:
            return _json({"error": "Request not found"})
        return _json({"request_id": request_id, "curl": cmd})

    @mcp.tool()
    def analyze_performance(limit: int = 100) -> str:
        """Analyze performance bottlenecks in captured traffic.

        Reports: slowest endpoints (with P95 latency), largest payloads,
        redundant/repeated requests, and error-prone endpoints.
        """
        return _json(db.analyze_performance(limit=limit, tenant_id=_tid()))

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

        req = db.get_request_by_id(request_id, tenant_id=_tid())
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
