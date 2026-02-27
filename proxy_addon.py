"""
mitmproxy addon that captures HTTP(S) traffic into the shared DuckDB store.

Usage:
    mitmproxy -s proxy_addon.py              # interactive console UI
    mitmdump  -s proxy_addon.py              # headless / scripting mode
    mitmweb   -s proxy_addon.py              # browser-based UI

Environment variables:
    LLMPROXY_DB           Path to the SQLite database (default: ./traffic.db)
    LLMPROXY_MAX_BODY     Max response body size to store in bytes (default: 512 KB)
    LLMPROXY_CAPTURE_BODY Set to "0" to skip storing bodies entirely
"""

from __future__ import annotations

import os
import time
import logging
from mitmproxy import http, websocket, ctx

import db

logger = logging.getLogger("llmproxy.addon")

MAX_BODY_SIZE = int(os.environ.get("LLMPROXY_MAX_BODY", 512 * 1024))
CAPTURE_BODY = os.environ.get("LLMPROXY_CAPTURE_BODY", "1") != "0"

# Content types worth storing as text (others are stored as <binary N bytes>)
TEXT_CONTENT_TYPES = {
    "text/", "application/json", "application/xml",
    "application/javascript", "application/x-www-form-urlencoded",
    "application/graphql", "application/soap+xml",
}


def _is_text(content_type: str | None) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    return any(ct.startswith(t) or t in ct for t in TEXT_CONTENT_TYPES)


def _safe_body(raw: bytes | None, content_type: str | None) -> str | None:
    """Return body text if it's a text type and below the size cap, else a placeholder."""
    if raw is None or not CAPTURE_BODY:
        return None
    if len(raw) > MAX_BODY_SIZE:
        return f"<truncated {len(raw)} bytes>"
    if _is_text(content_type):
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return f"<binary {len(raw)} bytes>"
    return f"<binary {len(raw)} bytes>"


class TrafficCapture:
    """Addon that writes every completed HTTP flow to DuckDB and enforces domain blocking."""

    def __init__(self):
        db.init_db()
        self._flow_start: dict[str, float] = {}
        ctx.log.info("[LLMProxy] Addon loaded – capturing traffic to " + db.DB_PATH)

    def done(self):
        """Flush buffered writes on proxy shutdown."""
        db.flush()
        ctx.log.info("[LLMProxy] Flushed write buffer on shutdown")

    # -- Request phase: check block list & record start time -----------------

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        self._flow_start[flow.id] = time.time()

        blocked, reason = db.is_domain_blocked(host)
        if blocked:
            flow.response = http.Response.make(
                403,
                f"Blocked by LLMProxy: {reason or 'no reason given'}".encode(),
                {"Content-Type": "text/plain"},
            )
            ctx.log.warn(f"[LLMProxy] Blocked {host}: {reason}")

    # -- Response phase: store the full exchange -----------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        start = self._flow_start.pop(flow.id, None)
        duration_ms = (time.time() - start) * 1000 if start else None

        req = flow.request
        resp = flow.response

        content_type = resp.headers.get("content-type", "") if resp else None
        resp_body_raw = resp.get_content(strict=False) if resp else None

        try:
            row_id = db.insert_request(
                method=req.method,
                url=req.pretty_url,
                host=req.pretty_host,
                path=req.path,
                port=req.port,
                scheme=req.scheme,
                request_headers=dict(req.headers),
                request_body=_safe_body(
                    req.get_content(strict=False),
                    req.headers.get("content-type"),
                ),
                status_code=resp.status_code if resp else None,
                response_headers=dict(resp.headers) if resp else None,
                response_body=_safe_body(resp_body_raw, content_type),
                content_type=content_type,
                content_length=len(resp_body_raw) if resp_body_raw else None,
                duration_ms=duration_ms,
            )
            ctx.log.debug(
                f"[LLMProxy] #{row_id} {req.method} {req.pretty_url} → {resp.status_code if resp else '?'}"
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store request", exc_info=True)

    # -- Error phase: still capture flows that errored -----------------------

    def error(self, flow: http.HTTPFlow) -> None:
        self._flow_start.pop(flow.id, None)
        req = flow.request
        try:
            db.insert_request(
                method=req.method,
                url=req.pretty_url,
                host=req.pretty_host,
                path=req.path,
                port=req.port,
                scheme=req.scheme,
                request_headers=dict(req.headers),
                request_body=_safe_body(
                    req.get_content(strict=False),
                    req.headers.get("content-type"),
                ),
                status_code=None,
                response_headers=None,
                response_body=f"<error: {flow.error.msg}>" if flow.error else None,
                content_type=None,
                content_length=None,
                duration_ms=None,
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store errored request", exc_info=True)

    # -- WebSocket phase: capture individual messages ------------------------

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]

        raw = msg.content
        if msg.is_text:
            content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            msg_type = "text"
        else:
            content = f"<binary {len(raw)} bytes>" if raw else None
            msg_type = "binary"

        # Truncate large messages
        if content and len(content) > MAX_BODY_SIZE:
            content = content[:MAX_BODY_SIZE] + f"... <truncated, total {len(raw)} bytes>"

        try:
            db.insert_ws_message(
                flow_id=flow.id,
                host=flow.request.pretty_host,
                url=flow.request.pretty_url,
                direction="send" if msg.from_client else "receive",
                message_type=msg_type,
                content=content if CAPTURE_BODY else None,
                content_length=len(raw) if raw else 0,
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store WebSocket message", exc_info=True)


addons = [TrafficCapture()]
