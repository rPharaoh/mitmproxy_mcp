"""
mitmproxy addon that captures HTTP(S) traffic into the shared Elasticsearch store.

Usage:
    mitmproxy -s proxy_addon.py              # interactive console UI
    mitmdump  -s proxy_addon.py              # headless / scripting mode
    mitmweb   -s proxy_addon.py              # browser-based UI

Environment variables:
    LLMPROXY_ES_URL       Elasticsearch URL (default: http://elasticsearch:9200)
    LLMPROXY_MAX_BODY     Max response body size to store in bytes (default: 512 KB)
    LLMPROXY_CAPTURE_BODY Set to "0" to skip storing bodies entirely
    LLMPROXY_AUTH_REQUIRED Set to "1" to require proxy auth (token-based multi-tenant)

Proxy Authentication (multi-tenant):
    When LLMPROXY_AUTH_REQUIRED=1, users must configure proxy auth.
    Username = their API token, password = anything.
    Traffic is tagged with the tenant_id associated with the token.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
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
    """Addon that writes every completed HTTP flow to Elasticsearch and enforces domain blocking."""

    def __init__(self):
        db.init_db()
        self._flow_start: dict[str, float] = {}
        self._flow_tenant: dict[str, str | None] = {}   # flow_id → tenant_id
        self._conn_tenant: dict[str, str | None] = {}   # client_conn.id → tenant_id (from CONNECT)
        self._rules: list[dict] = []
        self._rules_loaded_at: float = 0
        self._RULES_RELOAD_SEC = 5.0
        self._auth_required = db.AUTH_REQUIRED
        ctx.log.info("[LLMProxy] Addon loaded – capturing traffic to " + db.ES_URL)
        if self._auth_required:
            ctx.log.info("[LLMProxy] Auth REQUIRED – proxy auth enforced")

    def done(self):
        """Flush buffered writes on proxy shutdown."""
        db.flush()
        ctx.log.info("[LLMProxy] Flushed write buffer on shutdown")

    def client_disconnected(self, client_data) -> None:
        """Clean up stashed tenant when a client disconnects."""
        self._conn_tenant.pop(getattr(client_data, "id", None), None)

    # -- Rule engine ---------------------------------------------------------

    def _load_rules(self) -> None:
        """Reload traffic rules from DB if stale."""
        now = time.time()
        if now - self._rules_loaded_at < self._RULES_RELOAD_SEC:
            return
        try:
            self._rules = db.get_traffic_rules(enabled_only=True)
            self._rules_loaded_at = now
        except Exception:
            pass  # keep cached rules

    @staticmethod
    def _rule_matches(rule: dict, host: str, path: str, url: str) -> bool:
        """Check whether a rule matches a given request."""
        for field, value in (("match_host", host), ("match_path", path), ("match_url", url)):
            pattern = rule.get(field)
            if pattern:
                regex = pattern.replace("*", ".*")
                if not re.search(regex, value, re.I):
                    return False
        return True

    # -- Proxy auth helpers --------------------------------------------------

    @staticmethod
    def _parse_proxy_auth(headers) -> str:
        """Extract token from Proxy-Authorization header. Returns token or ''."""
        auth_header = headers.get("proxy-authorization", "")
        if auth_header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8", errors="replace")
                return decoded.split(":", 1)[0]
            except Exception:
                return ""
        return ""

    def _validate_token(self, token: str) -> str | None:
        """Validate a token. Returns tenant_id, None for admin, or '_reject' for invalid."""
        if not token:
            return "_reject" if self._auth_required else None
        if db.is_admin_token(token):
            return None  # admin sees everything
        tenant_id = db.validate_token(token)
        return tenant_id if tenant_id else "_reject"

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Handle CONNECT requests (HTTPS tunnels).

        Chrome/Edge send Proxy-Authorization only on the CONNECT request,
        not on individual requests inside the tunnel. We validate the token
        here and stash the tenant_id on the client connection for later use
        in request().
        """
        token = self._parse_proxy_auth(flow.request.headers)
        result = self._validate_token(token)

        if result == "_reject":
            flow.response = http.Response.make(
                407,
                b"Proxy authentication required. Set proxy username to your API token.",
                {"Content-Type": "text/plain", "Proxy-Authenticate": "Basic realm=\"LLMProxy\""},
            )
            return

        # Stash tenant on connection so request() can use it for HTTPS flows
        conn_id = flow.client_conn.id
        self._conn_tenant[conn_id] = result

    def _extract_tenant(self, flow: http.HTTPFlow) -> str | None:
        """Extract tenant_id from Proxy-Authorization header or stashed CONNECT auth.

        For HTTP: reads Proxy-Authorization directly from the request.
        For HTTPS: uses tenant stashed during http_connect().
        Returns tenant_id if valid, None for admin or no-auth mode.
        Sends 407 and returns sentinel '_reject' if auth is required but invalid.
        """
        # Check for Proxy-Authorization on the request itself (plain HTTP)
        token = self._parse_proxy_auth(flow.request.headers)
        flow.request.headers.pop("proxy-authorization", None)

        if token:
            # Direct auth header present (HTTP requests)
            result = self._validate_token(token)
            if result == "_reject":
                flow.response = http.Response.make(
                    407,
                    b"Invalid proxy token. Check your API token.",
                    {"Content-Type": "text/plain", "Proxy-Authenticate": "Basic realm=\"LLMProxy\""},
                )
            return result

        # No auth header — check if we have a stashed tenant from CONNECT
        conn_id = flow.client_conn.id
        if conn_id in self._conn_tenant:
            return self._conn_tenant[conn_id]

        # No auth at all
        if self._auth_required:
            # Allow mitm.it through without auth so users can install the CA cert
            if flow.request.pretty_host == "mitm.it":
                return None
            flow.response = http.Response.make(
                407,
                b"Proxy authentication required. Set proxy username to your API token.",
                {"Content-Type": "text/plain", "Proxy-Authenticate": "Basic realm=\"LLMProxy\""},
            )
            return "_reject"
        return None

    # -- Request phase: check block list & record start time -----------------

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        self._flow_start[flow.id] = time.time()

        # Authenticate and resolve tenant
        tenant_id = self._extract_tenant(flow)
        if tenant_id == "_reject":
            self._flow_start.pop(flow.id, None)
            return  # 407 already sent
        self._flow_tenant[flow.id] = tenant_id

        blocked, reason = db.is_domain_blocked(host, tenant_id=tenant_id)
        if blocked:
            flow.response = http.Response.make(
                403,
                f"Blocked by LLMProxy: {reason or 'no reason given'}".encode(),
                {"Content-Type": "text/plain"},
            )
            ctx.log.warn(f"[LLMProxy] Blocked {host}: {reason}")
            return

        # Apply request-phase traffic rules (only rules matching this tenant)
        self._load_rules()
        for rule in self._rules:
            rule_tenant = rule.get("tenant_id")
            if rule_tenant and rule_tenant != tenant_id:
                continue  # skip rules from other tenants
            if not self._rule_matches(rule, host, flow.request.path, flow.request.pretty_url):
                continue
            action = rule.get("action") or {}
            rtype = rule.get("rule_type")
            if rtype == "inject_request_header":
                flow.request.headers[action.get("header", "")] = action.get("value", "")
            elif rtype == "block_pattern":
                flow.response = http.Response.make(
                    action.get("status", 403),
                    (action.get("body", "Blocked by rule")).encode(),
                    {"Content-Type": "text/plain"},
                )
                return
            elif rtype == "throttle":
                delay = action.get("delay_ms", 0) / 1000.0
                if delay > 0:
                    time.sleep(delay)

    # -- Response phase: store the full exchange -----------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        start = self._flow_start.pop(flow.id, None)
        # Keep tenant_id in dict for WebSocket flows (websocket_message needs it)
        if flow.websocket:
            tenant_id = self._flow_tenant.get(flow.id)
        else:
            tenant_id = self._flow_tenant.pop(flow.id, None)
        duration_ms = (time.time() - start) * 1000 if start else None

        req = flow.request
        resp = flow.response

        # Apply response-phase traffic rules before storing
        self._load_rules()
        for rule in self._rules:
            rule_tenant = rule.get("tenant_id")
            if rule_tenant and rule_tenant != tenant_id:
                continue
            if not self._rule_matches(rule, req.pretty_host, req.path, req.pretty_url):
                continue
            action = rule.get("action") or {}
            rtype = rule.get("rule_type")
            if rtype == "inject_response_header" and resp:
                resp.headers[action.get("header", "")] = action.get("value", "")
            elif rtype == "modify_response_body" and resp:
                try:
                    body = resp.get_text(strict=False)
                    if body and action.get("find"):
                        body = body.replace(action["find"], action.get("replace", ""))
                        resp.set_text(body)
                except Exception:
                    pass  # skip if body is not decodable

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
                tenant_id=tenant_id,
            )
            ctx.log.debug(
                f"[LLMProxy] #{row_id} {req.method} {req.pretty_url} → {resp.status_code if resp else '?'}"
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store request", exc_info=True)

    # -- Error phase: still capture flows that errored -----------------------

    def error(self, flow: http.HTTPFlow) -> None:
        self._flow_start.pop(flow.id, None)
        tenant_id = self._flow_tenant.pop(flow.id, None)
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
                tenant_id=tenant_id,
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store errored request", exc_info=True)

    # -- WebSocket phase: capture individual messages ------------------------

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        """Clean up tenant mapping when a WebSocket connection closes."""
        self._flow_tenant.pop(flow.id, None)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        tenant_id = self._flow_tenant.get(flow.id)
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
                tenant_id=tenant_id,
            )
        except Exception:
            ctx.log.error("[LLMProxy] Failed to store WebSocket message", exc_info=True)


addons = [TrafficCapture()]
