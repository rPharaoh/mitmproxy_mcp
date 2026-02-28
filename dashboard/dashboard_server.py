"""
LLMProxy Dashboard – REST API + static file server.

Provides a web UI for visualizing captured traffic, security findings,
performance analysis, and managing proxy rules.

Run with:
    python dashboard_server.py                  # default port 8002
    python dashboard_server.py --port 9000      # custom port

Environment variables:
    LLMPROXY_ES_URL         Elasticsearch URL (default: http://elasticsearch:9200)
    LLMPROXY_ADMIN_TOKEN    Admin token (optional, for admin-level access)
    LLMPROXY_AUTH_REQUIRED  Set to "1" to require Bearer token auth
"""

from __future__ import annotations

import json
import sys
import asyncio
import traceback
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, FileResponse, StreamingResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

import storage.db as db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).parent / "static"


def _json_response(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status)


def _error(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


def _int(val: str | None, default: int) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _tenant(request: Request) -> str | None:
    """Resolve tenant_id for the current request.

    Admin users: use tenant_id from query param (or None for all).
    Regular users: always use their own tenant_id from auth.
    No auth: use query param as before.
    """
    auth_tenant = getattr(request.state, "tenant_id", None)
    is_admin = getattr(request.state, "is_admin", False)

    if is_admin:
        # Admin can specify a tenant_id, or see all
        return request.query_params.get("tenant_id") or None
    if auth_tenant:
        # Regular user always scoped to their own tenant
        return auth_tenant
    # No auth
    return request.query_params.get("tenant_id")


# ---------------------------------------------------------------------------
# Route handlers – Overview
# ---------------------------------------------------------------------------

async def index(request: Request) -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


async def api_stats(request: Request) -> JSONResponse:
    """GET /api/stats – overall traffic statistics."""
    try:
        data = db.get_traffic_stats(tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_summary(request: Request) -> JSONResponse:
    """GET /api/summary?hours=24 – activity summary."""
    try:
        hours = _int(request.query_params.get("hours"), 24)
        data = db.summarize_activity(hours=hours, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Requests
# ---------------------------------------------------------------------------

async def api_requests(request: Request) -> JSONResponse:
    """GET /api/requests – recent requests with optional filters and pagination."""
    try:
        data = db.get_recent_requests(
            limit=_int(request.query_params.get("limit"), 50),
            offset=_int(request.query_params.get("offset"), 0),
            method=request.query_params.get("method"),
            host=request.query_params.get("host"),
            status_code=_int(request.query_params.get("status_code"), None) if request.query_params.get("status_code") else None,
            status_class=request.query_params.get("status_class") or None,
            search=request.query_params.get("search"),
            mime_type=request.query_params.get("mime_type") or None,
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_request_detail(request: Request) -> JSONResponse:
    """GET /api/requests/{id} – single request detail."""
    try:
        req_id = request.path_params["id"]
        data = db.get_request_by_id(req_id, tenant_id=_tenant(request))
        if data is None:
            return _error("Request not found", 404)
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_search(request: Request) -> JSONResponse:
    """GET /api/search?q=...&field=url&limit=50."""
    try:
        q = request.query_params.get("q", "")
        field = request.query_params.get("field", "url")
        limit = _int(request.query_params.get("limit"), 50)
        data = db.search_requests(q, field=field, limit=limit, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_errors(request: Request) -> JSONResponse:
    """GET /api/errors – requests with status >= 400."""
    try:
        limit = _int(request.query_params.get("limit"), 50)
        data = db.find_errors(limit=limit, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_curl(request: Request) -> JSONResponse:
    """GET /api/curl/{id} – generate curl command."""
    try:
        req_id = request.path_params["id"]
        cmd = db.generate_curl_command(req_id, tenant_id=_tenant(request))
        return _json_response({"curl": cmd})
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Domains
# ---------------------------------------------------------------------------

async def api_domains(request: Request) -> JSONResponse:
    """GET /api/domains – domain summary."""
    try:
        limit = _int(request.query_params.get("limit"), 30)
        data = db.get_domain_summary(limit=limit, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Live feed
# ---------------------------------------------------------------------------

async def api_live(request: Request) -> JSONResponse:
    """GET /api/live – poll-based live feed with filters."""
    try:
        data = db.get_live_feed(
            after_id=request.query_params.get("after_id"),
            after_ws_id=request.query_params.get("after_ws_id"),
            limit=_int(request.query_params.get("limit"), 100),
            tenant_id=_tenant(request),
            host=request.query_params.get("host") or None,
            search=request.query_params.get("search") or None,
            method=request.query_params.get("method") or None,
            status_class=request.query_params.get("status_class") or None,
            mime_type=request.query_params.get("mime_type") or None,
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_live_stream(request: Request) -> StreamingResponse:
    """GET /api/live/stream – Server-Sent Events for real-time feed with filters."""
    tenant_id = _tenant(request)
    host = request.query_params.get("host") or None
    search = request.query_params.get("search") or None
    method = request.query_params.get("method") or None
    status_class = request.query_params.get("status_class") or None
    mime_type = request.query_params.get("mime_type") or None

    async def event_generator():
        cursor_http = None
        cursor_ws = None
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break
                try:
                    data = db.get_live_feed(
                        after_id=cursor_http,
                        after_ws_id=cursor_ws,
                        limit=50,
                        tenant_id=tenant_id,
                        host=host,
                        search=search,
                        method=method,
                        status_class=status_class,
                        mime_type=mime_type,
                    )
                    if data.get("http", {}).get("cursor"):
                        cursor_http = data["http"]["cursor"]
                    if data.get("ws", {}).get("cursor"):
                        cursor_ws = data["ws"]["cursor"]

                    http_reqs = data.get("http", {}).get("requests", [])
                    ws_msgs = data.get("ws", {}).get("messages", [])

                    if http_reqs or ws_msgs:
                        payload = json.dumps(
                            {"http": http_reqs, "ws": ws_msgs},
                            default=str,
                        )
                        yield f"data: {payload}\n\n"
                    else:
                        # Send keepalive comment to detect disconnects
                        yield ": keepalive\n\n"

                except Exception:
                    yield f"event: error\ndata: {{\"error\": \"poll error\"}}\n\n"

                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Route handlers – Performance
# ---------------------------------------------------------------------------

async def api_performance(request: Request) -> JSONResponse:
    """GET /api/performance – performance analysis."""
    try:
        data = db.analyze_performance(
            limit=_int(request.query_params.get("limit"), 100),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_anomalies(request: Request) -> JSONResponse:
    """GET /api/anomalies – anomaly detection."""
    try:
        data = db.detect_anomalies(
            limit=_int(request.query_params.get("limit"), 1000),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_bandwidth(request: Request) -> JSONResponse:
    """GET /api/bandwidth – bandwidth analysis."""
    try:
        data = db.bandwidth_analysis(
            limit=_int(request.query_params.get("limit"), 50),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Security
# ---------------------------------------------------------------------------

async def api_vulnerabilities(request: Request) -> JSONResponse:
    """GET /api/security/vulnerabilities."""
    try:
        data = db.scan_vulnerabilities(
            limit=_int(request.query_params.get("limit"), 500),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_pii(request: Request) -> JSONResponse:
    """GET /api/security/pii."""
    try:
        data = db.detect_pii(
            limit=_int(request.query_params.get("limit"), 500),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_sessions(request: Request) -> JSONResponse:
    """GET /api/security/sessions."""
    try:
        data = db.extract_session_tokens(
            limit=_int(request.query_params.get("limit"), 300),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_session_issues(request: Request) -> JSONResponse:
    """GET /api/security/session-issues."""
    try:
        data = db.detect_session_issues(
            limit=_int(request.query_params.get("limit"), 500),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_c2(request: Request) -> JSONResponse:
    """GET /api/security/c2."""
    try:
        data = db.detect_c2_patterns(
            limit=_int(request.query_params.get("limit"), 1000),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Privacy
# ---------------------------------------------------------------------------

async def api_third_parties(request: Request) -> JSONResponse:
    """GET /api/privacy/third-parties."""
    try:
        data = db.audit_third_parties(
            limit=_int(request.query_params.get("limit"), 100),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_cookies(request: Request) -> JSONResponse:
    """GET /api/privacy/cookies."""
    try:
        data = db.analyze_cookies_in_traffic(
            limit=_int(request.query_params.get("limit"), 300),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – WebSocket
# ---------------------------------------------------------------------------

async def api_ws_connections(request: Request) -> JSONResponse:
    """GET /api/websocket/connections."""
    try:
        data = db.get_ws_connections(
            limit=_int(request.query_params.get("limit"), 50),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_ws_messages(request: Request) -> JSONResponse:
    """GET /api/websocket/messages."""
    try:
        data = db.get_ws_messages(
            flow_id=request.query_params.get("flow_id"),
            host=request.query_params.get("host"),
            direction=request.query_params.get("direction"),
            search=request.query_params.get("search"),
            limit=_int(request.query_params.get("limit"), 100),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_ws_stats(request: Request) -> JSONResponse:
    """GET /api/websocket/stats."""
    try:
        data = db.get_ws_stats(tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – API Mapping
# ---------------------------------------------------------------------------

async def api_map(request: Request) -> JSONResponse:
    """GET /api/map – discovered API endpoints."""
    try:
        data = db.get_api_map(
            host=request.query_params.get("host"),
            limit=_int(request.query_params.get("limit"), 100),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_openapi(request: Request) -> JSONResponse:
    """GET /api/openapi?host=... – generate OpenAPI spec."""
    try:
        data = db.generate_openapi_spec(
            host=request.query_params.get("host"),
            tenant_id=_tenant(request),
        )
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Rules & Blocked Domains
# ---------------------------------------------------------------------------

async def api_blocked(request: Request) -> JSONResponse:
    """GET /api/blocked – list blocked domains."""
    try:
        data = db.get_all_blocked_domains(tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_block_domain(request: Request) -> JSONResponse:
    """POST /api/blocked – block a domain. Body: {domain, reason?}"""
    try:
        body = await request.json()
        domain = body.get("domain", "").strip()
        if not domain:
            return _error("domain is required")
        reason = body.get("reason")
        ok = db.add_blocked_domain(domain, reason=reason, tenant_id=_tenant(request))
        return _json_response({"success": ok, "domain": domain})
    except Exception as e:
        return _error(str(e), 500)


async def api_unblock_domain(request: Request) -> JSONResponse:
    """DELETE /api/blocked/{domain}."""
    try:
        domain = request.path_params["domain"]
        ok = db.remove_blocked_domain(domain, tenant_id=_tenant(request))
        return _json_response({"success": ok, "domain": domain})
    except Exception as e:
        return _error(str(e), 500)


async def api_rules(request: Request) -> JSONResponse:
    """GET /api/rules – traffic rules."""
    try:
        data = db.get_traffic_rules(enabled_only=False, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


async def api_compare(request: Request) -> JSONResponse:
    """GET /api/compare?id1=...&id2=... – compare two requests."""
    try:
        id1 = request.query_params.get("id1", "")
        id2 = request.query_params.get("id2", "")
        if not id1 or not id2:
            return _error("id1 and id2 are required")
        data = db.compare_requests(id1, id2, tenant_id=_tenant(request))
        return _json_response(data)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Tokens (admin-only)
# ---------------------------------------------------------------------------

async def api_list_tokens(request: Request) -> JSONResponse:
    """GET /api/tokens – list all tokens (admin only)."""
    if db.AUTH_REQUIRED and not getattr(request.state, "is_admin", False):
        return _error("Admin access required", 403)
    try:
        tokens = db.list_tokens()
        return _json_response(tokens)
    except Exception as e:
        return _error(str(e), 500)


async def api_create_token(request: Request) -> JSONResponse:
    """POST /api/tokens – create a new token (admin only).

    Body: {"name": "My App"}
    """
    if db.AUTH_REQUIRED and not getattr(request.state, "is_admin", False):
        return _error("Admin access required", 403)
    try:
        body = await request.json()
        name = (body.get("name") or "").strip()
        if not name:
            return _error("Name is required", 400)
        result = db.create_token(name)
        return _json_response(result)
    except Exception as e:
        return _error(str(e), 500)


async def api_revoke_token(request: Request) -> JSONResponse:
    """POST /api/tokens/revoke – revoke a token (admin only).

    Body: {"id": "es-document-id"}
    """
    if db.AUTH_REQUIRED and not getattr(request.state, "is_admin", False):
        return _error("Admin access required", 403)
    try:
        body = await request.json()
        doc_id = (body.get("id") or "").strip()
        if not doc_id:
            return _error("Token id is required", 400)
        ok = db.revoke_token_by_id(doc_id)
        if ok:
            return _json_response({"revoked": True})
        return _error("Token not found", 404)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Tenants
# ---------------------------------------------------------------------------

async def api_tenants(request: Request) -> JSONResponse:
    """GET /api/tenants – list all tenants (admin only)."""
    if db.AUTH_REQUIRED and not getattr(request.state, "is_admin", False):
        return _error("Admin access required", 403)
    try:
        tokens = db.list_tokens()
        seen = set()
        tenants = []
        for t in tokens:
            tid = t.get("tenant_id")
            if tid and tid not in seen:
                seen.add(tid)
                tenants.append({
                    "tenant_id": tid,
                    "name": t.get("name", tid),
                    "active": t.get("active", True),
                })
        return _json_response(tenants)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Route handlers – Clear Data
# ---------------------------------------------------------------------------

async def api_clear_data(request: Request) -> JSONResponse:
    """POST /api/clear – clear captured data (admin only).

    Body: {"tenant_id": "..."} to clear a specific tenant,
          {"all": true} to clear everything.
    """
    if db.AUTH_REQUIRED and not getattr(request.state, "is_admin", False):
        return _error("Admin access required", 403)
    try:
        body = await request.json()
    except Exception:
        return _error("Invalid JSON body")

    if body.get("all"):
        # Clear all data by deleting from every tenant-scoped index
        results = {}
        for idx in (db.IDX_REQUESTS, db.IDX_WS, db.IDX_BLOCKED, db.IDX_TAGS, db.IDX_RULES):
            try:
                es = db._get_es()
                resp = es.delete_by_query(
                    index=idx,
                    body={"query": {"match_all": {}}},
                    refresh=True,
                    conflicts="proceed",
                )
                results[idx] = resp.get("deleted", 0)
            except Exception as exc:
                results[idx] = f"error: {exc}"
        return _json_response({"cleared": "all", "results": results})

    tenant_id = body.get("tenant_id")
    if not tenant_id:
        return _error("Provide tenant_id or set all=true")

    results = db.clear_tenant_data(tenant_id)
    return _json_response({"cleared": tenant_id, "results": results})


# ---------------------------------------------------------------------------
# Route handlers – Export
# ---------------------------------------------------------------------------

async def api_export_requests(request: Request) -> JSONResponse:
    """GET /api/export/requests?limit=1000&host=... – export requests as JSON array."""
    try:
        limit = _int(request.query_params.get("limit"), 1000)
        host = request.query_params.get("host") or None
        tenant_id = _tenant(request)
        db._flush_buffer()

        must = db._tenant_must(tenant_id)
        if host:
            must.append({"term": {"host": host}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        body = {"query": query, "sort": [{"timestamp": "desc"}]}

        if limit <= 0:
            # Export all using scroll
            es = db._get_es()
            resp = es.search(index=db.IDX_REQUESTS, body=body, size=5000, scroll="2m")
            rows = [db._hit_to_dict(h) for h in resp["hits"]["hits"]]
            scroll_id = resp.get("_scroll_id")
            while scroll_id:
                page = es.scroll(scroll_id=scroll_id, scroll="2m")
                hits = page["hits"]["hits"]
                if not hits:
                    break
                rows.extend(db._hit_to_dict(h) for h in hits)
                scroll_id = page.get("_scroll_id")
            if scroll_id:
                try:
                    es.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass
        else:
            rows = db._search(db.IDX_REQUESTS, body, size=min(limit, 10000))

        return _json_response(rows)
    except Exception as e:
        return _error(str(e), 500)


async def api_export_websocket(request: Request) -> JSONResponse:
    """GET /api/export/websocket?limit=1000&host=... – export websocket messages as JSON array."""
    try:
        limit = _int(request.query_params.get("limit"), 5000)
        host = request.query_params.get("host") or None
        tenant_id = _tenant(request)

        must = db._tenant_must(tenant_id)
        if host:
            must.append({"term": {"host": host}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        body = {"query": query, "sort": [{"timestamp": "desc"}]}

        if limit <= 0:
            es = db._get_es()
            resp = es.search(index=db.IDX_WS, body=body, size=5000, scroll="2m")
            rows = [db._hit_to_dict(h) for h in resp["hits"]["hits"]]
            scroll_id = resp.get("_scroll_id")
            while scroll_id:
                page = es.scroll(scroll_id=scroll_id, scroll="2m")
                hits = page["hits"]["hits"]
                if not hits:
                    break
                rows.extend(db._hit_to_dict(h) for h in hits)
                scroll_id = page.get("_scroll_id")
            if scroll_id:
                try:
                    es.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass
        else:
            rows = db._search(db.IDX_WS, body, size=min(limit, 10000))

        return _json_response(rows)
    except Exception as e:
        return _error(str(e), 500)


# ---------------------------------------------------------------------------
# Auth check endpoint
# ---------------------------------------------------------------------------

async def api_auth_check(request: Request) -> JSONResponse:
    """GET /api/auth/check – returns auth requirements."""
    return _json_response({"auth_required": db.AUTH_REQUIRED})


async def api_auth_me(request: Request) -> JSONResponse:
    """GET /api/auth/me – validate token and return identity."""
    if not db.AUTH_REQUIRED:
        return _json_response({"auth_required": False, "is_admin": True, "tenant_id": None})

    auth_header = request.headers.get("authorization", "")
    token = None
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()

    if not token:
        return _error("Token required", 401)

    if db.is_admin_token(token):
        return _json_response({"auth_required": True, "is_admin": True, "tenant_id": None, "name": "Admin"})

    info = db.validate_token_info(token)
    if not info:
        return _error("Invalid or revoked token", 401)

    return _json_response({"auth_required": True, "is_admin": False, "tenant_id": info["tenant_id"], "name": info.get("name", "User")})


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

class _DashboardAuthMiddleware:
    """ASGI middleware that validates Bearer tokens on /api/* requests.

    Skips auth for:
     - Static file / HTML requests (/, /static/*)
     - /api/auth/check (so UI can discover if auth is needed)
     - /api/auth/me   (validates the token itself)
    When AUTH_REQUIRED=0, sets is_admin=True for backward compat.
    """

    # Paths that never require auth
    _PUBLIC = {"/", "/api/auth/check", "/api/auth/me"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Public routes + static files
        if path in self._PUBLIC or path.startswith("/static"):
            # Provide defaults on scope state
            if "state" not in scope:
                scope["state"] = {}
            scope["state"]["is_admin"] = not db.AUTH_REQUIRED
            scope["state"]["tenant_id"] = None
            await self.app(scope, receive, send)
            return

        if not db.AUTH_REQUIRED:
            if "state" not in scope:
                scope["state"] = {}
            scope["state"]["is_admin"] = True
            scope["state"]["tenant_id"] = None
            await self.app(scope, receive, send)
            return

        # Extract Bearer token from header or query param (for SSE EventSource)
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode("utf-8", errors="replace")
        token = None
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        # Fallback: check ?token= query param (needed for EventSource/SSE)
        if not token:
            qs = scope.get("query_string", b"").decode("utf-8", errors="replace")
            from urllib.parse import parse_qs
            params = parse_qs(qs)
            if "token" in params:
                token = params["token"][0]

        if not token:
            from starlette.responses import JSONResponse as JR
            resp = JR({"error": "Authorization required"}, status_code=401)
            await resp(scope, receive, send)
            return

        if "state" not in scope:
            scope["state"] = {}

        if db.is_admin_token(token):
            scope["state"]["is_admin"] = True
            scope["state"]["tenant_id"] = None
            await self.app(scope, receive, send)
            return

        tenant_id = db.validate_token(token)
        if not tenant_id:
            from starlette.responses import JSONResponse as JR
            resp = JR({"error": "Invalid or revoked token"}, status_code=401)
            await resp(scope, receive, send)
            return

        scope["state"]["is_admin"] = False
        scope["state"]["tenant_id"] = tenant_id
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

routes = [
    Route("/", index),

    # Overview
    Route("/api/stats", api_stats),
    Route("/api/summary", api_summary),

    # Requests
    Route("/api/requests", api_requests),
    Route("/api/requests/{id:path}", api_request_detail),
    Route("/api/search", api_search),
    Route("/api/errors", api_errors),
    Route("/api/curl/{id:path}", api_curl),
    Route("/api/compare", api_compare),

    # Domains
    Route("/api/domains", api_domains),

    # Live feed
    Route("/api/live", api_live),
    Route("/api/live/stream", api_live_stream),

    # Performance
    Route("/api/performance", api_performance),
    Route("/api/anomalies", api_anomalies),
    Route("/api/bandwidth", api_bandwidth),

    # Security
    Route("/api/security/vulnerabilities", api_vulnerabilities),
    Route("/api/security/pii", api_pii),
    Route("/api/security/sessions", api_sessions),
    Route("/api/security/session-issues", api_session_issues),
    Route("/api/security/c2", api_c2),

    # Privacy
    Route("/api/privacy/third-parties", api_third_parties),
    Route("/api/privacy/cookies", api_cookies),

    # WebSocket
    Route("/api/websocket/connections", api_ws_connections),
    Route("/api/websocket/messages", api_ws_messages),
    Route("/api/websocket/stats", api_ws_stats),

    # API Mapping
    Route("/api/map", api_map),
    Route("/api/openapi", api_openapi),

    # Blocked domains
    Route("/api/blocked", api_blocked, methods=["GET"]),
    Route("/api/blocked", api_block_domain, methods=["POST"]),
    Route("/api/blocked/{domain:path}", api_unblock_domain, methods=["DELETE"]),

    # Rules
    Route("/api/rules", api_rules),

    # Tenants
    Route("/api/tenants", api_tenants),

    # Tokens
    Route("/api/tokens", api_list_tokens, methods=["GET"]),
    Route("/api/tokens", api_create_token, methods=["POST"]),
    Route("/api/tokens/revoke", api_revoke_token, methods=["POST"]),

    # Clear data
    Route("/api/clear", api_clear_data, methods=["POST"]),

    # Export
    Route("/api/export/requests", api_export_requests),
    Route("/api/export/websocket", api_export_websocket),

    # Auth
    Route("/api/auth/check", api_auth_check),
    Route("/api/auth/me", api_auth_me),

    # Static files
    Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

app = Starlette(
    routes=routes,
    middleware=[
        Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
    ],
)

# Wrap with auth middleware
app = _DashboardAuthMiddleware(app)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = 8002
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    print(f"[LLMProxy Dashboard] Starting on http://0.0.0.0:{port}")
    db.init_db()
    uvicorn.run(app, host="0.0.0.0", port=port)
