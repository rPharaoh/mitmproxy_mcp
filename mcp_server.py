"""
MCP server that exposes mitmproxy-captured web traffic as tools.

Run with:
    python mcp_server.py                          # stdio (default)
    python mcp_server.py --transport sse           # SSE on port 8000
    python mcp_server.py --transport sse --port 9000

Environment variables:
    LLMPROXY_ES_URL         Elasticsearch URL (default: http://elasticsearch:9200)
    LLMPROXY_ADMIN_TOKEN    Admin token for token management (required for admin tools)
    LLMPROXY_AUTH_REQUIRED  Set to "1" to require auth on SSE connections
"""

from __future__ import annotations

import contextvars
import json
from typing import Any

from mcp.server.fastmcp import FastMCP

import db
from tools import register_all

# ---------------------------------------------------------------------------
# Tenant context – set by auth middleware, read by tool functions
# ---------------------------------------------------------------------------

_current_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_tenant", default=None
)
_is_admin: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "is_admin", default=False
)

# ---------------------------------------------------------------------------

mcp = FastMCP("llmproxy")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


def _tid() -> str | None:
    """Get the current tenant_id from request context."""
    return _current_tenant.get(None)


# ---------------------------------------------------------------------------
# Register all tool modules
# ---------------------------------------------------------------------------

register_all(mcp, {
    "_json": _json,
    "_tid": _tid,
    "_is_admin": _is_admin,
    "_current_tenant": _current_tenant,
})


# ---------------------------------------------------------------------------
# Auth middleware for SSE transport
# ---------------------------------------------------------------------------

class _AuthMiddleware:
    """ASGI middleware that validates Bearer tokens on HTTP requests.

    Sets _current_tenant and _is_admin context vars for tool functions.
    Skips auth when LLMPROXY_AUTH_REQUIRED != '1' (backward compat).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not db.AUTH_REQUIRED:
            await self.app(scope, receive, send)
            return

        # Extract token from Authorization header or query string
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode("utf-8", errors="replace")
        token = None

        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        if not token:
            qs = scope.get("query_string", b"").decode("utf-8", errors="replace")
            for part in qs.split("&"):
                if part.startswith("token="):
                    token = part[6:]
                    break

        if not token:
            from starlette.responses import PlainTextResponse
            resp = PlainTextResponse("Authorization required. Use Bearer token.", status_code=401)
            await resp(scope, receive, send)
            return

        # Admin token
        if db.is_admin_token(token):
            _current_tenant.set(None)
            _is_admin.set(True)
            await self.app(scope, receive, send)
            return

        # User token
        tenant_id = db.validate_token(token)
        if not tenant_id:
            from starlette.responses import PlainTextResponse
            resp = PlainTextResponse("Invalid or revoked token.", status_code=401)
            await resp(scope, receive, send)
            return

        _current_tenant.set(tenant_id)
        _is_admin.set(False)
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    use_sse = "--transport" in sys.argv and "sse" in sys.argv
    use_streamable = "--transport" in sys.argv and "streamable-http" in sys.argv

    if (use_sse or use_streamable) and db.AUTH_REQUIRED:
        # SSE or Streamable HTTP with auth middleware — run via uvicorn
        import uvicorn

        if use_streamable:
            app = mcp.streamable_http_app()
        else:
            app = mcp.sse_app()
        authed_app = _AuthMiddleware(app)

        port = 8000
        if "--port" in sys.argv:
            idx = sys.argv.index("--port")
            if idx + 1 < len(sys.argv):
                port = int(sys.argv[idx + 1])

        uvicorn.run(authed_app, host="0.0.0.0", port=port)
    elif use_streamable:
        # Streamable HTTP without auth
        mcp.run(transport="streamable-http")
    elif use_sse:
        # SSE without auth — let FastMCP handle it
        mcp.run(transport="sse")
    else:
        mcp.run()
