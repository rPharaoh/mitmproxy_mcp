"""Admin tools: token management (admin-only)."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _is_admin = helpers["_is_admin"]

    @mcp.tool()
    def create_token(name: str) -> str:
        """Create a new API token for a tenant (admin only).

        Returns the token and tenant_id. The token is used as:
         - Proxy auth username (for the mitmproxy)
         - Bearer token (for the MCP SSE endpoint)

        The raw token is shown only once; store it securely.
        """
        if not _is_admin.get(False) and db.AUTH_REQUIRED:
            return _json({"error": "Admin token required for this operation"})
        result = db.create_token(name)
        return _json({"status": "created", **result})

    @mcp.tool()
    def list_tokens() -> str:
        """List all API tokens with metadata (admin only). Token values are masked."""
        if not _is_admin.get(False) and db.AUTH_REQUIRED:
            return _json({"error": "Admin token required for this operation"})
        tokens = db.list_tokens()
        return _json({"count": len(tokens), "tokens": tokens})

    @mcp.tool()
    def revoke_token(token: str) -> str:
        """Revoke an API token (admin only). Traffic already captured remains."""
        if not _is_admin.get(False) and db.AUTH_REQUIRED:
            return _json({"error": "Admin token required for this operation"})
        revoked = db.revoke_token(token)
        return _json({"status": "revoked" if revoked else "not_found"})

    @mcp.tool()
    def clear_tenant_data(tenant_id: str) -> str:
        """Delete all captured data for a tenant (admin only).

        Removes requests, websocket messages, blocked domains, tags, and
        traffic rules.  Token records are preserved — revoke separately
        if needed.

        tenant_id: the tenant identifier whose data should be wiped.
        """
        if not _is_admin.get(False) and db.AUTH_REQUIRED:
            return _json({"error": "Admin token required for this operation"})
        counts = db.clear_tenant_data(tenant_id)
        return _json({"status": "cleared", "tenant_id": tenant_id, "deleted": counts})
