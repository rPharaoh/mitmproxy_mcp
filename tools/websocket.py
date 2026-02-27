"""WebSocket tools."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def get_ws_connections(limit: int = 50) -> str:
        """List captured WebSocket connections with message counts, bytes transferred, and timestamps."""
        rows = db.get_ws_connections(limit=limit, tenant_id=_tid())
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
            tenant_id=_tid(),
        )
        return _json({"count": len(rows), "messages": rows})

    @mcp.tool()
    def get_ws_stats() -> str:
        """Overall WebSocket statistics: total messages, connections, bytes, send/receive breakdown."""
        return _json(db.get_ws_stats(tenant_id=_tid()))
