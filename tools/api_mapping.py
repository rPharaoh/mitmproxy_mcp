"""API mapping and OpenAPI spec generation tools."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def map_api(host: str | None = None, limit: int = 100) -> str:
        """Discover and map API endpoints from captured traffic.

        Automatically normalizes paths (replaces numeric IDs and UUIDs with
        placeholders) to group similar endpoints. Shows methods, status codes,
        hit count, and average duration per endpoint.
        """
        endpoints = db.get_api_map(host=host, limit=limit, tenant_id=_tid())
        return _json({"count": len(endpoints), "endpoints": endpoints})

    @mcp.tool()
    def get_endpoint_detail(host: str, path: str, limit: int = 50) -> str:
        """Get recent requests for a specific API endpoint (host + path pattern).

        Use after map_api to drill into a particular endpoint.
        """
        rows = db.get_endpoint_detail(host=host, path=path, limit=limit, tenant_id=_tid())
        return _json({"count": len(rows), "requests": rows})

    @mcp.tool()
    def generate_openapi_spec(host: str | None = None) -> str:
        """Generate an OpenAPI 3.0 specification from observed traffic.

        Automatically normalizes path parameters (IDs, UUIDs) and groups
        endpoints. Filter by host to generate a spec for a specific API.
        """
        return _json(db.generate_openapi_spec(host=host, tenant_id=_tid()))
