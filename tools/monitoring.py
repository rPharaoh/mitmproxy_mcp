"""Monitoring and analysis tools."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def detect_anomalies(limit: int = 1000) -> str:
        """Detect traffic anomalies: status code distribution, timing outliers
        (beyond 3 standard deviations), rare one-off hosts, and error bursts
        (5+ errors in a single minute).
        """
        return _json(db.detect_anomalies(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def summarize_activity(hours: int = 24) -> str:
        """High-level activity dashboard for a time window.

        Shows: total requests, unique hosts, bandwidth, top hosts/paths,
        and hourly breakdown.
        """
        return _json(db.summarize_activity(hours=hours, tenant_id=_tid()))

    @mcp.tool()
    def bandwidth_analysis(limit: int = 50) -> str:
        """Identify top bandwidth consumers by host and content type.

        Lists the largest individual responses and overall byte totals.
        """
        return _json(db.bandwidth_analysis(limit=limit, tenant_id=_tid()))
