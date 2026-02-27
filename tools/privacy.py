"""Privacy and compliance tools."""

from __future__ import annotations

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def audit_third_parties(limit: int = 100) -> str:
        """List all external domains contacted, with traffic stats and automatic
        categorization (advertising/tracking, social media, CDN, other).
        """
        return _json(db.audit_third_parties(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def analyze_cookies(limit: int = 300) -> str:
        """Parse and categorize all cookies from Set-Cookie headers.

        Reports category (session, tracking, CSRF, preference), security flags
        (Secure, HttpOnly, SameSite), and frequency.
        """
        return _json(db.analyze_cookies_in_traffic(limit=limit, tenant_id=_tid()))
