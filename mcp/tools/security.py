"""Security analysis tools."""

from __future__ import annotations

import json

import storage.db as db

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS – enforces HTTPS",
    "content-security-policy": "CSP – mitigates XSS and injection",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "Prevents MIME-sniffing",
    "referrer-policy": "Controls Referer header leakage",
    "permissions-policy": "Controls browser feature access",
    "x-xss-protection": "Legacy XSS filter (deprecated but still checked)",
    "cross-origin-opener-policy": "COOP – isolates browsing context",
    "cross-origin-resource-policy": "CORP – restricts resource loading",
    "cross-origin-embedder-policy": "COEP – controls embedding",
}


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def analyze_security_headers(request_id: int) -> str:
        """Check a response's security headers (HSTS, CSP, X-Frame-Options, etc.) and report present/missing."""
        req = db.get_request_by_id(request_id, tenant_id=_tid())
        if req is None:
            return _json({"error": "Request not found"})

        resp_headers = req.get("response_headers") or {}
        if isinstance(resp_headers, str):
            resp_headers = json.loads(resp_headers)

        lower_headers = {k.lower(): v for k, v in resp_headers.items()}
        present = {}
        missing = []
        for header, desc in SECURITY_HEADERS.items():
            if header in lower_headers:
                present[header] = {"value": lower_headers[header], "description": desc}
            else:
                missing.append({"header": header, "description": desc})

        return _json({
            "url": req["url"],
            "present": present,
            "missing": missing,
            "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
        })

    @mcp.tool()
    def scan_vulnerabilities(limit: int = 500) -> str:
        """Scan captured traffic for security vulnerabilities.

        Detects: SQL injection error leaks, XSS payloads, path traversal,
        plaintext credentials over HTTP, exposed sensitive paths (.git, .env, etc.),
        server version disclosure, and stack trace leaks.
        """
        return _json(db.scan_vulnerabilities(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def detect_pii(limit: int = 500) -> str:
        """Scan request/response bodies for PII (Personally Identifiable Information).

        Detects: email addresses, credit card numbers, SSNs, phone numbers,
        JWTs, AWS access keys, and private keys.
        """
        return _json(db.detect_pii(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def extract_session_tokens(limit: int = 300) -> str:
        """Extract authentication tokens, session cookies, and API keys from
        captured traffic. Finds Authorization headers, session cookies,
        Set-Cookie responses, and JWTs.
        """
        return _json(db.extract_session_tokens(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def detect_session_issues(limit: int = 500) -> str:
        """Detect session security issues: cross-host cookie reuse, missing CSRF
        tokens on form submissions, and insecure cookie flags (missing
        Secure/HttpOnly/SameSite).
        """
        return _json(db.detect_session_issues(limit=limit, tenant_id=_tid()))

    @mcp.tool()
    def detect_c2_patterns(limit: int = 1000) -> str:
        """Detect potential command-and-control (C2) beaconing patterns.

        Identifies hosts with regular-interval requests (low coefficient of
        variation) and suspiciously long encoded query parameters.
        """
        return _json(db.detect_c2_patterns(limit=limit, tenant_id=_tid()))
