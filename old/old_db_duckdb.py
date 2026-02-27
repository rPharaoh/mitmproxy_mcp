"""
Shared database module for LLMProxy.
Uses DuckDB for high-throughput traffic capture with an in-memory write
buffer that batches inserts for maximum performance under heavy proxy load.

Both the mitmproxy addon and MCP server use this module.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import duckdb

DB_PATH = os.environ.get("LLMPROXY_DB", str(Path(__file__).parent / "traffic.duckdb"))

# Write buffer config (tunable via env vars)
_FLUSH_SIZE = int(os.environ.get("LLMPROXY_FLUSH_SIZE", 100))    # rows
_FLUSH_INTERVAL = float(os.environ.get("LLMPROXY_FLUSH_INTERVAL", 1.0))  # seconds

# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_conn: duckdb.DuckDBPyConnection | None = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    """Return a singleton DuckDB connection (thread-safe via lock)."""
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                _conn = duckdb.connect(DB_PATH)
                # DuckDB handles concurrency internally; set memory limit for safety
                _conn.execute("SET memory_limit = '512MB'")
                _conn.execute("SET threads = 4")
    return _conn


def _query(sql: str, params: list | tuple | None = None) -> list[dict]:
    """Execute a read query and return list of dicts."""
    conn = _get_conn()
    with _lock:
        if params:
            result = conn.execute(sql, params)
        else:
            result = conn.execute(sql)
        cols = [desc[0] for desc in result.description]
        rows = result.fetchall()
    return [dict(zip(cols, row)) for row in rows]


def _execute(sql: str, params: list | tuple | None = None) -> None:
    """Execute a write statement."""
    conn = _get_conn()
    with _lock:
        if params:
            conn.execute(sql, params)
        else:
            conn.execute(sql)


def init_db():
    """Create tables and sequences if they don't exist."""
    conn = _get_conn()
    with _lock:
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_requests START 1;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id              BIGINT DEFAULT nextval('seq_requests') PRIMARY KEY,
                timestamp       TIMESTAMP NOT NULL,
                method          VARCHAR NOT NULL,
                url             VARCHAR NOT NULL,
                host            VARCHAR NOT NULL,
                path            VARCHAR NOT NULL,
                port            INTEGER,
                scheme          VARCHAR,
                request_headers VARCHAR,
                request_body    VARCHAR,
                status_code     INTEGER,
                response_headers VARCHAR,
                response_body   VARCHAR,
                content_type    VARCHAR,
                content_length  BIGINT,
                duration_ms     DOUBLE
            );
        """)
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_blocked START 1;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id          BIGINT DEFAULT nextval('seq_blocked') PRIMARY KEY,
                domain      VARCHAR NOT NULL UNIQUE,
                reason      VARCHAR,
                created_at  TIMESTAMP NOT NULL
            );
        """)
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_tags START 1;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tags (
                id          BIGINT DEFAULT nextval('seq_tags') PRIMARY KEY,
                request_id  BIGINT NOT NULL,
                tag         VARCHAR NOT NULL,
                created_at  TIMESTAMP NOT NULL
            );
        """)
        # WebSocket messages
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_ws START 1;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS websocket_messages (
                id              BIGINT DEFAULT nextval('seq_ws') PRIMARY KEY,
                timestamp       TIMESTAMP NOT NULL,
                flow_id         VARCHAR NOT NULL,
                host            VARCHAR NOT NULL,
                url             VARCHAR NOT NULL,
                direction       VARCHAR NOT NULL,
                message_type    VARCHAR NOT NULL,
                content         VARCHAR,
                content_length  BIGINT
            );
        """)
        # Traffic manipulation rules
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_rules START 1;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic_rules (
                id          BIGINT DEFAULT nextval('seq_rules') PRIMARY KEY,
                rule_type   VARCHAR NOT NULL,
                match_host  VARCHAR,
                match_path  VARCHAR,
                match_url   VARCHAR,
                action      VARCHAR NOT NULL,
                description VARCHAR,
                enabled     BOOLEAN DEFAULT TRUE,
                created_at  TIMESTAMP NOT NULL
            );
        """)


# ---------------------------------------------------------------------------
# Write buffer – batches proxy inserts for throughput
# ---------------------------------------------------------------------------

_buffer: list[tuple] = []
_buffer_lock = threading.Lock()
_flush_timer: threading.Timer | None = None

_INSERT_COLS = (
    "timestamp", "method", "url", "host", "path", "port", "scheme",
    "request_headers", "request_body",
    "status_code", "response_headers", "response_body",
    "content_type", "content_length", "duration_ms",
)


def _flush_buffer() -> None:
    """Flush the in-memory buffer to DuckDB in a single batch insert."""
    global _flush_timer
    with _buffer_lock:
        if not _buffer:
            return
        batch = _buffer.copy()
        _buffer.clear()
        _flush_timer = None

    if not batch:
        return

    placeholders = ", ".join(["?"] * len(_INSERT_COLS))
    cols = ", ".join(_INSERT_COLS)
    conn = _get_conn()
    with _lock:
        conn.executemany(
            f"INSERT INTO requests ({cols}) VALUES ({placeholders})",
            batch,
        )


def _schedule_flush() -> None:
    """Schedule a timer-based flush if one isn't already pending."""
    global _flush_timer
    if _flush_timer is None:
        _flush_timer = threading.Timer(_FLUSH_INTERVAL, _flush_buffer)
        _flush_timer.daemon = True
        _flush_timer.start()


def flush():
    """Public API: force-flush all write buffers."""
    _flush_buffer()
    _flush_ws_buffer()


# ---------------------------------------------------------------------------
# Insert helpers (used by the proxy addon)
# ---------------------------------------------------------------------------

def insert_request(
    *,
    method: str,
    url: str,
    host: str,
    path: str,
    port: int | None = None,
    scheme: str | None = None,
    request_headers: dict | None = None,
    request_body: str | None = None,
    status_code: int | None = None,
    response_headers: dict | None = None,
    response_body: str | None = None,
    content_type: str | None = None,
    content_length: int | None = None,
    duration_ms: float | None = None,
) -> int:
    """Buffer a captured request for batch insert. Returns 0 (ID assigned at flush)."""
    now = datetime.now(timezone.utc)
    row = (
        now, method, url, host, path, port, scheme,
        json.dumps(request_headers) if request_headers else None,
        request_body,
        status_code,
        json.dumps(response_headers) if response_headers else None,
        response_body,
        content_type,
        content_length,
        duration_ms,
    )
    with _buffer_lock:
        _buffer.append(row)
        buf_len = len(_buffer)

    if buf_len >= _FLUSH_SIZE:
        _flush_buffer()
    else:
        _schedule_flush()

    return 0  # ID assigned by sequence at flush time


def insert_request_immediate(
    *,
    method: str,
    url: str,
    host: str,
    path: str,
    port: int | None = None,
    scheme: str | None = None,
    request_headers: dict | None = None,
    request_body: str | None = None,
    status_code: int | None = None,
    response_headers: dict | None = None,
    response_body: str | None = None,
    content_type: str | None = None,
    content_length: int | None = None,
    duration_ms: float | None = None,
) -> int:
    """Insert a single request immediately (bypasses buffer). Returns row id."""
    now = datetime.now(timezone.utc)
    conn = _get_conn()
    with _lock:
        result = conn.execute(
            """
            INSERT INTO requests
                (timestamp, method, url, host, path, port, scheme,
                 request_headers, request_body,
                 status_code, response_headers, response_body,
                 content_type, content_length, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            [
                now, method, url, host, path, port, scheme,
                json.dumps(request_headers) if request_headers else None,
                request_body,
                status_code,
                json.dumps(response_headers) if response_headers else None,
                response_body,
                content_type,
                content_length,
                duration_ms,
            ],
        )
        row = result.fetchone()
    return row[0] if row else 0


def is_domain_blocked(domain: str) -> tuple[bool, str | None]:
    """Check whether a domain is on the block list. Returns (blocked, reason)."""
    rows = _query("SELECT reason FROM blocked_domains WHERE domain = ?", [domain])
    if rows:
        return True, rows[0]["reason"]
    return False, None


def add_blocked_domain(domain: str, reason: str | None = None) -> bool:
    """Add a domain to the block list. Returns True if newly added."""
    now = datetime.now(timezone.utc)
    try:
        _execute(
            "INSERT INTO blocked_domains (domain, reason, created_at) VALUES (?, ?, ?)",
            [domain, reason, now],
        )
        return True
    except duckdb.ConstraintException:
        return False


def remove_blocked_domain(domain: str) -> bool:
    """Remove a domain from the block list. Returns True if it existed."""
    # Check existence first, then delete (DuckDB doesn't return rowcount easily)
    rows = _query("SELECT id FROM blocked_domains WHERE domain = ?", [domain])
    if not rows:
        return False
    _execute("DELETE FROM blocked_domains WHERE domain = ?", [domain])
    return True


# ---------------------------------------------------------------------------
# Query helpers (used by the MCP server)
# ---------------------------------------------------------------------------

def _parse_json_cols(d: dict) -> dict:
    """Parse JSON string columns back to dicts."""
    for key in ("request_headers", "response_headers"):
        if d.get(key) and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def get_recent_requests(
    limit: int = 25,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
) -> list[dict]:
    """Return recent requests with optional filters."""
    clauses: list[str] = []
    params: list = []
    if method:
        clauses.append("method = ?")
        params.append(method.upper())
    if host:
        clauses.append("host ILIKE ?")
        params.append(f"%{host}%")
    if status_code is not None:
        clauses.append("status_code = ?")
        params.append(status_code)
    if search:
        clauses.append("url ILIKE ?")
        params.append(f"%{search}%")

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 200))

    # Flush buffer so recent data is visible
    _flush_buffer()

    return _query(
        f"""
        SELECT id, timestamp, method, url, host, status_code,
               content_type, content_length, duration_ms
        FROM requests{where}
        ORDER BY id DESC
        LIMIT ?
        """,
        params,
    )


def get_request_by_id(request_id: int) -> dict | None:
    """Return full details of a single request."""
    _flush_buffer()
    rows = _query("SELECT * FROM requests WHERE id = ?", [request_id])
    if rows:
        return _parse_json_cols(rows[0])
    return None


def get_domain_summary(limit: int = 30) -> list[dict]:
    """Aggregate traffic stats per domain."""
    _flush_buffer()
    return _query(
        """
        SELECT host,
               COUNT(*)               AS total_requests,
               COUNT(DISTINCT method)  AS distinct_methods,
               STRING_AGG(DISTINCT method, ',') AS methods,
               AVG(duration_ms)        AS avg_duration_ms,
               SUM(content_length)     AS total_bytes,
               MIN(timestamp)          AS first_seen,
               MAX(timestamp)          AS last_seen
        FROM requests
        GROUP BY host
        ORDER BY total_requests DESC
        LIMIT ?
        """,
        [limit],
    )


def get_traffic_stats() -> dict:
    """Return overall traffic statistics."""
    _flush_buffer()
    rows = _query(
        """
        SELECT COUNT(*)                     AS total_requests,
               COUNT(DISTINCT host)          AS unique_hosts,
               COUNT(DISTINCT method)        AS distinct_methods,
               AVG(duration_ms)              AS avg_duration_ms,
               SUM(content_length)           AS total_bytes,
               MIN(timestamp)                AS earliest,
               MAX(timestamp)                AS latest,
               SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors,
               SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS success
        FROM requests
        """
    )
    return rows[0] if rows else {}


def find_errors(limit: int = 50) -> list[dict]:
    """Find requests that returned HTTP error status codes (4xx / 5xx)."""
    _flush_buffer()
    return _query(
        """
        SELECT id, timestamp, method, url, host, status_code, content_type, duration_ms
        FROM requests
        WHERE status_code >= 400
        ORDER BY id DESC
        LIMIT ?
        """,
        [limit],
    )


def search_requests(
    pattern: str,
    field: str = "url",
    limit: int = 50,
) -> list[dict]:
    """Search requests by ILIKE pattern on a given field."""
    allowed_fields = {"url", "host", "path", "request_body", "response_body", "content_type"}
    if field not in allowed_fields:
        raise ValueError(f"field must be one of {allowed_fields}")
    _flush_buffer()
    return _query(
        f"""
        SELECT id, timestamp, method, url, host, status_code,
               content_type, content_length, duration_ms
        FROM requests
        WHERE {field} ILIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        [f"%{pattern}%", limit],
    )


def get_all_blocked_domains() -> list[dict]:
    """Return all blocked domains."""
    return _query(
        "SELECT id, domain, reason, created_at FROM blocked_domains ORDER BY created_at DESC"
    )


def add_tag(request_id: int, tag: str) -> int:
    """Tag a request. Returns tag id."""
    now = datetime.now(timezone.utc)
    conn = _get_conn()
    with _lock:
        result = conn.execute(
            "INSERT INTO tags (request_id, tag, created_at) VALUES (?, ?, ?) RETURNING id",
            [request_id, tag, now],
        )
        row = result.fetchone()
    return row[0] if row else 0


def get_tags_for_request(request_id: int) -> list[str]:
    """Return tags for a request."""
    rows = _query("SELECT tag FROM tags WHERE request_id = ?", [request_id])
    return [r["tag"] for r in rows]


# ---------------------------------------------------------------------------
# WebSocket write buffer
# ---------------------------------------------------------------------------

_ws_buffer: list[tuple] = []
_ws_buffer_lock = threading.Lock()
_ws_flush_timer: threading.Timer | None = None

_WS_INSERT_COLS = (
    "timestamp", "flow_id", "host", "url",
    "direction", "message_type", "content", "content_length",
)


def _flush_ws_buffer() -> None:
    """Flush WebSocket message buffer to DuckDB."""
    global _ws_flush_timer
    with _ws_buffer_lock:
        if not _ws_buffer:
            return
        batch = _ws_buffer.copy()
        _ws_buffer.clear()
        _ws_flush_timer = None

    if not batch:
        return

    placeholders = ", ".join(["?"] * len(_WS_INSERT_COLS))
    cols = ", ".join(_WS_INSERT_COLS)
    conn = _get_conn()
    with _lock:
        conn.executemany(
            f"INSERT INTO websocket_messages ({cols}) VALUES ({placeholders})",
            batch,
        )


def _schedule_ws_flush() -> None:
    """Schedule a timer-based WS buffer flush."""
    global _ws_flush_timer
    if _ws_flush_timer is None:
        _ws_flush_timer = threading.Timer(_FLUSH_INTERVAL, _flush_ws_buffer)
        _ws_flush_timer.daemon = True
        _ws_flush_timer.start()


# ---------------------------------------------------------------------------
# WebSocket insert helpers
# ---------------------------------------------------------------------------

def insert_ws_message(
    *,
    flow_id: str,
    host: str,
    url: str,
    direction: str,
    message_type: str,
    content: str | None = None,
    content_length: int | None = None,
) -> None:
    """Buffer a WebSocket message for batch insert."""
    now = datetime.now(timezone.utc)
    row = (now, flow_id, host, url, direction, message_type, content, content_length)
    with _ws_buffer_lock:
        _ws_buffer.append(row)
        buf_len = len(_ws_buffer)

    if buf_len >= _FLUSH_SIZE:
        _flush_ws_buffer()
    else:
        _schedule_ws_flush()


# ---------------------------------------------------------------------------
# WebSocket query helpers
# ---------------------------------------------------------------------------

def get_ws_connections(limit: int = 50) -> list[dict]:
    """List distinct WebSocket connections with message counts."""
    _flush_ws_buffer()
    return _query(
        """
        SELECT flow_id, host, url,
               COUNT(*) AS total_messages,
               SUM(CASE WHEN direction = 'send' THEN 1 ELSE 0 END) AS sent,
               SUM(CASE WHEN direction = 'receive' THEN 1 ELSE 0 END) AS received,
               SUM(content_length) AS total_bytes,
               MIN(timestamp) AS first_message,
               MAX(timestamp) AS last_message
        FROM websocket_messages
        GROUP BY flow_id, host, url
        ORDER BY last_message DESC
        LIMIT ?
        """,
        [limit],
    )


def get_ws_messages(
    flow_id: str | None = None,
    host: str | None = None,
    direction: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return WebSocket messages with optional filters."""
    _flush_ws_buffer()
    clauses: list[str] = []
    params: list = []
    if flow_id:
        clauses.append("flow_id = ?")
        params.append(flow_id)
    if host:
        clauses.append("host ILIKE ?")
        params.append(f"%{host}%")
    if direction:
        clauses.append("direction = ?")
        params.append(direction)
    if search:
        clauses.append("content ILIKE ?")
        params.append(f"%{search}%")

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 500))

    return _query(
        f"""
        SELECT id, timestamp, flow_id, host, url, direction,
               message_type, content, content_length
        FROM websocket_messages{where}
        ORDER BY id DESC
        LIMIT ?
        """,
        params,
    )


def get_ws_stats() -> dict:
    """Return overall WebSocket statistics."""
    _flush_ws_buffer()
    rows = _query(
        """
        SELECT COUNT(*)              AS total_messages,
               COUNT(DISTINCT flow_id) AS total_connections,
               COUNT(DISTINCT host)    AS unique_hosts,
               SUM(content_length)     AS total_bytes,
               SUM(CASE WHEN direction = 'send' THEN 1 ELSE 0 END) AS sent,
               SUM(CASE WHEN direction = 'receive' THEN 1 ELSE 0 END) AS received,
               MIN(timestamp)          AS earliest,
               MAX(timestamp)          AS latest
        FROM websocket_messages
        """
    )
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# API mapping queries
# ---------------------------------------------------------------------------

def _normalize_path(path: str) -> str:
    """Replace numeric/UUID path segments with placeholders to group endpoints."""
    segments = path.split("/")
    normalized = []
    for seg in segments:
        if not seg:
            normalized.append(seg)
        elif re.fullmatch(r'\d+', seg):
            normalized.append("{id}")
        elif re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', seg, re.I):
            normalized.append("{uuid}")
        elif re.fullmatch(r'[0-9a-f]{24}', seg, re.I):
            normalized.append("{objectId}")
        else:
            normalized.append(seg)
    return "/".join(normalized)


def get_api_map(host: str | None = None, limit: int = 100) -> list[dict]:
    """Map discovered API endpoints grouped by normalized path.

    Returns endpoints with methods, status codes, avg duration, and request counts.
    """
    _flush_buffer()
    clauses: list[str] = []
    params: list = []
    if host:
        clauses.append("host ILIKE ?")
        params.append(f"%{host}%")

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 500))

    raw = _query(
        f"""
        SELECT host, path, method, status_code,
               COUNT(*) AS hits,
               AVG(duration_ms) AS avg_duration_ms,
               MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen
        FROM requests{where}
        GROUP BY host, path, method, status_code
        ORDER BY hits DESC
        LIMIT ?
        """,
        params,
    )

    # Group by normalized endpoint
    endpoints: dict[str, dict] = {}
    for row in raw:
        norm = _normalize_path(row["path"])
        key = f"{row['host']}|{norm}"
        if key not in endpoints:
            endpoints[key] = {
                "host": row["host"],
                "path": norm,
                "original_paths": set(),
                "methods": set(),
                "status_codes": set(),
                "total_hits": 0,
                "avg_duration_ms": [],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
        ep = endpoints[key]
        ep["original_paths"].add(row["path"])
        ep["methods"].add(row["method"])
        if row["status_code"] is not None:
            ep["status_codes"].add(row["status_code"])
        ep["total_hits"] += row["hits"]
        if row["avg_duration_ms"] is not None:
            ep["avg_duration_ms"].append(row["avg_duration_ms"])
        if row["first_seen"] < ep["first_seen"]:
            ep["first_seen"] = row["first_seen"]
        if row["last_seen"] > ep["last_seen"]:
            ep["last_seen"] = row["last_seen"]

    # Convert sets to sorted lists for JSON serialization
    result = []
    for ep in sorted(endpoints.values(), key=lambda e: e["total_hits"], reverse=True):
        durations = ep["avg_duration_ms"]
        result.append({
            "host": ep["host"],
            "endpoint": ep["path"],
            "original_paths": sorted(ep["original_paths"]),
            "methods": sorted(ep["methods"]),
            "status_codes": sorted(ep["status_codes"]),
            "total_hits": ep["total_hits"],
            "avg_duration_ms": round(sum(durations) / len(durations), 2) if durations else None,
            "first_seen": str(ep["first_seen"]),
            "last_seen": str(ep["last_seen"]),
        })
    return result


def get_endpoint_detail(host: str, path: str, limit: int = 50) -> list[dict]:
    """Get recent requests for a specific host + path combination."""
    _flush_buffer()
    return _query(
        """
        SELECT id, timestamp, method, url, host, path, status_code,
               content_type, content_length, duration_ms
        FROM requests
        WHERE host ILIKE ? AND path ILIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        [f"%{host}%", f"%{path}%", limit],
    )


# ---------------------------------------------------------------------------
# Live feed – poll-based stream of traffic
# ---------------------------------------------------------------------------

def get_live_feed(
    after_id: int | None = None,
    after_ws_id: int | None = None,
    include_bodies: bool = False,
    limit: int = 100,
) -> dict:
    """Return new HTTP requests and WebSocket messages since the given cursors.

    The caller passes the last-seen ``after_id`` (for HTTP) and
    ``after_ws_id`` (for WS). The response includes the new high-water
    marks so the next call can pick up where it left off – giving the LLM
    an efficient poll-based live stream.
    """
    _flush_buffer()
    _flush_ws_buffer()

    cap = min(limit, 500)

    # -- HTTP --
    if after_id is not None:
        if include_bodies:
            http_rows = _query(
                "SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT ?",
                [after_id, cap],
            )
            http_rows = [_parse_json_cols(r) for r in http_rows]
        else:
            http_rows = _query(
                """SELECT id, timestamp, method, url, host, status_code,
                          content_type, content_length, duration_ms
                   FROM requests WHERE id > ? ORDER BY id ASC LIMIT ?""",
                [after_id, cap],
            )
    else:
        # First call – return the latest <limit> rows so the LLM has context
        if include_bodies:
            http_rows = _query(
                "SELECT * FROM requests ORDER BY id DESC LIMIT ?", [cap]
            )
            http_rows = [_parse_json_cols(r) for r in http_rows]
        else:
            http_rows = _query(
                """SELECT id, timestamp, method, url, host, status_code,
                          content_type, content_length, duration_ms
                   FROM requests ORDER BY id DESC LIMIT ?""",
                [cap],
            )
        http_rows.reverse()  # oldest-first

    new_http_cursor = http_rows[-1]["id"] if http_rows else after_id

    # -- WebSocket --
    if after_ws_id is not None:
        ws_rows = _query(
            """SELECT id, timestamp, flow_id, host, url, direction,
                      message_type, content, content_length
               FROM websocket_messages WHERE id > ? ORDER BY id ASC LIMIT ?""",
            [after_ws_id, cap],
        )
    else:
        ws_rows = _query(
            """SELECT id, timestamp, flow_id, host, url, direction,
                      message_type, content, content_length
               FROM websocket_messages ORDER BY id DESC LIMIT ?""",
            [cap],
        )
        ws_rows.reverse()

    new_ws_cursor = ws_rows[-1]["id"] if ws_rows else after_ws_id

    return {
        "http": {"count": len(http_rows), "requests": http_rows, "cursor": new_http_cursor},
        "ws": {"count": len(ws_rows), "messages": ws_rows, "cursor": new_ws_cursor},
        "hint": "Pass cursor values back as after_id / after_ws_id to get only new traffic.",
    }


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

_VULN_SQL_RE = re.compile(
    r'(?:SQL syntax.*?MySQL|Warning.*?\Wmysql_|valid MySQL result'
    r'|pg_query\b|pg_exec\b|PostgreSQL.*?ERROR'
    r'|SQLite3::|sqlite_|SQLITE_ERROR'
    r'|ORA-\d{5}|SQLSTATE\['
    r'|Unclosed quotation mark|Microsoft OLE DB'
    r'|ODBC SQL Server|JET Database Engine)',
    re.I,
)

_VULN_XSS_RE = re.compile(
    r'<script|javascript:|on(?:error|load|click|focus|mouseover)\s*='
    r'|eval\s*\(|document\.cookie|document\.write',
    re.I,
)

_VULN_TRAVERSAL_RE = re.compile(r'\.\./|\.\.\\|%2e%2e[/\\%]', re.I)

_SENSITIVE_PATHS_RE = re.compile(
    r'(?:\.git[/\\]|\.env\b|\.htaccess|\.htpasswd|wp-admin|wp-login'
    r'|phpinfo|phpmyadmin|\.DS_Store|web\.config'
    r'|server-status|server-info|\.svn[/\\]|elmah\.axd'
    r'|actuator|swagger-ui|api-docs)',
    re.I,
)

_CRED_KEYWORDS = (
    "password=", "passwd=", "pwd=", "secret=", "token=",
    "api_key=", "apikey=", "access_key=", "auth=",
)

_PII_PATTERNS = {
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "credit_card": re.compile(
        r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}'
        r'|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12})\b'
    ),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "phone": re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+'),
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
}

_AUTH_HEADERS = (
    "authorization", "x-api-key", "x-auth-token",
    "x-access-token", "proxy-authorization",
)

_SESSION_COOKIE_NAMES = ("session", "token", "auth", "jwt", "sid", "csrf", "xsrf")


def scan_vulnerabilities(limit: int = 500) -> dict:
    """Scan captured traffic for common vulnerability indicators."""
    _flush_buffer()
    findings: list[dict] = []
    rows = _query(
        """SELECT id, method, url, host, path, scheme, status_code,
                  request_headers, request_body, response_headers, response_body
           FROM requests ORDER BY id DESC LIMIT ?""",
        [min(limit, 2000)],
    )
    for row in rows:
        row = _parse_json_cols(row)
        rid, url = row["id"], row["url"] or ""
        path = row.get("path") or ""
        resp_body = row.get("response_body") or ""
        req_body = row.get("request_body") or ""
        resp_h = row.get("response_headers") if isinstance(row.get("response_headers"), dict) else {}

        if _VULN_SQL_RE.search(resp_body):
            findings.append({"type": "sql_error_leak", "severity": "high",
                             "request_id": rid, "url": url,
                             "detail": "SQL error in response – possible injection"})
        if _VULN_XSS_RE.search(req_body) or _VULN_XSS_RE.search(url):
            findings.append({"type": "xss_payload", "severity": "high",
                             "request_id": rid, "url": url,
                             "detail": "XSS payload in request"})
        if _VULN_TRAVERSAL_RE.search(url):
            findings.append({"type": "path_traversal", "severity": "high",
                             "request_id": rid, "url": url,
                             "detail": "Path traversal pattern in URL"})
        if _SENSITIVE_PATHS_RE.search(path):
            findings.append({"type": "sensitive_path", "severity": "medium",
                             "request_id": rid, "url": url,
                             "detail": "Access to potentially sensitive path"})
        if row.get("scheme") == "http":
            combined = (req_body + url).lower()
            if any(k in combined for k in _CRED_KEYWORDS):
                findings.append({"type": "plaintext_creds", "severity": "critical",
                                 "request_id": rid, "url": url,
                                 "detail": "Credentials over unencrypted HTTP"})
        server_h = resp_h.get("server", resp_h.get("Server", "")) if isinstance(resp_h, dict) else ""
        if server_h and re.search(r'\d+\.\d+', str(server_h)):
            findings.append({"type": "server_version_leak", "severity": "low",
                             "request_id": rid, "url": url,
                             "detail": f"Server version: {server_h}"})
        trace_markers = ("Traceback (most recent", "Exception in thread",
                         "NullPointerException", "at java.", "at com.")
        if any(m in resp_body for m in trace_markers):
            findings.append({"type": "stack_trace_leak", "severity": "medium",
                             "request_id": rid, "url": url,
                             "detail": "Stack trace in response"})

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"]] += 1
    return {"total_scanned": len(rows), "findings_count": len(findings),
            "by_severity": sev, "findings": findings}


def detect_pii(limit: int = 500) -> dict:
    """Scan request/response bodies and URLs for PII patterns."""
    _flush_buffer()
    findings: list[dict] = []
    rows = _query(
        """SELECT id, url, host, method, request_body, response_body
           FROM requests ORDER BY id DESC LIMIT ?""",
        [min(limit, 2000)],
    )
    for row in rows:
        rid, url = row["id"], row["url"] or ""
        for loc, text in [("request_body", row.get("request_body") or ""),
                          ("response_body", row.get("response_body") or ""),
                          ("url", url)]:
            if not text:
                continue
            for pii_type, pat in _PII_PATTERNS.items():
                matches = pat.findall(text)
                if matches:
                    unique = list(set(matches))[:5]
                    findings.append({
                        "type": pii_type, "location": loc,
                        "request_id": rid, "url": url, "count": len(matches),
                        "samples": [str(m)[:20] + "..." if len(str(m)) > 20 else str(m) for m in unique],
                    })
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    return {"total_scanned": len(rows), "findings_count": len(findings),
            "by_type": by_type, "findings": findings}


def extract_session_tokens(limit: int = 300) -> dict:
    """Extract authentication tokens, session cookies, and API keys from traffic."""
    _flush_buffer()
    tokens: list[dict] = []
    seen: set[str] = set()
    rows = _query(
        """SELECT id, url, host, request_headers, response_headers
           FROM requests ORDER BY id DESC LIMIT ?""",
        [min(limit, 1000)],
    )
    for row in rows:
        row = _parse_json_cols(row)
        rid, host = row["id"], row.get("host") or ""
        req_h = row.get("request_headers") or {}
        resp_h = row.get("response_headers") or {}

        # Auth headers
        for k, v in req_h.items():
            if k.lower() in _AUTH_HEADERS and v:
                key = f"h:{k}:{v[:30]}"
                if key not in seen:
                    seen.add(key)
                    tokens.append({"type": "auth_header", "header": k,
                                   "value": v[:80] + ("..." if len(v) > 80 else ""),
                                   "host": host, "request_id": rid})
        # Session cookies
        cookies_raw = req_h.get("cookie", req_h.get("Cookie", ""))
        if cookies_raw:
            for part in cookies_raw.split(";"):
                part = part.strip()
                if "=" in part:
                    name, val = part.split("=", 1)
                    if any(s in name.strip().lower() for s in _SESSION_COOKIE_NAMES):
                        key = f"c:{host}:{name.strip()}:{val[:20]}"
                        if key not in seen:
                            seen.add(key)
                            tokens.append({"type": "session_cookie", "name": name.strip(),
                                           "value": val[:60] + ("..." if len(val) > 60 else ""),
                                           "host": host, "request_id": rid})
        # Set-Cookie in responses
        for k, v in resp_h.items():
            if k.lower() == "set-cookie" and v:
                key = f"sc:{host}:{v[:40]}"
                if key not in seen:
                    seen.add(key)
                    tokens.append({"type": "set_cookie",
                                   "value": v[:120] + ("..." if len(v) > 120 else ""),
                                   "host": host, "request_id": rid})

    return {"total_scanned": len(rows), "tokens_found": len(tokens), "tokens": tokens}


def detect_session_issues(limit: int = 500) -> dict:
    """Detect session anomalies: cross-host cookies, missing CSRF, insecure flags."""
    _flush_buffer()
    issues: list[dict] = []
    rows = _query(
        """SELECT id, url, host, method, request_headers, response_headers
           FROM requests ORDER BY id DESC LIMIT ?""",
        [min(limit, 1000)],
    )
    session_hosts: dict[str, set[str]] = {}
    for row in rows:
        row = _parse_json_cols(row)
        host = row.get("host") or ""
        req_h = row.get("request_headers") or {}
        resp_h = row.get("response_headers") or {}

        cookies = req_h.get("cookie", req_h.get("Cookie", ""))
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part:
                name, val = part.split("=", 1)
                if any(s in name.strip().lower() for s in ("session", "sid", "auth")):
                    session_hosts.setdefault(f"{name.strip()}={val[:40]}", set()).add(host)

        # Missing CSRF on POST forms
        if row.get("method") in ("POST", "PUT", "DELETE", "PATCH"):
            ct = req_h.get("content-type", req_h.get("Content-Type", "")).lower()
            if "form" in ct:
                has_csrf = any(k.lower() in ("x-csrf-token", "x-xsrf-token") for k in req_h)
                if not has_csrf:
                    issues.append({"type": "missing_csrf", "severity": "medium",
                                   "request_id": row["id"], "url": row["url"],
                                   "detail": "Form POST without CSRF token"})

        # Insecure Set-Cookie flags
        for k, v in resp_h.items():
            if k.lower() == "set-cookie" and v:
                flags_lower = v.lower()
                missing_flags = []
                if "secure" not in flags_lower:
                    missing_flags.append("Secure")
                if "httponly" not in flags_lower:
                    missing_flags.append("HttpOnly")
                if "samesite" not in flags_lower:
                    missing_flags.append("SameSite")
                if missing_flags:
                    cname = v.split("=")[0].strip() if "=" in v else "unknown"
                    issues.append({"type": "insecure_cookie", "severity": "medium",
                                   "request_id": row["id"], "host": host,
                                   "cookie": cname, "missing_flags": missing_flags,
                                   "detail": f"Cookie '{cname}' missing: {', '.join(missing_flags)}"})

    for cookie_key, hosts in session_hosts.items():
        if len(hosts) > 1:
            issues.append({"type": "cross_host_session", "severity": "high",
                           "cookie": cookie_key[:50] + "...", "hosts": sorted(hosts),
                           "detail": f"Session cookie used across {len(hosts)} hosts"})

    return {"total_scanned": len(rows), "issues_count": len(issues), "issues": issues}


def detect_c2_patterns(limit: int = 1000) -> dict:
    """Detect potential C2 beaconing patterns and encoded payloads."""
    _flush_buffer()
    findings: list[dict] = []
    rows = _query(
        """SELECT host, timestamp, url, method, content_type, content_length
           FROM requests ORDER BY timestamp ASC LIMIT ?""",
        [min(limit, 5000)],
    )
    by_host: dict[str, list[dict]] = {}
    for r in rows:
        by_host.setdefault(r["host"], []).append(r)

    for host, reqs in by_host.items():
        if len(reqs) < 5:
            continue
        timestamps = []
        for r in reqs:
            ts = r["timestamp"]
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    continue
            timestamps.append(ts)
        if len(timestamps) < 5:
            continue

        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if 0 < delta < 3600:
                intervals.append(delta)
        if len(intervals) < 4:
            continue

        avg = sum(intervals) / len(intervals)
        if avg < 1:
            continue
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / avg if avg > 0 else float("inf")

        if cv < 0.3 and avg < 300:
            findings.append({
                "type": "beaconing", "severity": "high", "host": host,
                "avg_interval_sec": round(avg, 1),
                "std_dev_sec": round(std_dev, 1),
                "coefficient_of_variation": round(cv, 3),
                "sample_count": len(intervals),
                "detail": f"Regular beaconing: ~{avg:.0f}s intervals (CV={cv:.2f})",
            })

    # Encoded payloads in URLs
    for r in rows:
        url = r.get("url") or ""
        if "?" in url:
            query = url.split("?", 1)[1]
            if len(query) > 200 and re.search(r'[A-Za-z0-9+/=]{100,}', query):
                findings.append({
                    "type": "encoded_payload", "severity": "medium",
                    "host": r["host"], "url": url[:200],
                    "detail": "Suspiciously long encoded query parameter",
                })

    return {"total_scanned": len(rows), "findings_count": len(findings), "findings": findings}


# ---------------------------------------------------------------------------
# Privacy & compliance
# ---------------------------------------------------------------------------

_AD_PATTERN = re.compile(
    r'(?:doubleclick|googlesyndication|googleadservices|facebook.*ads'
    r'|ads\.|adserver|adtrack|analytics|tracker|pixel|beacon'
    r'|taboola|outbrain|criteo|pubmatic|rubiconproject)', re.I,
)
_SOCIAL_PATTERN = re.compile(
    r'(?:facebook|twitter|instagram|linkedin|tiktok|pinterest'
    r'|reddit|tumblr|snapchat)\.(?:com|net)', re.I,
)
_CDN_PATTERN = re.compile(
    r'(?:cloudflare|cloudfront|akamai|fastly|cdn|static'
    r'|assets|googleapis|gstatic)', re.I,
)


def audit_third_parties(limit: int = 100) -> dict:
    """List all external domains contacted with traffic stats and categorization."""
    _flush_buffer()
    rows = _query(
        """SELECT host,
                  COUNT(*) AS total_requests,
                  SUM(content_length) AS total_bytes,
                  STRING_AGG(DISTINCT method, ', ') AS methods,
                  MIN(timestamp) AS first_seen,
                  MAX(timestamp) AS last_seen,
                  SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors
           FROM requests GROUP BY host
           ORDER BY total_requests DESC LIMIT ?""",
        [min(limit, 500)],
    )
    for r in rows:
        host = r["host"] or ""
        if _AD_PATTERN.search(host):
            r["category"] = "advertising/tracking"
        elif _SOCIAL_PATTERN.search(host):
            r["category"] = "social_media"
        elif _CDN_PATTERN.search(host):
            r["category"] = "cdn/static"
        else:
            r["category"] = "other"
    return {"total_domains": len(rows), "domains": rows}


def analyze_cookies_in_traffic(limit: int = 300) -> dict:
    """Parse and categorize all cookies from Set-Cookie headers."""
    _flush_buffer()
    cookies_map: dict[str, dict] = {}
    rows = _query(
        """SELECT id, host, request_headers, response_headers
           FROM requests ORDER BY id DESC LIMIT ?""",
        [min(limit, 1000)],
    )
    for row in rows:
        row = _parse_json_cols(row)
        host = row.get("host") or ""
        resp_h = row.get("response_headers") or {}

        for k, v in resp_h.items():
            if k.lower() != "set-cookie" or not v:
                continue
            parts = [p.strip() for p in v.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name, val = parts[0].split("=", 1)
            name = name.strip()
            flags_raw = [p.lower().strip() for p in parts[1:]]
            flags: dict[str, Any] = {}
            for f in flags_raw:
                if f:
                    if "=" in f:
                        fk, fv = f.split("=", 1)
                        flags[fk] = fv
                    else:
                        flags[f] = True

            key = f"{host}:{name}"
            if key not in cookies_map:
                name_l = name.lower()
                if any(s in name_l for s in ("session", "sid", "auth", "login")):
                    category = "session"
                elif any(s in name_l for s in ("track", "analytics", "_ga", "_gid", "_fbp", "pixel")):
                    category = "tracking"
                elif any(s in name_l for s in ("csrf", "xsrf")):
                    category = "csrf"
                elif any(s in name_l for s in ("pref", "lang", "theme", "consent")):
                    category = "preference"
                else:
                    category = "other"
                cookies_map[key] = {
                    "name": name, "host": host, "category": category,
                    "secure": "secure" in flags, "httponly": "httponly" in flags,
                    "samesite": flags.get("samesite", "not set"),
                    "path": flags.get("path", "/"),
                    "max_age": flags.get("max-age"),
                    "seen_count": 0,
                    "sample_value": val[:40] + ("..." if len(val) > 40 else ""),
                }
            cookies_map[key]["seen_count"] += 1

    cookies = sorted(cookies_map.values(), key=lambda c: c["seen_count"], reverse=True)
    by_cat: dict[str, int] = {}
    for c in cookies:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    return {"total_cookies": len(cookies), "by_category": by_cat, "cookies": cookies}


# ---------------------------------------------------------------------------
# Debugging & development
# ---------------------------------------------------------------------------

def compare_requests(id1: int, id2: int) -> dict:
    """Compare two requests side-by-side, highlighting differences."""
    _flush_buffer()
    r1 = get_request_by_id(id1)
    r2 = get_request_by_id(id2)
    if not r1 or not r2:
        missing = str(id1) if not r1 else str(id2)
        return {"error": f"Request #{missing} not found"}

    diffs: list[dict] = []
    for field in ("method", "url", "host", "path", "scheme", "status_code",
                  "content_type", "content_length", "duration_ms"):
        v1, v2 = r1.get(field), r2.get(field)
        if v1 != v2:
            diffs.append({"field": field, "request_1": v1, "request_2": v2})

    for hdr_key in ("request_headers", "response_headers"):
        h1 = r1.get(hdr_key) or {}
        h2 = r2.get(hdr_key) or {}
        all_keys = sorted(set(list(h1.keys()) + list(h2.keys())))
        for k in all_keys:
            v1, v2 = h1.get(k), h2.get(k)
            if v1 != v2:
                diffs.append({"field": f"{hdr_key}.{k}", "request_1": v1, "request_2": v2})

    for body_key in ("request_body", "response_body"):
        b1, b2 = r1.get(body_key) or "", r2.get(body_key) or ""
        if b1 != b2:
            diffs.append({
                "field": body_key,
                "request_1": b1[:200] + ("..." if len(b1) > 200 else ""),
                "request_2": b2[:200] + ("..." if len(b2) > 200 else ""),
            })

    return {
        "request_1": {"id": id1, "method": r1.get("method"), "url": r1.get("url")},
        "request_2": {"id": id2, "method": r2.get("method"), "url": r2.get("url")},
        "differences_count": len(diffs),
        "identical": len(diffs) == 0,
        "differences": diffs,
    }


def generate_openapi_spec(host: str | None = None) -> dict:
    """Generate an OpenAPI 3.0 spec from observed traffic patterns."""
    _flush_buffer()
    clauses: list[str] = []
    params: list = []
    if host:
        clauses.append("host ILIKE ?")
        params.append(f"%{host}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    rows = _query(
        f"""SELECT DISTINCT host, path, method, status_code,
                   content_type, request_headers, request_body,
                   response_headers, response_body
            FROM requests{where}
            ORDER BY host, path, method
            LIMIT 2000""",
        params or None,
    )

    hosts_seen: set[str] = set()
    paths_spec: dict[str, dict] = {}
    for row in rows:
        row = _parse_json_cols(row)
        h = row["host"]
        hosts_seen.add(h)
        norm = _normalize_path(row["path"])
        method = (row["method"] or "GET").lower()
        status = str(row.get("status_code") or 200)
        ct = row.get("content_type") or "application/json"

        if norm not in paths_spec:
            paths_spec[norm] = {}
        if method not in paths_spec[norm]:
            paths_spec[norm][method] = {
                "summary": f"{row['method']} {norm}",
                "responses": {},
            }
            path_params = []
            for seg in norm.split("/"):
                if seg.startswith("{") and seg.endswith("}"):
                    path_params.append({
                        "name": seg[1:-1], "in": "path",
                        "required": True, "schema": {"type": "string"},
                    })
            if path_params:
                paths_spec[norm][method]["parameters"] = path_params

        op = paths_spec[norm][method]
        if status not in op["responses"]:
            ct_clean = ct.split(";")[0].strip() if ct else "application/json"
            op["responses"][status] = {
                "description": f"Status {status}",
                "content": {ct_clean: {"schema": {"type": "object"}}},
            }

    primary_host = host or (sorted(hosts_seen)[0] if hosts_seen else "localhost")
    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"API for {primary_host}",
            "version": "1.0.0",
            "description": "Auto-generated from captured traffic by LLMProxy",
        },
        "servers": [{"url": f"https://{h}"} for h in sorted(hosts_seen)[:5]],
        "paths": paths_spec,
    }


def analyze_performance(limit: int = 100) -> dict:
    """Find slow endpoints, large payloads, redundant requests, and error hotspots."""
    _flush_buffer()
    slow = _query(
        """SELECT host, path, method,
                  COUNT(*) AS hits,
                  AVG(duration_ms) AS avg_ms,
                  MAX(duration_ms) AS max_ms,
                  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_ms
           FROM requests WHERE duration_ms IS NOT NULL
           GROUP BY host, path, method HAVING COUNT(*) >= 2
           ORDER BY avg_ms DESC LIMIT ?""",
        [min(limit, 100)],
    )
    large = _query(
        """SELECT id, url, host, method, content_type,
                  content_length, duration_ms
           FROM requests WHERE content_length IS NOT NULL
           ORDER BY content_length DESC LIMIT 20"""
    )
    redundant = _query(
        """SELECT url, method, COUNT(*) AS hits
           FROM requests GROUP BY url, method
           HAVING COUNT(*) > 3 ORDER BY hits DESC LIMIT 20"""
    )
    error_prone = _query(
        """SELECT host, path, method,
                  COUNT(*) AS total,
                  SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors,
                  ROUND(100.0 * SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)
                        / COUNT(*), 1) AS error_rate
           FROM requests GROUP BY host, path, method
           HAVING errors > 0 ORDER BY error_rate DESC LIMIT 20"""
    )
    return {
        "slow_endpoints": slow,
        "large_payloads": large,
        "redundant_requests": redundant,
        "error_prone_endpoints": error_prone,
    }


def generate_curl_command(request_id: int) -> str:
    """Generate a curl command that reproduces a captured request."""
    req = get_request_by_id(request_id)
    if not req:
        return ""
    parts = [f"curl -X {req['method']}"]
    parts.append(f"  '{req['url']}'")
    headers = req.get("request_headers") or {}
    skip = {"host", "content-length", "transfer-encoding"}
    for k, v in headers.items():
        if k.lower() not in skip:
            parts.append(f"  -H '{k}: {v}'")
    body = req.get("request_body")
    if body and not body.startswith("<"):
        escaped = body.replace("'", "'\\''")
        parts.append(f"  -d '{escaped}'")
    return " \\\n".join(parts)


# ---------------------------------------------------------------------------
# Monitoring & analysis
# ---------------------------------------------------------------------------

def detect_anomalies(limit: int = 1000) -> dict:
    """Detect unusual traffic patterns: status spikes, timing outliers, rare hosts."""
    _flush_buffer()
    status_dist = _query(
        """SELECT status_code, COUNT(*) AS cnt
           FROM requests WHERE status_code IS NOT NULL
           GROUP BY status_code ORDER BY cnt DESC"""
    )
    stats = _query(
        "SELECT AVG(duration_ms) AS avg, STDDEV(duration_ms) AS sd "
        "FROM requests WHERE duration_ms IS NOT NULL"
    )
    avg_d = stats[0]["avg"] if stats and stats[0]["avg"] else 0
    sd_d = stats[0]["sd"] if stats and stats[0]["sd"] else 0
    threshold = avg_d + 3 * sd_d if sd_d else avg_d * 3

    outliers = []
    if threshold > 0:
        outliers = _query(
            """SELECT id, url, host, method, duration_ms, status_code
               FROM requests WHERE duration_ms > ? ORDER BY duration_ms DESC LIMIT 20""",
            [threshold],
        )
    rare_hosts = _query(
        """SELECT host, COUNT(*) AS cnt, MIN(timestamp) AS first_seen
           FROM requests GROUP BY host HAVING cnt <= 2
           ORDER BY first_seen DESC LIMIT 30"""
    )
    error_bursts = _query(
        """SELECT DATE_TRUNC('minute', timestamp) AS minute,
                  COUNT(*) AS error_count,
                  STRING_AGG(DISTINCT host, ', ') AS hosts
           FROM requests WHERE status_code >= 400
           GROUP BY DATE_TRUNC('minute', timestamp)
           HAVING error_count >= 5 ORDER BY minute DESC LIMIT 20"""
    )
    return {
        "status_distribution": status_dist,
        "timing_outliers": {"threshold_ms": round(threshold, 1), "outliers": outliers},
        "rare_hosts": rare_hosts,
        "error_bursts": error_bursts,
    }


def summarize_activity(hours: int = 24) -> dict:
    """High-level activity summary for a given time window."""
    _flush_buffer()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    overview = _query(
        """SELECT COUNT(*) AS total_requests,
                  COUNT(DISTINCT host) AS unique_hosts,
                  SUM(content_length) AS total_bytes,
                  AVG(duration_ms) AS avg_duration_ms,
                  SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors
           FROM requests WHERE timestamp >= ?""",
        [cutoff],
    )
    top_hosts = _query(
        """SELECT host, COUNT(*) AS requests, SUM(content_length) AS bytes
           FROM requests WHERE timestamp >= ?
           GROUP BY host ORDER BY requests DESC LIMIT 10""",
        [cutoff],
    )
    top_paths = _query(
        """SELECT host, path, method, COUNT(*) AS hits
           FROM requests WHERE timestamp >= ?
           GROUP BY host, path, method ORDER BY hits DESC LIMIT 10""",
        [cutoff],
    )
    hourly = _query(
        """SELECT DATE_TRUNC('hour', timestamp) AS hour, COUNT(*) AS requests
           FROM requests WHERE timestamp >= ?
           GROUP BY hour ORDER BY hour""",
        [cutoff],
    )
    return {
        "period_hours": hours,
        "overview": overview[0] if overview else {},
        "top_hosts": top_hosts,
        "top_paths": top_paths,
        "hourly_breakdown": hourly,
    }


def bandwidth_analysis(limit: int = 50) -> dict:
    """Identify top bandwidth consumers by host and content type."""
    _flush_buffer()
    by_host = _query(
        """SELECT host, SUM(content_length) AS total_bytes,
                  COUNT(*) AS requests, AVG(content_length) AS avg_bytes
           FROM requests WHERE content_length > 0
           GROUP BY host ORDER BY total_bytes DESC LIMIT ?""",
        [min(limit, 100)],
    )
    by_type = _query(
        """SELECT content_type, SUM(content_length) AS total_bytes,
                  COUNT(*) AS requests, AVG(content_length) AS avg_bytes
           FROM requests WHERE content_length > 0 AND content_type IS NOT NULL
           GROUP BY content_type ORDER BY total_bytes DESC LIMIT 20"""
    )
    largest = _query(
        """SELECT id, url, host, content_type, content_length
           FROM requests WHERE content_length IS NOT NULL
           ORDER BY content_length DESC LIMIT 20"""
    )
    total = _query(
        "SELECT SUM(content_length) AS total FROM requests WHERE content_length > 0"
    )
    return {
        "total_bytes": total[0]["total"] if total else 0,
        "by_host": by_host,
        "by_content_type": by_type,
        "largest_responses": largest,
    }


# ---------------------------------------------------------------------------
# Traffic manipulation rules
# ---------------------------------------------------------------------------

def add_traffic_rule(
    rule_type: str,
    action: dict,
    match_host: str | None = None,
    match_path: str | None = None,
    match_url: str | None = None,
    description: str | None = None,
) -> int:
    """Add a traffic manipulation rule. Returns rule ID."""
    now = datetime.now(timezone.utc)
    conn = _get_conn()
    with _lock:
        result = conn.execute(
            """INSERT INTO traffic_rules
                   (rule_type, match_host, match_path, match_url,
                    action, description, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, TRUE, ?) RETURNING id""",
            [rule_type, match_host, match_path, match_url,
             json.dumps(action), description, now],
        )
        row = result.fetchone()
    return row[0] if row else 0


def get_traffic_rules(enabled_only: bool = True) -> list[dict]:
    """List traffic manipulation rules."""
    if enabled_only:
        rows = _query(
            "SELECT * FROM traffic_rules WHERE enabled = TRUE ORDER BY created_at DESC"
        )
    else:
        rows = _query("SELECT * FROM traffic_rules ORDER BY created_at DESC")
    for r in rows:
        if isinstance(r.get("action"), str):
            try:
                r["action"] = json.loads(r["action"])
            except (json.JSONDecodeError, TypeError):
                pass
    return rows


def remove_traffic_rule(rule_id: int) -> bool:
    """Remove a traffic rule by ID."""
    rows = _query("SELECT id FROM traffic_rules WHERE id = ?", [rule_id])
    if not rows:
        return False
    _execute("DELETE FROM traffic_rules WHERE id = ?", [rule_id])
    return True


def toggle_traffic_rule(rule_id: int, enabled: bool) -> bool:
    """Enable or disable a traffic rule."""
    rows = _query("SELECT id FROM traffic_rules WHERE id = ?", [rule_id])
    if not rows:
        return False
    _execute("UPDATE traffic_rules SET enabled = ? WHERE id = ?", [enabled, rule_id])
    return True


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def close():
    """Flush all buffers and close the connection."""
    global _conn
    _flush_buffer()
    _flush_ws_buffer()
    if _conn is not None:
        with _lock:
            _conn.close()
            _conn = None


# Flush on process exit
atexit.register(close)

# Auto-init on import
init_db()
