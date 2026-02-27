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
