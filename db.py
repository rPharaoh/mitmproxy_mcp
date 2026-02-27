"""
Shared database module for LLMProxy.
Uses Elasticsearch for high-throughput, concurrent traffic capture and search.
Both containers (proxy + MCP server) connect to the same Elasticsearch instance.

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
from typing import Any

from elasticsearch import Elasticsearch, NotFoundError, ConflictError
from elasticsearch.helpers import bulk

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ES_URL = os.environ.get("LLMPROXY_ES_URL", "http://elasticsearch:9200")
ES_REQUEST_TIMEOUT = int(os.environ.get("LLMPROXY_ES_TIMEOUT", "30"))

# Indices
IDX_REQUESTS = "llmproxy-requests"
IDX_WS = "llmproxy-websocket"
IDX_BLOCKED = "llmproxy-blocked"
IDX_TAGS = "llmproxy-tags"
IDX_RULES = "llmproxy-rules"

# Write buffer config
_FLUSH_SIZE = int(os.environ.get("LLMPROXY_FLUSH_SIZE", "100"))
_FLUSH_INTERVAL = float(os.environ.get("LLMPROXY_FLUSH_INTERVAL", "1.0"))

# Kept for backward compatibility (proxy_addon references it)
DB_PATH = ES_URL

# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

_es: Elasticsearch | None = None
_lock = threading.Lock()


def _get_es() -> Elasticsearch:
    """Return a singleton Elasticsearch client (thread-safe)."""
    global _es
    if _es is None:
        with _lock:
            if _es is None:
                _es = Elasticsearch(
                    ES_URL,
                    request_timeout=ES_REQUEST_TIMEOUT,
                    max_retries=5,
                    retry_on_timeout=True,
                )
    return _es


def _wait_for_es(max_wait: int = 60) -> None:
    """Block until Elasticsearch is reachable (for container startup)."""
    es = _get_es()
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            if es.ping():
                return
        except Exception:
            pass
        time.sleep(1)
    raise ConnectionError(f"Elasticsearch not reachable at {ES_URL} after {max_wait}s")


# ---------------------------------------------------------------------------
# Index mappings
# ---------------------------------------------------------------------------

_REQUESTS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":        {"type": "date"},
            "method":           {"type": "keyword"},
            "url":              {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 2048}}},
            "host":             {"type": "keyword"},
            "path":             {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 2048}}},
            "port":             {"type": "integer"},
            "scheme":           {"type": "keyword"},
            "request_headers":  {"type": "object", "enabled": False},
            "request_body":     {"type": "text"},
            "status_code":      {"type": "integer"},
            "response_headers": {"type": "object", "enabled": False},
            "response_body":    {"type": "text"},
            "content_type":     {"type": "keyword"},
            "content_length":   {"type": "long"},
            "duration_ms":      {"type": "double"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "1s"},
}

_WS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":      {"type": "date"},
            "flow_id":        {"type": "keyword"},
            "host":           {"type": "keyword"},
            "url":            {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 2048}}},
            "direction":      {"type": "keyword"},
            "message_type":   {"type": "keyword"},
            "content":        {"type": "text"},
            "content_length": {"type": "long"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "1s"},
}

_BLOCKED_MAPPING = {
    "mappings": {
        "properties": {
            "domain":     {"type": "keyword"},
            "reason":     {"type": "text"},
            "created_at": {"type": "date"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}

_TAGS_MAPPING = {
    "mappings": {
        "properties": {
            "request_id": {"type": "keyword"},
            "tag":        {"type": "keyword"},
            "created_at": {"type": "date"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}

_RULES_MAPPING = {
    "mappings": {
        "properties": {
            "rule_type":   {"type": "keyword"},
            "match_host":  {"type": "keyword"},
            "match_path":  {"type": "keyword"},
            "match_url":   {"type": "keyword"},
            "action":      {"type": "object", "enabled": False},
            "description": {"type": "text"},
            "enabled":     {"type": "boolean"},
            "created_at":  {"type": "date"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}


def init_db():
    """Create Elasticsearch indices if they don't exist."""
    _wait_for_es()
    es = _get_es()
    for idx, mapping in [
        (IDX_REQUESTS, _REQUESTS_MAPPING),
        (IDX_WS, _WS_MAPPING),
        (IDX_BLOCKED, _BLOCKED_MAPPING),
        (IDX_TAGS, _TAGS_MAPPING),
        (IDX_RULES, _RULES_MAPPING),
    ]:
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx, body=mapping)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hit_to_dict(hit: dict) -> dict:
    """Convert an ES hit to a flat dict with 'id' field."""
    d = hit["_source"]
    d["id"] = hit["_id"]
    return d


def _search(index: str, body: dict, size: int = 100) -> list[dict]:
    """Run an ES search and return list of dicts."""
    es = _get_es()
    resp = es.search(index=index, body=body, size=min(size, 10000))
    return [_hit_to_dict(h) for h in resp["hits"]["hits"]]


def _count(index: str, body: dict | None = None) -> int:
    es = _get_es()
    if body:
        return es.count(index=index, body=body)["count"]
    return es.count(index=index)["count"]


def _refresh(index: str) -> None:
    """Force refresh so writes are immediately searchable."""
    _get_es().indices.refresh(index=index)


# ---------------------------------------------------------------------------
# Write buffer – batches proxy inserts for throughput
# ---------------------------------------------------------------------------

_buffer: list[dict] = []
_buffer_lock = threading.Lock()
_flush_timer: threading.Timer | None = None


def _flush_buffer() -> None:
    """Flush the in-memory buffer to Elasticsearch in a single bulk request."""
    global _flush_timer
    with _buffer_lock:
        if not _buffer:
            _flush_timer = None
            return
        batch = _buffer.copy()
        _buffer.clear()
        _flush_timer = None

    if not batch:
        return

    actions = [{"_index": IDX_REQUESTS, "_source": doc} for doc in batch]
    try:
        bulk(_get_es(), actions, refresh=False)
    except Exception:
        pass  # best-effort; don't crash the proxy


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
    doc = {
        "timestamp": _now_iso(),
        "method": method,
        "url": url,
        "host": host,
        "path": path,
        "port": port,
        "scheme": scheme,
        "request_headers": request_headers,
        "request_body": request_body,
        "status_code": status_code,
        "response_headers": response_headers,
        "response_body": response_body,
        "content_type": content_type,
        "content_length": content_length,
        "duration_ms": duration_ms,
    }
    with _buffer_lock:
        _buffer.append(doc)
        buf_len = len(_buffer)

    if buf_len >= _FLUSH_SIZE:
        _flush_buffer()
    else:
        _schedule_flush()

    return 0


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
) -> str:
    """Insert a single request immediately. Returns document ID."""
    doc = {
        "timestamp": _now_iso(),
        "method": method, "url": url, "host": host, "path": path,
        "port": port, "scheme": scheme,
        "request_headers": request_headers, "request_body": request_body,
        "status_code": status_code,
        "response_headers": response_headers, "response_body": response_body,
        "content_type": content_type, "content_length": content_length,
        "duration_ms": duration_ms,
    }
    es = _get_es()
    resp = es.index(index=IDX_REQUESTS, body=doc, refresh="wait_for")
    return resp["_id"]


def is_domain_blocked(domain: str) -> tuple[bool, str | None]:
    """Check whether a domain is on the block list."""
    es = _get_es()
    resp = es.search(
        index=IDX_BLOCKED,
        body={"query": {"term": {"domain": domain}}},
        size=1,
    )
    hits = resp["hits"]["hits"]
    if hits:
        return True, hits[0]["_source"].get("reason")
    return False, None


def add_blocked_domain(domain: str, reason: str | None = None) -> bool:
    """Add a domain to the block list. Returns True if newly added."""
    es = _get_es()
    # Use domain as doc ID to enforce uniqueness
    doc_id = f"block-{domain}"
    try:
        es.create(
            index=IDX_BLOCKED, id=doc_id,
            body={"domain": domain, "reason": reason, "created_at": _now_iso()},
            refresh="wait_for",
        )
        return True
    except ConflictError:
        return False


def remove_blocked_domain(domain: str) -> bool:
    """Remove a domain from the block list."""
    es = _get_es()
    doc_id = f"block-{domain}"
    try:
        es.delete(index=IDX_BLOCKED, id=doc_id, refresh="wait_for")
        return True
    except NotFoundError:
        return False


# ---------------------------------------------------------------------------
# Query helpers (used by the MCP server)
# ---------------------------------------------------------------------------

def _parse_json_cols(d: dict) -> dict:
    """Headers are already dicts from ES -- this is kept for API compatibility."""
    return d


def get_recent_requests(
    limit: int = 25,
    method: str | None = None,
    host: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
) -> list[dict]:
    """Return recent requests with optional filters."""
    _flush_buffer()
    must: list[dict] = []
    if method:
        must.append({"term": {"method": method.upper()}})
    if host:
        must.append({"wildcard": {"host": f"*{host.lower()}*"}})
    if status_code is not None:
        must.append({"term": {"status_code": status_code}})
    if search:
        must.append({"wildcard": {"url.raw": f"*{search}*"}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "query": query,
        "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "method", "url", "host", "status_code",
                     "content_type", "content_length", "duration_ms"],
    }
    return _search(IDX_REQUESTS, body, size=min(limit, 200))


def get_request_by_id(request_id: str | int) -> dict | None:
    """Return full details of a single request by ES document ID."""
    _flush_buffer()
    es = _get_es()
    try:
        resp = es.get(index=IDX_REQUESTS, id=str(request_id))
        return _hit_to_dict(resp)
    except NotFoundError:
        return None


def get_domain_summary(limit: int = 30) -> list[dict]:
    """Aggregate traffic stats per domain."""
    _flush_buffer()
    body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {"field": "host", "size": limit, "order": {"_count": "desc"}},
                "aggs": {
                    "methods": {"terms": {"field": "method", "size": 10}},
                    "avg_duration": {"avg": {"field": "duration_ms"}},
                    "total_bytes": {"sum": {"field": "content_length"}},
                    "first_seen": {"min": {"field": "timestamp"}},
                    "last_seen": {"max": {"field": "timestamp"}},
                }
            }
        }
    }
    es = _get_es()
    resp = es.search(index=IDX_REQUESTS, body=body)
    results = []
    for bucket in resp["aggregations"]["by_host"]["buckets"]:
        methods = [m["key"] for m in bucket["methods"]["buckets"]]
        results.append({
            "host": bucket["key"],
            "total_requests": bucket["doc_count"],
            "distinct_methods": len(methods),
            "methods": ",".join(methods),
            "avg_duration_ms": bucket["avg_duration"]["value"],
            "total_bytes": bucket["total_bytes"]["value"],
            "first_seen": bucket["first_seen"]["value_as_string"],
            "last_seen": bucket["last_seen"]["value_as_string"],
        })
    return results


def get_traffic_stats() -> dict:
    """Return overall traffic statistics."""
    _flush_buffer()
    body = {
        "size": 0,
        "aggs": {
            "unique_hosts": {"cardinality": {"field": "host"}},
            "distinct_methods": {"cardinality": {"field": "method"}},
            "avg_duration": {"avg": {"field": "duration_ms"}},
            "total_bytes": {"sum": {"field": "content_length"}},
            "earliest": {"min": {"field": "timestamp"}},
            "latest": {"max": {"field": "timestamp"}},
            "errors": {"filter": {"range": {"status_code": {"gte": 400}}}},
            "success": {"filter": {"range": {"status_code": {"gte": 200, "lt": 300}}}},
        }
    }
    es = _get_es()
    resp = es.search(index=IDX_REQUESTS, body=body)
    aggs = resp["aggregations"]
    return {
        "total_requests": resp["hits"]["total"]["value"],
        "unique_hosts": aggs["unique_hosts"]["value"],
        "distinct_methods": aggs["distinct_methods"]["value"],
        "avg_duration_ms": aggs["avg_duration"]["value"],
        "total_bytes": aggs["total_bytes"]["value"],
        "earliest": aggs["earliest"]["value_as_string"] if aggs["earliest"]["value"] else None,
        "latest": aggs["latest"]["value_as_string"] if aggs["latest"]["value"] else None,
        "errors": aggs["errors"]["doc_count"],
        "success": aggs["success"]["doc_count"],
    }


def find_errors(limit: int = 50) -> list[dict]:
    """Find requests with HTTP error status codes (4xx/5xx)."""
    _flush_buffer()
    body = {
        "query": {"range": {"status_code": {"gte": 400}}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "method", "url", "host", "status_code",
                     "content_type", "duration_ms"],
    }
    return _search(IDX_REQUESTS, body, size=limit)


def search_requests(
    pattern: str,
    field: str = "url",
    limit: int = 50,
) -> list[dict]:
    """Search requests by pattern on a given field."""
    allowed_fields = {"url", "host", "path", "request_body", "response_body", "content_type"}
    if field not in allowed_fields:
        raise ValueError(f"field must be one of {allowed_fields}")
    _flush_buffer()

    # Keyword fields use wildcard; text fields use match_phrase
    if field in ("host", "content_type"):
        q = {"wildcard": {field: f"*{pattern}*"}}
    elif field in ("url", "path"):
        q = {"wildcard": {f"{field}.raw": f"*{pattern}*"}}
    else:
        q = {"match_phrase": {field: pattern}}

    body = {
        "query": q,
        "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "method", "url", "host", "status_code",
                     "content_type", "content_length", "duration_ms"],
    }
    return _search(IDX_REQUESTS, body, size=limit)


def get_all_blocked_domains() -> list[dict]:
    """Return all blocked domains."""
    body = {"query": {"match_all": {}}, "sort": [{"created_at": "desc"}]}
    return _search(IDX_BLOCKED, body, size=1000)


def add_tag(request_id: str | int, tag: str) -> str:
    """Tag a request. Returns tag doc ID."""
    es = _get_es()
    doc = {"request_id": str(request_id), "tag": tag, "created_at": _now_iso()}
    resp = es.index(index=IDX_TAGS, body=doc, refresh="wait_for")
    return resp["_id"]


def get_tags_for_request(request_id: str | int) -> list[str]:
    """Return tags for a request."""
    body = {"query": {"term": {"request_id": str(request_id)}}}
    hits = _search(IDX_TAGS, body, size=100)
    return [h["tag"] for h in hits]


# ---------------------------------------------------------------------------
# WebSocket write buffer
# ---------------------------------------------------------------------------

_ws_buffer: list[dict] = []
_ws_buffer_lock = threading.Lock()
_ws_flush_timer: threading.Timer | None = None


def _flush_ws_buffer() -> None:
    """Flush WebSocket message buffer to Elasticsearch."""
    global _ws_flush_timer
    with _ws_buffer_lock:
        if not _ws_buffer:
            _ws_flush_timer = None
            return
        batch = _ws_buffer.copy()
        _ws_buffer.clear()
        _ws_flush_timer = None

    if not batch:
        return

    actions = [{"_index": IDX_WS, "_source": doc} for doc in batch]
    try:
        bulk(_get_es(), actions, refresh=False)
    except Exception:
        pass


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
    doc = {
        "timestamp": _now_iso(),
        "flow_id": flow_id, "host": host, "url": url,
        "direction": direction, "message_type": message_type,
        "content": content, "content_length": content_length,
    }
    with _ws_buffer_lock:
        _ws_buffer.append(doc)
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
    body = {
        "size": 0,
        "aggs": {
            "by_flow": {
                "terms": {"field": "flow_id", "size": limit, "order": {"last_msg": "desc"}},
                "aggs": {
                    "host": {"terms": {"field": "host", "size": 1}},
                    "url": {"top_hits": {"size": 1, "_source": ["url"]}},
                    "sent": {"filter": {"term": {"direction": "send"}}},
                    "received": {"filter": {"term": {"direction": "receive"}}},
                    "total_bytes": {"sum": {"field": "content_length"}},
                    "first_msg": {"min": {"field": "timestamp"}},
                    "last_msg": {"max": {"field": "timestamp"}},
                }
            }
        }
    }
    es = _get_es()
    resp = es.search(index=IDX_WS, body=body)
    results = []
    for b in resp["aggregations"]["by_flow"]["buckets"]:
        results.append({
            "flow_id": b["key"],
            "host": b["host"]["buckets"][0]["key"] if b["host"]["buckets"] else "",
            "url": b["url"]["hits"]["hits"][0]["_source"]["url"] if b["url"]["hits"]["hits"] else "",
            "total_messages": b["doc_count"],
            "sent": b["sent"]["doc_count"],
            "received": b["received"]["doc_count"],
            "total_bytes": b["total_bytes"]["value"],
            "first_message": b["first_msg"]["value_as_string"],
            "last_message": b["last_msg"]["value_as_string"],
        })
    return results


def get_ws_messages(
    flow_id: str | None = None,
    host: str | None = None,
    direction: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return WebSocket messages with optional filters."""
    _flush_ws_buffer()
    must: list[dict] = []
    if flow_id:
        must.append({"term": {"flow_id": flow_id}})
    if host:
        must.append({"wildcard": {"host": f"*{host.lower()}*"}})
    if direction:
        must.append({"term": {"direction": direction}})
    if search:
        must.append({"match_phrase": {"content": search}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {"query": query, "sort": [{"timestamp": "desc"}]}
    return _search(IDX_WS, body, size=min(limit, 500))


def get_ws_stats() -> dict:
    """Return overall WebSocket statistics."""
    _flush_ws_buffer()
    body = {
        "size": 0,
        "aggs": {
            "total_connections": {"cardinality": {"field": "flow_id"}},
            "unique_hosts": {"cardinality": {"field": "host"}},
            "total_bytes": {"sum": {"field": "content_length"}},
            "sent": {"filter": {"term": {"direction": "send"}}},
            "received": {"filter": {"term": {"direction": "receive"}}},
            "earliest": {"min": {"field": "timestamp"}},
            "latest": {"max": {"field": "timestamp"}},
        }
    }
    es = _get_es()
    resp = es.search(index=IDX_WS, body=body)
    aggs = resp["aggregations"]
    return {
        "total_messages": resp["hits"]["total"]["value"],
        "total_connections": aggs["total_connections"]["value"],
        "unique_hosts": aggs["unique_hosts"]["value"],
        "total_bytes": aggs["total_bytes"]["value"],
        "sent": aggs["sent"]["doc_count"],
        "received": aggs["received"]["doc_count"],
        "earliest": aggs["earliest"]["value_as_string"] if aggs["earliest"]["value"] else None,
        "latest": aggs["latest"]["value_as_string"] if aggs["latest"]["value"] else None,
    }


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
        elif re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', seg, re.I
        ):
            normalized.append("{uuid}")
        elif re.fullmatch(r'[0-9a-f]{24}', seg, re.I):
            normalized.append("{objectId}")
        else:
            normalized.append(seg)
    return "/".join(normalized)


def get_api_map(host: str | None = None, limit: int = 100) -> list[dict]:
    """Map discovered API endpoints grouped by normalized path."""
    _flush_buffer()
    must: list[dict] = []
    if host:
        must.append({"wildcard": {"host": f"*{host.lower()}*"}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}

    body = {
        "query": query,
        "sort": [{"timestamp": "desc"}],
        "_source": ["host", "path", "method", "status_code", "duration_ms", "timestamp"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit * 5, 5000))

    endpoints: dict[str, dict] = {}
    for row in rows:
        norm = _normalize_path(row.get("path") or "")
        key = f"{row.get('host', '')}|{norm}"
        if key not in endpoints:
            endpoints[key] = {
                "host": row.get("host", ""),
                "path": norm,
                "original_paths": set(),
                "methods": set(),
                "status_codes": set(),
                "total_hits": 0,
                "avg_duration_ms": [],
                "first_seen": row.get("timestamp", ""),
                "last_seen": row.get("timestamp", ""),
            }
        ep = endpoints[key]
        ep["original_paths"].add(row.get("path", ""))
        ep["methods"].add(row.get("method", ""))
        sc = row.get("status_code")
        if sc is not None:
            ep["status_codes"].add(sc)
        ep["total_hits"] += 1
        d = row.get("duration_ms")
        if d is not None:
            ep["avg_duration_ms"].append(d)
        ts = row.get("timestamp", "")
        if ts < ep["first_seen"]:
            ep["first_seen"] = ts
        if ts > ep["last_seen"]:
            ep["last_seen"] = ts

    result = []
    for ep in sorted(endpoints.values(), key=lambda e: e["total_hits"], reverse=True)[:limit]:
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
    body = {
        "query": {"bool": {"must": [
            {"wildcard": {"host": f"*{host.lower()}*"}},
            {"wildcard": {"path.raw": f"*{path}*"}},
        ]}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "method", "url", "host", "path",
                     "status_code", "content_type", "content_length", "duration_ms"],
    }
    return _search(IDX_REQUESTS, body, size=limit)


# ---------------------------------------------------------------------------
# Live feed -- poll-based stream of traffic
# ---------------------------------------------------------------------------

def get_live_feed(
    after_id: str | int | None = None,
    after_ws_id: str | int | None = None,
    include_bodies: bool = False,
    limit: int = 100,
) -> dict:
    """Return new HTTP requests and WebSocket messages since given cursors.

    Uses timestamp-based cursors for pagination.
    """
    _flush_buffer()
    _flush_ws_buffer()
    cap = min(limit, 500)

    source_fields = None if include_bodies else [
        "timestamp", "method", "url", "host", "status_code",
        "content_type", "content_length", "duration_ms",
    ]

    if after_id is not None:
        body = {
            "query": {"range": {"timestamp": {"gt": str(after_id)}}},
            "sort": [{"timestamp": "asc"}],
        }
        if source_fields:
            body["_source"] = source_fields
        http_rows = _search(IDX_REQUESTS, body, size=cap)
    else:
        body = {"query": {"match_all": {}}, "sort": [{"timestamp": "desc"}]}
        if source_fields:
            body["_source"] = source_fields
        http_rows = _search(IDX_REQUESTS, body, size=cap)
        http_rows.reverse()

    new_http_cursor = http_rows[-1]["timestamp"] if http_rows else after_id

    if after_ws_id is not None:
        ws_body = {
            "query": {"range": {"timestamp": {"gt": str(after_ws_id)}}},
            "sort": [{"timestamp": "asc"}],
        }
        ws_rows = _search(IDX_WS, ws_body, size=cap)
    else:
        ws_body = {"query": {"match_all": {}}, "sort": [{"timestamp": "desc"}]}
        ws_rows = _search(IDX_WS, ws_body, size=cap)
        ws_rows.reverse()

    new_ws_cursor = ws_rows[-1]["timestamp"] if ws_rows else after_ws_id

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
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "desc"}],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 2000))
    findings: list[dict] = []

    for row in rows:
        rid, url = row.get("id", ""), row.get("url") or ""
        path = row.get("path") or ""
        resp_body = row.get("response_body") or ""
        req_body = row.get("request_body") or ""
        resp_h = row.get("response_headers") or {}
        if not isinstance(resp_h, dict):
            resp_h = {}

        if _VULN_SQL_RE.search(resp_body):
            findings.append({"type": "sql_error_leak", "severity": "high",
                             "request_id": rid, "url": url,
                             "detail": "SQL error in response -- possible injection"})
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
        server_h = resp_h.get("server", resp_h.get("Server", ""))
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
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["url", "host", "method", "request_body", "response_body"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 2000))
    findings: list[dict] = []
    for row in rows:
        rid, url = row.get("id", ""), row.get("url") or ""
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
                        "samples": [
                            str(m)[:20] + "..." if len(str(m)) > 20 else str(m)
                            for m in unique
                        ],
                    })
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    return {"total_scanned": len(rows), "findings_count": len(findings),
            "by_type": by_type, "findings": findings}


def extract_session_tokens(limit: int = 300) -> dict:
    """Extract authentication tokens, session cookies, and API keys from traffic."""
    _flush_buffer()
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["url", "host", "request_headers", "response_headers"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 1000))
    tokens: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        rid, host = row.get("id", ""), row.get("host") or ""
        req_h = row.get("request_headers") or {}
        resp_h = row.get("response_headers") or {}

        for k, v in req_h.items():
            if k.lower() in _AUTH_HEADERS and v:
                key = f"h:{k}:{v[:30]}"
                if key not in seen:
                    seen.add(key)
                    tokens.append({"type": "auth_header", "header": k,
                                   "value": v[:80] + ("..." if len(v) > 80 else ""),
                                   "host": host, "request_id": rid})

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
                            tokens.append({
                                "type": "session_cookie", "name": name.strip(),
                                "value": val[:60] + ("..." if len(val) > 60 else ""),
                                "host": host, "request_id": rid,
                            })

        for k, v in resp_h.items():
            if k.lower() == "set-cookie" and v:
                key = f"sc:{host}:{v[:40]}"
                if key not in seen:
                    seen.add(key)
                    tokens.append({
                        "type": "set_cookie",
                        "value": v[:120] + ("..." if len(v) > 120 else ""),
                        "host": host, "request_id": rid,
                    })

    return {"total_scanned": len(rows), "tokens_found": len(tokens), "tokens": tokens}


def detect_session_issues(limit: int = 500) -> dict:
    """Detect session anomalies: cross-host cookies, missing CSRF, insecure flags."""
    _flush_buffer()
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["url", "host", "method", "request_headers", "response_headers"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 1000))
    issues: list[dict] = []
    session_hosts: dict[str, set[str]] = {}

    for row in rows:
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

        if row.get("method") in ("POST", "PUT", "DELETE", "PATCH"):
            ct = req_h.get("content-type", req_h.get("Content-Type", "")).lower()
            if "form" in ct:
                has_csrf = any(
                    k.lower() in ("x-csrf-token", "x-xsrf-token") for k in req_h
                )
                if not has_csrf:
                    issues.append({
                        "type": "missing_csrf", "severity": "medium",
                        "request_id": row.get("id"), "url": row.get("url"),
                        "detail": "Form POST without CSRF token",
                    })

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
                    issues.append({
                        "type": "insecure_cookie", "severity": "medium",
                        "request_id": row.get("id"), "host": host,
                        "cookie": cname, "missing_flags": missing_flags,
                        "detail": f"Cookie '{cname}' missing: {', '.join(missing_flags)}",
                    })

    for cookie_key, hosts in session_hosts.items():
        if len(hosts) > 1:
            issues.append({
                "type": "cross_host_session", "severity": "high",
                "cookie": cookie_key[:50] + "...", "hosts": sorted(hosts),
                "detail": f"Session cookie used across {len(hosts)} hosts",
            })

    return {"total_scanned": len(rows), "issues_count": len(issues), "issues": issues}


def detect_c2_patterns(limit: int = 1000) -> dict:
    """Detect potential C2 beaconing patterns and encoded payloads."""
    _flush_buffer()
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "asc"}],
        "_source": ["host", "timestamp", "url", "method", "content_type", "content_length"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 5000))
    findings: list[dict] = []

    by_host: dict[str, list[dict]] = {}
    for r in rows:
        by_host.setdefault(r.get("host", ""), []).append(r)

    for host, reqs in by_host.items():
        if len(reqs) < 5:
            continue
        timestamps = []
        for r in reqs:
            ts = r.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    continue
            if ts:
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

    for r in rows:
        url = r.get("url") or ""
        if "?" in url:
            query = url.split("?", 1)[1]
            if len(query) > 200 and re.search(r'[A-Za-z0-9+/=]{100,}', query):
                findings.append({
                    "type": "encoded_payload", "severity": "medium",
                    "host": r.get("host"), "url": url[:200],
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
    body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {
                    "field": "host",
                    "size": min(limit, 500),
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "methods": {"terms": {"field": "method", "size": 10}},
                    "total_bytes": {"sum": {"field": "content_length"}},
                    "first_seen": {"min": {"field": "timestamp"}},
                    "last_seen": {"max": {"field": "timestamp"}},
                    "errors": {"filter": {"range": {"status_code": {"gte": 400}}}},
                }
            }
        }
    }
    es = _get_es()
    resp = es.search(index=IDX_REQUESTS, body=body)
    results = []
    for b in resp["aggregations"]["by_host"]["buckets"]:
        host = b["key"]
        methods = ", ".join(m["key"] for m in b["methods"]["buckets"])
        row = {
            "host": host,
            "total_requests": b["doc_count"],
            "total_bytes": b["total_bytes"]["value"],
            "methods": methods,
            "first_seen": b["first_seen"]["value_as_string"],
            "last_seen": b["last_seen"]["value_as_string"],
            "errors": b["errors"]["doc_count"],
        }
        if _AD_PATTERN.search(host):
            row["category"] = "advertising/tracking"
        elif _SOCIAL_PATTERN.search(host):
            row["category"] = "social_media"
        elif _CDN_PATTERN.search(host):
            row["category"] = "cdn/static"
        else:
            row["category"] = "other"
        results.append(row)
    return {"total_domains": len(results), "domains": results}


def analyze_cookies_in_traffic(limit: int = 300) -> dict:
    """Parse and categorize all cookies from Set-Cookie headers."""
    _flush_buffer()
    body = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": "desc"}],
        "_source": ["host", "request_headers", "response_headers"],
    }
    rows = _search(IDX_REQUESTS, body, size=min(limit, 1000))
    cookies_map: dict[str, dict] = {}
    for row in rows:
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

            ckey = f"{host}:{name}"
            if ckey not in cookies_map:
                name_l = name.lower()
                if any(s in name_l for s in ("session", "sid", "auth", "login")):
                    category = "session"
                elif any(s in name_l for s in (
                    "track", "analytics", "_ga", "_gid", "_fbp", "pixel"
                )):
                    category = "tracking"
                elif any(s in name_l for s in ("csrf", "xsrf")):
                    category = "csrf"
                elif any(s in name_l for s in ("pref", "lang", "theme", "consent")):
                    category = "preference"
                else:
                    category = "other"
                cookies_map[ckey] = {
                    "name": name, "host": host, "category": category,
                    "secure": "secure" in flags, "httponly": "httponly" in flags,
                    "samesite": flags.get("samesite", "not set"),
                    "path": flags.get("path", "/"),
                    "max_age": flags.get("max-age"),
                    "seen_count": 0,
                    "sample_value": val[:40] + ("..." if len(val) > 40 else ""),
                }
            cookies_map[ckey]["seen_count"] += 1

    cookies = sorted(cookies_map.values(), key=lambda c: c["seen_count"], reverse=True)
    by_cat: dict[str, int] = {}
    for c in cookies:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    return {"total_cookies": len(cookies), "by_category": by_cat, "cookies": cookies}


# ---------------------------------------------------------------------------
# Debugging & development
# ---------------------------------------------------------------------------

def compare_requests(id1: str | int, id2: str | int) -> dict:
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
    must: list[dict] = []
    if host:
        must.append({"wildcard": {"host": f"*{host.lower()}*"}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}

    body = {
        "query": query,
        "sort": [{"timestamp": "desc"}],
        "_source": ["host", "path", "method", "status_code", "content_type",
                     "request_headers", "request_body", "response_headers", "response_body"],
    }
    rows = _search(IDX_REQUESTS, body, size=2000)

    hosts_seen: set[str] = set()
    paths_spec: dict[str, dict] = {}
    for row in rows:
        h = row.get("host", "")
        hosts_seen.add(h)
        norm = _normalize_path(row.get("path", ""))
        method = (row.get("method") or "GET").lower()
        status = str(row.get("status_code") or 200)
        ct = row.get("content_type") or "application/json"

        if norm not in paths_spec:
            paths_spec[norm] = {}
        if method not in paths_spec[norm]:
            paths_spec[norm][method] = {
                "summary": f"{(row.get('method') or 'GET').upper()} {norm}",
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
    es = _get_es()

    # Slow endpoints
    slow_body = {
        "size": 0,
        "aggs": {
            "by_endpoint": {
                "multi_terms": {
                    "terms": [
                        {"field": "host"},
                        {"field": "path.raw"},
                        {"field": "method"},
                    ],
                    "size": min(limit, 100),
                    "order": {"avg_dur": "desc"},
                },
                "aggs": {
                    "avg_dur": {"avg": {"field": "duration_ms"}},
                    "max_dur": {"max": {"field": "duration_ms"}},
                    "p95_dur": {"percentiles": {"field": "duration_ms", "percents": [95]}},
                }
            }
        }
    }
    slow_resp = es.search(index=IDX_REQUESTS, body=slow_body)
    slow = []
    for b in slow_resp["aggregations"]["by_endpoint"]["buckets"]:
        if b["doc_count"] >= 2:
            slow.append({
                "host": b["key"][0], "path": b["key"][1], "method": b["key"][2],
                "hits": b["doc_count"],
                "avg_ms": b["avg_dur"]["value"],
                "max_ms": b["max_dur"]["value"],
                "p95_ms": b["p95_dur"]["values"].get("95.0"),
            })

    # Large payloads
    large = _search(IDX_REQUESTS, {
        "query": {"exists": {"field": "content_length"}},
        "sort": [{"content_length": "desc"}],
        "_source": ["url", "host", "method", "content_type", "content_length", "duration_ms"],
    }, size=20)

    # Redundant requests
    redundant_body = {
        "size": 0,
        "aggs": {
            "by_url_method": {
                "multi_terms": {
                    "terms": [{"field": "url.raw"}, {"field": "method"}],
                    "size": 20,
                    "min_doc_count": 4,
                    "order": {"_count": "desc"},
                }
            }
        }
    }
    red_resp = es.search(index=IDX_REQUESTS, body=redundant_body)
    redundant = [{"url": b["key"][0], "method": b["key"][1], "hits": b["doc_count"]}
                 for b in red_resp["aggregations"]["by_url_method"]["buckets"]]

    # Error-prone endpoints
    err_body = {
        "size": 0,
        "aggs": {
            "by_endpoint": {
                "multi_terms": {
                    "terms": [
                        {"field": "host"},
                        {"field": "path.raw"},
                        {"field": "method"},
                    ],
                    "size": 20,
                },
                "aggs": {
                    "errors": {"filter": {"range": {"status_code": {"gte": 400}}}},
                }
            }
        }
    }
    err_resp = es.search(index=IDX_REQUESTS, body=err_body)
    error_prone = []
    for b in err_resp["aggregations"]["by_endpoint"]["buckets"]:
        errs = b["errors"]["doc_count"]
        if errs > 0:
            error_prone.append({
                "host": b["key"][0], "path": b["key"][1], "method": b["key"][2],
                "total": b["doc_count"], "errors": errs,
                "error_rate": round(100.0 * errs / b["doc_count"], 1),
            })
    error_prone.sort(key=lambda x: x["error_rate"], reverse=True)

    return {
        "slow_endpoints": slow,
        "large_payloads": large,
        "redundant_requests": redundant,
        "error_prone_endpoints": error_prone[:20],
    }


def generate_curl_command(request_id: str | int) -> str:
    """Generate a curl command that reproduces a captured request."""
    req = get_request_by_id(request_id)
    if not req:
        return ""
    parts = [f"curl -X {req.get('method', 'GET')}"]
    parts.append(f"  '{req.get('url', '')}'")
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
    es = _get_es()

    # Status distribution
    status_body = {
        "size": 0,
        "aggs": {
            "by_status": {
                "terms": {"field": "status_code", "size": 50, "order": {"_count": "desc"}}
            }
        }
    }
    status_resp = es.search(index=IDX_REQUESTS, body=status_body)
    status_dist = [{"status_code": b["key"], "cnt": b["doc_count"]}
                   for b in status_resp["aggregations"]["by_status"]["buckets"]]

    # Timing stats
    stats_body = {
        "size": 0,
        "aggs": {
            "avg_dur": {"avg": {"field": "duration_ms"}},
            "sd_dur": {"extended_stats": {"field": "duration_ms"}},
        }
    }
    stats_resp = es.search(index=IDX_REQUESTS, body=stats_body)
    avg_d = stats_resp["aggregations"]["avg_dur"]["value"] or 0
    sd_d = stats_resp["aggregations"]["sd_dur"]["std_deviation"] or 0
    threshold = avg_d + 3 * sd_d if sd_d else avg_d * 3

    outliers = []
    if threshold > 0:
        outliers = _search(IDX_REQUESTS, {
            "query": {"range": {"duration_ms": {"gt": threshold}}},
            "sort": [{"duration_ms": "desc"}],
            "_source": ["url", "host", "method", "duration_ms", "status_code"],
        }, size=20)

    # Rare hosts
    rare_body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {"field": "host", "size": 100, "order": {"_count": "asc"}},
                "aggs": {"first_seen": {"min": {"field": "timestamp"}}},
            }
        }
    }
    rare_resp = es.search(index=IDX_REQUESTS, body=rare_body)
    rare_hosts = [{"host": b["key"], "cnt": b["doc_count"],
                   "first_seen": b["first_seen"]["value_as_string"]}
                  for b in rare_resp["aggregations"]["by_host"]["buckets"]
                  if b["doc_count"] <= 2][:30]

    # Error bursts
    err_burst_body = {
        "size": 0,
        "query": {"range": {"status_code": {"gte": 400}}},
        "aggs": {
            "by_minute": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "minute"},
                "aggs": {"hosts": {"terms": {"field": "host", "size": 5}}},
            }
        }
    }
    err_burst_resp = es.search(index=IDX_REQUESTS, body=err_burst_body)
    error_bursts = []
    for b in err_burst_resp["aggregations"]["by_minute"]["buckets"]:
        if b["doc_count"] >= 5:
            hosts = ", ".join(h["key"] for h in b["hosts"]["buckets"])
            error_bursts.append({
                "minute": b["key_as_string"],
                "error_count": b["doc_count"],
                "hosts": hosts,
            })
    error_bursts = error_bursts[-20:]

    return {
        "status_distribution": status_dist,
        "timing_outliers": {"threshold_ms": round(threshold, 1), "outliers": outliers},
        "rare_hosts": rare_hosts,
        "error_bursts": error_bursts,
    }


def summarize_activity(hours: int = 24) -> dict:
    """High-level activity summary for a given time window."""
    _flush_buffer()
    es = _get_es()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    range_q = {"range": {"timestamp": {"gte": cutoff}}}

    overview_body = {
        "size": 0,
        "query": range_q,
        "aggs": {
            "unique_hosts": {"cardinality": {"field": "host"}},
            "total_bytes": {"sum": {"field": "content_length"}},
            "avg_dur": {"avg": {"field": "duration_ms"}},
            "errors": {"filter": {"range": {"status_code": {"gte": 400}}}},
        }
    }
    ov_resp = es.search(index=IDX_REQUESTS, body=overview_body)
    ov_aggs = ov_resp["aggregations"]
    overview = {
        "total_requests": ov_resp["hits"]["total"]["value"],
        "unique_hosts": ov_aggs["unique_hosts"]["value"],
        "total_bytes": ov_aggs["total_bytes"]["value"],
        "avg_duration_ms": ov_aggs["avg_dur"]["value"],
        "errors": ov_aggs["errors"]["doc_count"],
    }

    # Top hosts
    top_hosts_body = {
        "size": 0, "query": range_q,
        "aggs": {"by_host": {
            "terms": {"field": "host", "size": 10, "order": {"_count": "desc"}},
            "aggs": {"bytes": {"sum": {"field": "content_length"}}},
        }}
    }
    th_resp = es.search(index=IDX_REQUESTS, body=top_hosts_body)
    top_hosts = [{"host": b["key"], "requests": b["doc_count"],
                  "bytes": b["bytes"]["value"]}
                 for b in th_resp["aggregations"]["by_host"]["buckets"]]

    # Top paths
    top_paths_body = {
        "size": 0, "query": range_q,
        "aggs": {"by_path": {
            "multi_terms": {
                "terms": [{"field": "host"}, {"field": "path.raw"}, {"field": "method"}],
                "size": 10, "order": {"_count": "desc"},
            }
        }}
    }
    tp_resp = es.search(index=IDX_REQUESTS, body=top_paths_body)
    top_paths = [{"host": b["key"][0], "path": b["key"][1], "method": b["key"][2],
                  "hits": b["doc_count"]}
                 for b in tp_resp["aggregations"]["by_path"]["buckets"]]

    # Hourly
    hourly_body = {
        "size": 0, "query": range_q,
        "aggs": {
            "by_hour": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "hour"}
            }
        }
    }
    hr_resp = es.search(index=IDX_REQUESTS, body=hourly_body)
    hourly = [{"hour": b["key_as_string"], "requests": b["doc_count"]}
              for b in hr_resp["aggregations"]["by_hour"]["buckets"]]

    return {
        "period_hours": hours,
        "overview": overview,
        "top_hosts": top_hosts,
        "top_paths": top_paths,
        "hourly_breakdown": hourly,
    }


def bandwidth_analysis(limit: int = 50) -> dict:
    """Identify top bandwidth consumers by host and content type."""
    _flush_buffer()
    es = _get_es()

    host_body = {
        "size": 0,
        "aggs": {"by_host": {
            "terms": {"field": "host", "size": min(limit, 100), "order": {"total": "desc"}},
            "aggs": {
                "total": {"sum": {"field": "content_length"}},
                "avg": {"avg": {"field": "content_length"}},
            }
        }}
    }
    h_resp = es.search(index=IDX_REQUESTS, body=host_body)
    by_host = [{"host": b["key"], "total_bytes": b["total"]["value"],
                "requests": b["doc_count"], "avg_bytes": b["avg"]["value"]}
               for b in h_resp["aggregations"]["by_host"]["buckets"]]

    type_body = {
        "size": 0,
        "aggs": {"by_type": {
            "terms": {"field": "content_type", "size": 20, "order": {"total": "desc"}},
            "aggs": {
                "total": {"sum": {"field": "content_length"}},
                "avg": {"avg": {"field": "content_length"}},
            }
        }}
    }
    t_resp = es.search(index=IDX_REQUESTS, body=type_body)
    by_type = [{"content_type": b["key"], "total_bytes": b["total"]["value"],
                "requests": b["doc_count"], "avg_bytes": b["avg"]["value"]}
               for b in t_resp["aggregations"]["by_type"]["buckets"]]

    largest = _search(IDX_REQUESTS, {
        "query": {"exists": {"field": "content_length"}},
        "sort": [{"content_length": "desc"}],
        "_source": ["url", "host", "content_type", "content_length"],
    }, size=20)

    total_body = {"size": 0, "aggs": {"total": {"sum": {"field": "content_length"}}}}
    total_resp = es.search(index=IDX_REQUESTS, body=total_body)
    total_bytes = total_resp["aggregations"]["total"]["value"]

    return {
        "total_bytes": total_bytes,
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
) -> str:
    """Add a traffic manipulation rule. Returns rule ID."""
    doc = {
        "rule_type": rule_type,
        "match_host": match_host, "match_path": match_path, "match_url": match_url,
        "action": action, "description": description,
        "enabled": True, "created_at": _now_iso(),
    }
    es = _get_es()
    resp = es.index(index=IDX_RULES, body=doc, refresh="wait_for")
    return resp["_id"]


def get_traffic_rules(enabled_only: bool = True) -> list[dict]:
    """List traffic manipulation rules."""
    if enabled_only:
        query = {"term": {"enabled": True}}
    else:
        query = {"match_all": {}}
    body = {"query": query, "sort": [{"created_at": "desc"}]}
    return _search(IDX_RULES, body, size=1000)


def remove_traffic_rule(rule_id: str | int) -> bool:
    """Remove a traffic rule by ID."""
    es = _get_es()
    try:
        es.delete(index=IDX_RULES, id=str(rule_id), refresh="wait_for")
        return True
    except NotFoundError:
        return False


def toggle_traffic_rule(rule_id: str | int, enabled: bool) -> bool:
    """Enable or disable a traffic rule."""
    es = _get_es()
    try:
        es.update(index=IDX_RULES, id=str(rule_id),
                  body={"doc": {"enabled": enabled}}, refresh="wait_for")
        return True
    except NotFoundError:
        return False


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def close():
    """Flush all buffers."""
    global _es
    _flush_buffer()
    _flush_ws_buffer()
    if _es is not None:
        try:
            _es.close()
        except Exception:
            pass
        _es = None


# Flush on process exit
atexit.register(close)

# Auto-init on import
init_db()
