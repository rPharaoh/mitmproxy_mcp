"""Traffic control tools: domain blocking and traffic rules."""

from __future__ import annotations

import json

import db


def register(mcp, helpers):
    _json = helpers["_json"]
    _tid = helpers["_tid"]

    @mcp.tool()
    def block_domain(domain: str, reason: str | None = None) -> str:
        """Add a domain to the proxy block list. Future requests will be rejected with 403."""
        added = db.add_blocked_domain(domain, reason, tenant_id=_tid())
        status = "blocked" if added else "already_blocked"
        return _json({"status": status, "domain": domain})

    @mcp.tool()
    def unblock_domain(domain: str) -> str:
        """Remove a domain from the proxy block list."""
        removed = db.remove_blocked_domain(domain, tenant_id=_tid())
        status = "unblocked" if removed else "not_found"
        return _json({"status": status, "domain": domain})

    @mcp.tool()
    def list_blocked_domains() -> str:
        """List all currently blocked domains."""
        rows = db.get_all_blocked_domains(tenant_id=_tid())
        return _json({"count": len(rows), "domains": rows})

    @mcp.tool()
    def tag_request(request_id: int, tag: str) -> str:
        """Add a descriptive tag/label to a captured request for later reference."""
        tag_id = db.add_tag(request_id, tag, tenant_id=_tid())
        return _json({"status": "tagged", "tag_id": tag_id})

    @mcp.tool()
    def get_request_tags(request_id: int) -> str:
        """Get all tags attached to a specific request."""
        tags = db.get_tags_for_request(request_id, tenant_id=_tid())
        return _json({"request_id": request_id, "tags": tags})

    @mcp.tool()
    def create_traffic_rule(
        rule_type: str,
        action: str,
        match_host: str | None = None,
        match_path: str | None = None,
        match_url: str | None = None,
        description: str | None = None,
    ) -> str:
        """Create a traffic manipulation rule. The proxy applies it in real time.

        rule_type (one of):
          inject_request_header  — action: {"header": "X-Custom", "value": "test"}
          inject_response_header — action: {"header": "X-Frame-Options", "value": "DENY"}
          throttle               — action: {"delay_ms": 2000}
          block_pattern          — action: {"status": 403, "body": "Blocked"}
          modify_response_body   — action: {"find": "old", "replace": "new"}

        match_host/match_path/match_url: glob patterns (* = wildcard) to filter which requests the rule applies to.
        """
        try:
            action_dict = json.loads(action) if isinstance(action, str) else action
        except json.JSONDecodeError:
            return _json({"error": "action must be valid JSON"})
        rule_id = db.add_traffic_rule(
            rule_type=rule_type, action=action_dict,
            match_host=match_host, match_path=match_path,
            match_url=match_url, description=description,
            tenant_id=_tid(),
        )
        return _json({"status": "created", "rule_id": rule_id})

    @mcp.tool()
    def list_traffic_rules(include_disabled: bool = False) -> str:
        """List all active traffic manipulation rules."""
        rules = db.get_traffic_rules(enabled_only=not include_disabled, tenant_id=_tid())
        return _json({"count": len(rules), "rules": rules})

    @mcp.tool()
    def remove_traffic_rule(rule_id: int) -> str:
        """Remove a traffic manipulation rule by ID."""
        removed = db.remove_traffic_rule(rule_id, tenant_id=_tid())
        return _json({"status": "removed" if removed else "not_found", "rule_id": rule_id})

    @mcp.tool()
    def toggle_traffic_rule(rule_id: int, enabled: bool) -> str:
        """Enable or disable a traffic rule without deleting it."""
        toggled = db.toggle_traffic_rule(rule_id, enabled, tenant_id=_tid())
        return _json({"status": "updated" if toggled else "not_found",
                      "rule_id": rule_id, "enabled": enabled})
