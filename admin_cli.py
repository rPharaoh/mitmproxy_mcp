#!/usr/bin/env python3
"""
LLMProxy Admin CLI — manage API tokens for multi-tenant auth.

Usage (Docker):
    docker compose exec mcp python admin_cli.py create "My App"
    docker compose exec mcp python admin_cli.py list
    docker compose exec mcp python admin_cli.py revoke <token>

Usage (local):
    LLMPROXY_ES_URL=http://localhost:9200 python admin_cli.py create "My App"

Environment:
    LLMPROXY_ES_URL   Elasticsearch URL (default: http://elasticsearch:9200)
"""

from __future__ import annotations

import argparse
import json
import sys

import storage.db as db


def cmd_create(args: argparse.Namespace) -> None:
    """Create a new API token."""
    result = db.create_token(args.name)
    print()
    print("Token created successfully!")
    print(f"  Name:      {result['name']}")
    print(f"  Token:     {result['token']}")
    print(f"  Tenant ID: {result['tenant_id']}")
    print()
    print("Save the token now — it cannot be retrieved later.")
    print()
    print("MCP client config (SSE with auth):")
    print(json.dumps({
        "mcpServers": {
            "llmproxy": {
                "url": "http://localhost:8000/sse?token=" + result["token"]
            }
        }
    }, indent=2))
    print()
    print("Proxy config (use token as username, any password):")
    print(f"  http://{result['token']}:x@localhost:8080")


def cmd_list(args: argparse.Namespace) -> None:
    """List all tokens."""
    tokens = db.list_tokens()
    if not tokens:
        print("No tokens found.")
        return

    # Column widths
    name_w = max(len(t.get("name", "")) for t in tokens)
    name_w = max(name_w, 4)  # min header width

    print(f"{'NAME':<{name_w}}  {'TOKEN':<13}  {'TENANT ID':<34}  {'ACTIVE':<6}  CREATED")
    print(f"{'─' * name_w}  {'─' * 13}  {'─' * 34}  {'─' * 6}  {'─' * 20}")
    for t in tokens:
        name = t.get("name", "")
        token_masked = t.get("token", "???")
        tenant_id = t.get("tenant_id", "")
        active = "yes" if t.get("active", False) else "no"
        created = t.get("created_at", "")[:19].replace("T", " ")
        print(f"{name:<{name_w}}  {token_masked:<13}  {tenant_id:<34}  {active:<6}  {created}")

    print(f"\n{len(tokens)} token(s) total")


def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a token."""
    if db.revoke_token(args.token):
        print(f"Token revoked successfully.")
    else:
        print(f"Token not found or already revoked.", file=sys.stderr)
        sys.exit(1)


def cmd_clear(args: argparse.Namespace) -> None:
    """Clear all captured data for a tenant."""
    if args.no_tenant:
        tenant = None
    elif args.tenant:
        tenant = args.tenant
    else:
        print("Error: provide a tenant ID or use --no-tenant to clear orphaned data.", file=sys.stderr)
        sys.exit(1)
    label = tenant or "<no tenant (unassigned)>"
    if not args.yes:
        answer = input(f"Delete ALL data for {label}? [y/N] ")
        if answer.lower() not in ("y", "yes"):
            print("Aborted.")
            return
    result = db.clear_tenant_data(tenant)
    deleted = sum(v for v in result.values() if isinstance(v, int))
    print(f"Cleared {deleted} documents across {len(result)} indices.")
    for idx, count in result.items():
        print(f"  {idx}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="admin_cli",
        description="LLMProxy Admin CLI — manage API tokens and data",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new API token")
    p_create.add_argument("name", help="Human-readable label for the token (e.g. app name or user)")
    p_create.set_defaults(func=cmd_create)

    # list
    p_list = sub.add_parser("list", help="List all tokens (masked)")
    p_list.set_defaults(func=cmd_list)

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a token")
    p_revoke.add_argument("token", help="Full token string to revoke")
    p_revoke.set_defaults(func=cmd_revoke)

    # clear
    p_clear = sub.add_parser("clear", help="Clear all captured data for a tenant")
    p_clear.add_argument("tenant", nargs="?", default=None, help="Tenant ID to clear data for")
    p_clear.add_argument("--no-tenant", action="store_true", help="Clear data with no tenant assigned (orphaned data)")
    p_clear.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_clear.set_defaults(func=cmd_clear)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
