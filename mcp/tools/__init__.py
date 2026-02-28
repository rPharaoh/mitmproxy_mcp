"""
Tool modules for the LLMProxy MCP server.

Each sub-module defines a ``register(mcp, helpers)`` function that receives
the FastMCP instance and a dict of shared helpers (_json, _tid, etc.) and
registers its tools via ``@mcp.tool()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# All tool modules in registration order
_MODULES = [
    "tools.traffic",
    "tools.security",
    "tools.websocket",
    "tools.api_mapping",
    "tools.debugging",
    "tools.privacy",
    "tools.monitoring",
    "tools.control",
    "tools.admin",
    "tools.fuzzing",
    "tools.scanning",
    "tools.recon",
]


def register_all(mcp: "FastMCP", helpers: dict) -> None:
    """Import every tool module and call its ``register()`` function."""
    import importlib

    for mod_name in _MODULES:
        mod = importlib.import_module(mod_name)
        mod.register(mcp, helpers)
