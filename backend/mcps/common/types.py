"""Shared helpers for Phase 4 MCP output formatting."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def build_tool_result(
    tool_name: str,
    artifacts: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    signals: Dict[str, Any],
    errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "tool_name": tool_name,
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
        "errors": errors or None,
    }