"""Local-first extraction helper used before LLM calls."""

from __future__ import annotations

from typing import Any, Callable, Dict


def local_first(
    local_extract: Callable[[], Dict[str, Any]],
    llm_extract: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Run deterministic extraction first. If it sets needs_llm=False, return it.

    Expected local output shape:
      {
        "artifacts": {...},
        "evidence": [...],
        "signals": {...},
        "needs_llm": bool
      }
    """
    local_result = local_extract()
    if not local_result.get("needs_llm", False):
        return _strip_needs_llm(local_result)

    llm_result = llm_extract(local_result)
    return _merge_results(local_result, llm_result)


def _strip_needs_llm(result: Dict[str, Any]) -> Dict[str, Any]:
    if "needs_llm" in result:
        result = dict(result)
        result.pop("needs_llm", None)
    return result


def _merge_results(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key in ("artifacts", "signals"):
        merged[key] = {**base.get(key, {}), **overlay.get(key, {})}
    merged["evidence"] = [
        *base.get("evidence", []),
        *overlay.get("evidence", []),
    ]
    merged.pop("needs_llm", None)
    return merged