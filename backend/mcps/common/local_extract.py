"""Local-first extraction helper used before LLM calls."""

from __future__ import annotations

from typing import Any, Callable, Dict, List


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
        merged[key] = _merge_values(base.get(key, {}), overlay.get(key, {}), key=key)
    merged["evidence"] = [
        *base.get("evidence", []),
        *overlay.get("evidence", []),
    ]
    merged.pop("needs_llm", None)
    return merged


def _merge_values(base: Any, overlay: Any, key: str = "") -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = dict(base)
        for child_key, child_value in overlay.items():
            if child_key in out:
                out[child_key] = _merge_values(
                    out[child_key], child_value, key=child_key
                )
            else:
                out[child_key] = child_value
        return out

    if isinstance(base, list) and isinstance(overlay, list):
        if key in {"endpoints", "endpoint_guess"}:
            return _merge_endpoints(base, overlay)
        return _merge_lists(base, overlay)

    return overlay


def _merge_lists(base: List[Any], overlay: List[Any]) -> List[Any]:
    out = list(base)
    for item in overlay:
        if item not in out:
            out.append(item)
    return out


def _merge_endpoints(base: List[Any], overlay: List[Any]) -> List[str]:
    merged = [str(item) for item in _merge_lists(base, overlay) if str(item).strip()]
    best_by_tail: Dict[str, str] = {}

    for endpoint in merged:
        endpoint = endpoint.strip()
        tail = endpoint.rsplit("/", 1)[-1]
        existing = best_by_tail.get(tail)
        if not existing:
            best_by_tail[tail] = endpoint
            continue
        existing_depth = existing.count("/")
        endpoint_depth = endpoint.count("/")
        if endpoint_depth > existing_depth or (
            endpoint_depth == existing_depth and len(endpoint) > len(existing)
        ):
            best_by_tail[tail] = endpoint

    ordered: List[str] = []
    seen = set()
    for endpoint in merged:
        tail = endpoint.rsplit("/", 1)[-1]
        chosen = best_by_tail.get(tail, endpoint)
        if chosen not in seen:
            ordered.append(chosen)
            seen.add(chosen)

    return ordered
