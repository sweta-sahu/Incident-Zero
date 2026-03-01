import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.mcps.common.local_extract import local_first
from backend.mcps.common.mistral_client import call_text
from backend.mcps.common.types import build_tool_result


MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_CHUNKS = 10
DEFAULT_TEXT_MODEL = "mistral-large-latest"


ERROR_PATTERNS = [
    r"exception",
    r"traceback",
    r"panic",
    r"error",
    r"failed",
    r"500",
    r"sqlstate",
]

AUTH_PATTERNS = [
    r"401",
    r"403",
    r"unauthorized",
    r"forbidden",
    r"invalid token",
    r"jwt",
]

SUSPICIOUS_PATTERNS = [
    r"\.\./",
    r"drop table",
    r"union select",
    r"or 1=1",
    r"--",
]


def run(log_path: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    context = context or {}
    path = Path(log_path)
    errors: List[Dict[str, Any]] = []

    if not path.exists():
        errors.append({"error": "log_not_found", "path": log_path})
        return build_tool_result("LogReasoner", {}, [], {}, errors)

    if path.stat().st_size > MAX_LOG_BYTES:
        errors.append({"error": "log_too_large", "max_bytes": MAX_LOG_BYTES})
        return build_tool_result("LogReasoner", {}, [], {}, errors)

    raw_text = path.read_text(encoding="utf-8", errors="ignore")

    def local_extract() -> Dict[str, Any]:
        format_hint, messages = _parse_logs(raw_text)
        error_blocks = _extract_error_blocks(messages)
        top_messages = _top_messages(messages)
        stack_traces = _extract_stack_traces(messages)

        chunks = _select_chunks(error_blocks, stack_traces, top_messages)
        summary = _build_summary(messages, error_blocks, stack_traces)

        evidence = [
            {
                "id": f"e_log_{idx}",
                "kind": "log",
                "file_path": str(path),
                "line": 0,
                "snippet": chunk,
                "note": "Selected log chunk",
            }
            for idx, chunk in enumerate(chunks, start=1)
        ]

        signals = _signals_from_summary(summary)

        return {
            "artifacts": {
                "format": format_hint,
                "summary": summary,
                "chunks": chunks,
            },
            "evidence": evidence,
            "signals": signals,
            "needs_llm": bool(chunks),
        }

    def llm_extract(local_payload: Dict[str, Any]) -> Dict[str, Any]:
        summary = local_payload.get("artifacts", {}).get("summary", {})
        chunks = local_payload.get("artifacts", {}).get("chunks", [])
        prompt = _build_prompt(summary, chunks, context)
        schema = {
            "required": [
                "most_likely_causes",
                "related_components",
                "security_indicators",
                "user_impact_guess",
                "recommended_next_checks",
                "confidence",
            ]
        }
        result = call_text(
            model=DEFAULT_TEXT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            json_schema=schema,
        )
        if not result.get("ok"):
            return {
                "artifacts": {},
                "evidence": [],
                "signals": {},
                "errors": [{"error": "llm_failed", "detail": result.get("error")}],
            }

        data = result.get("data", {})
        return {
            "artifacts": data,
            "evidence": [],
            "signals": _signals_from_llm(data),
        }

    combined = local_first(local_extract, llm_extract)
    errors.extend(combined.pop("errors", []) or [])

    artifacts = combined.get("artifacts", {})
    evidence = combined.get("evidence", [])
    signals = combined.get("signals", {})

    return build_tool_result(
        tool_name="LogReasoner",
        artifacts=artifacts,
        evidence=evidence,
        signals=signals,
        errors=errors,
    )


def _parse_logs(raw_text: str) -> Tuple[str, List[str]]:
    lines = [line for line in raw_text.splitlines() if line.strip()]
    json_lines = []
    plain_lines = []

    for line in lines:
        try:
            obj = json.loads(line)
            msg = _extract_message(obj)
            if msg:
                json_lines.append(msg)
        except Exception:
            plain_lines.append(line)

    if json_lines and not plain_lines:
        return "json", json_lines
    if json_lines:
        return "mixed", json_lines + plain_lines
    return "text", plain_lines


def _extract_message(obj: Dict[str, Any]) -> str:
    for key in ("message", "msg", "log", "error", "event"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return json.dumps(obj)[:400]


def _extract_error_blocks(messages: List[str]) -> List[str]:
    blocks = []
    current: List[str] = []
    for line in messages:
        if _matches_any(line, ERROR_PATTERNS):
            current.append(line)
        elif current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def _extract_stack_traces(messages: List[str]) -> List[str]:
    traces = []
    current: List[str] = []
    for line in messages:
        if "traceback" in line.lower() or "exception" in line.lower():
            current.append(line)
        elif current and (line.startswith(" ") or line.startswith("\t")):
            current.append(line)
        elif current:
            traces.append("\n".join(current))
            current = []
    if current:
        traces.append("\n".join(current))
    return traces


def _top_messages(messages: List[str]) -> List[str]:
    counter = Counter(messages)
    return [msg for msg, _ in counter.most_common(5)]


def _select_chunks(
    error_blocks: List[str],
    stack_traces: List[str],
    top_messages: List[str],
) -> List[str]:
    chunks = []
    for item in error_blocks + stack_traces + top_messages:
        if item and item not in chunks:
            chunks.append(item)
        if len(chunks) >= MAX_CHUNKS:
            break
    return chunks


def _build_summary(
    messages: List[str],
    error_blocks: List[str],
    stack_traces: List[str],
) -> Dict[str, Any]:
    total = len(messages)
    error_count = sum(1 for msg in messages if _matches_any(msg, ERROR_PATTERNS))
    auth_count = sum(1 for msg in messages if _matches_any(msg, AUTH_PATTERNS))
    suspicious_count = sum(1 for msg in messages if _matches_any(msg, SUSPICIOUS_PATTERNS))

    top_errors = error_blocks[:5]
    top_traces = stack_traces[:3]

    return {
        "total_messages": total,
        "error_messages": error_count,
        "auth_failures": auth_count,
        "suspicious_patterns": suspicious_count,
        "top_errors": top_errors,
        "top_stack_traces": top_traces,
    }


def _signals_from_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    signals: Dict[str, Any] = {}
    if summary.get("error_messages", 0) > 0:
        signals["runtime_proof"] = True
    if summary.get("auth_failures", 0) > 0:
        signals["auth_failure_detected"] = True
    if summary.get("suspicious_patterns", 0) > 0:
        signals["suspicious_log_activity"] = True
    return signals


def _signals_from_llm(data: Dict[str, Any]) -> Dict[str, Any]:
    signals: Dict[str, Any] = {}
    indicators = data.get("security_indicators") or []
    for item in indicators:
        lower = str(item).lower()
        if "sql" in lower:
            signals["sql_injection_suspected"] = True
        if "jwt" in lower or "token" in lower:
            signals["auth_issue_suspected"] = True
    return signals


def _matches_any(text: str, patterns: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(re.search(pattern, lowered) for pattern in patterns)


def _build_prompt(summary: Dict[str, Any], chunks: List[str], context: Dict[str, Any]) -> str:
    return (
        "You are a security analyst. Given log summary and chunks, "
        "return strict JSON with: most_likely_causes[], related_components[], "
        "security_indicators[], user_impact_guess, recommended_next_checks[], confidence (0-1).\n\n"
        f"Context: {context}\n\n"
        f"Summary: {json.dumps(summary)}\n\n"
        "Top Chunks:\n"
        + "\n---\n".join(chunks)
    )