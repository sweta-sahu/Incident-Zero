import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.local_extract import local_first
from backend.mcps.common.mistral_client import call_ocr, call_text
from backend.mcps.common.types import build_tool_result


MAX_IMAGE_BYTES = 10 * 1024 * 1024
DEFAULT_OCR_MODEL = os.environ.get("MISTRAL_OCR_MODEL", "mistral-ocr-latest")
DEFAULT_TEXT_MODEL = os.environ.get("MISTRAL_TEXT_MODEL", "mistral-large-latest")


def run(
    image_path: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Analyze a screenshot using local extraction + Mistral OCR + text model.

    Returns Phase 4 ToolResult:
      tool_name, artifacts, evidence, signals, errors
    """
    context = context or {}
    path = Path(image_path)
    errors: List[Dict[str, Any]] = []

    if not path.exists():
        errors.append({"error": "image_not_found", "path": image_path})
        return build_tool_result(
            tool_name="ScreenshotAnalyzer",
            artifacts={},
            evidence=[],
            signals={},
            errors=errors,
        )

    if path.stat().st_size > MAX_IMAGE_BYTES:
        errors.append({"error": "image_too_large", "max_bytes": MAX_IMAGE_BYTES})
        return build_tool_result(
            tool_name="ScreenshotAnalyzer",
            artifacts={},
            evidence=[],
            signals={},
            errors=errors,
        )

    ocr_result = call_ocr(image_path=str(path), model=DEFAULT_OCR_MODEL)
    if not ocr_result.get("ok"):
        errors.append({"error": "ocr_failed", "detail": ocr_result.get("error")})
        return build_tool_result(
            tool_name="ScreenshotAnalyzer",
            artifacts={},
            evidence=[],
            signals={},
            errors=errors,
        )

    text_blocks = ocr_result.get("data", {}).get("text_blocks", [])
    ocr_text = "\n".join(text_blocks).strip()

    def local_extract() -> Dict[str, Any]:
        artifacts = {
            "visible_messages": [],
            "error_codes": [],
            "stack_trace_seen": False,
            "possible_secret_exposure": [],
            "entities": {"urls": [], "hosts": [], "endpoints": []},
            "confidence": 0.2,
        }
        evidence = []
        signals = {}

        if not ocr_text:
            return {
                "artifacts": artifacts,
                "evidence": evidence,
                "signals": signals,
                "needs_llm": False,
            }

        urls, hosts, endpoints = _extract_entities(ocr_text)
        secrets = _detect_secrets(ocr_text)

        artifacts["entities"] = {
            "urls": urls,
            "hosts": hosts,
            "endpoints": endpoints,
        }
        artifacts["possible_secret_exposure"] = secrets
        artifacts["stack_trace_seen"] = _looks_like_stack_trace(ocr_text)
        artifacts["visible_messages"] = _extract_error_messages(ocr_text)
        artifacts["error_codes"] = _extract_error_codes(ocr_text)
        artifacts["confidence"] = 0.35

        if secrets:
            signals["secret_exposure_detected"] = True

        if endpoints:
            signals["endpoint_guess"] = endpoints[:3]

        if artifacts["visible_messages"]:
            signals["error_message"] = artifacts["visible_messages"][0]

        evidence.append(
            {
                "id": "e_ocr_text",
                "kind": "ocr",
                "file_path": str(path),
                "line": 0,
                "snippet": _trim_text(ocr_text, 1200),
                "note": "OCR text extracted from screenshot",
            }
        )

        return {
            "artifacts": artifacts,
            "evidence": evidence,
            "signals": signals,
            "needs_llm": True,
        }

    def llm_extract(local_payload: Dict[str, Any]) -> Dict[str, Any]:
        prompt = _build_prompt(ocr_text=ocr_text, context=context)
        schema = {
            "required": [
                "visible_messages",
                "error_codes",
                "stack_trace_seen",
                "possible_secret_exposure",
                "entities",
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
        data["possible_secret_exposure"] = _mask_secrets_list(
            data.get("possible_secret_exposure", [])
        )

        return {
            "artifacts": data,
            "evidence": [],
            "signals": _signals_from_artifacts(data),
        }

    combined = local_first(local_extract, llm_extract)

    errors.extend(combined.pop("errors", []) or [])
    artifacts = combined.get("artifacts", {})
    evidence = combined.get("evidence", [])
    signals = combined.get("signals", {})

    if artifacts.get("possible_secret_exposure"):
        signals["secret_exposure_detected"] = True

    return build_tool_result(
        tool_name="ScreenshotAnalyzer",
        artifacts=artifacts,
        evidence=evidence,
        signals=signals,
        errors=errors,
    )


def _build_prompt(ocr_text: str, context: Dict[str, Any]) -> str:
    return (
        "You are a security analyst. Interpret OCR text from a screenshot. "
        "Return strict JSON with: visible_messages[], error_codes[], "
        "stack_trace_seen (true/false), possible_secret_exposure[] (type + example masked), "
        "entities {urls[], hosts[], endpoints[]}, confidence (0-1). "
        "Mask secrets: show only first/last 2 chars.\n\n"
        f"Context: {context}\n\n"
        f"OCR Text:\n{_trim_text(ocr_text, 4000)}"
    )


def _extract_entities(text: str) -> Tuple[List[str], List[str], List[str]]:
    url_pattern = r"https?://[^\s'\"]+"
    urls = re.findall(url_pattern, text)

    host_pattern = r"\b([a-zA-Z0-9.-]+\.(com|net|org|io|internal|local))\b"
    hosts = [match[0] for match in re.findall(host_pattern, text)]

    endpoint_pattern = r"\b/[A-Za-z0-9_./-]+"
    endpoints = re.findall(endpoint_pattern, text)

    return _dedupe(urls), _dedupe(hosts), _dedupe(endpoints)


def _extract_error_messages(text: str) -> List[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    candidates = [line for line in lines if _looks_like_error_line(line)]
    return _dedupe(candidates)[:5]


def _extract_error_codes(text: str) -> List[str]:
    codes = re.findall(r"\b[A-Z]{2,10}-\d{2,6}\b", text)
    codes += re.findall(r"\bERR_[A-Z0-9_]+\b", text)
    return _dedupe(codes)[:5]


def _looks_like_error_line(line: str) -> bool:
    return any(
        token in line.lower()
        for token in ["error", "exception", "failed", "traceback", "fatal"]
    )


def _looks_like_stack_trace(text: str) -> bool:
    return "traceback" in text.lower() or "exception" in text.lower()


def _detect_secrets(text: str) -> List[Dict[str, str]]:
    patterns = {
        "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
        "github_token": r"\bghp_[A-Za-z0-9]{36,}\b",
        "stripe_key": r"\b(sk_live|sk_test)_[A-Za-z0-9]{20,}\b",
        "generic_token": r"\b[A-Za-z0-9_\-]{24,}\b",
    }
    findings = []
    for key, pattern in patterns.items():
        for match in re.findall(pattern, text):
            findings.append({"type": key, "example": _mask_secret(match)})
    return findings


def _mask_secrets_list(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    masked = []
    for item in items:
        example = item.get("example", "")
        masked.append({
            **item,
            "example": _mask_secret(example) if example else example,
        })
    return masked


def _mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 4:
        return value
    return f"{value[:2]}***{value[-2:]}"


def _signals_from_artifacts(artifacts: Dict[str, Any]) -> Dict[str, Any]:
    signals: Dict[str, Any] = {}
    messages = artifacts.get("visible_messages") or []
    if messages:
        signals["error_message"] = messages[0]

    entities = artifacts.get("entities") or {}
    if entities.get("endpoints"):
        signals["endpoint_guess"] = entities.get("endpoints")[:3]

    if artifacts.get("possible_secret_exposure"):
        signals["secret_exposure_detected"] = True

    return signals


def _trim_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result