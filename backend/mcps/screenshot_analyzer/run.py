import base64
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.local_extract import local_first
from backend.mcps.common.mistral_client import call_ocr, call_text, call_vision
from backend.mcps.common.types import build_tool_result


MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 1600
DEFAULT_OCR_MODEL = os.environ.get("MISTRAL_OCR_MODEL", "mistral-ocr-latest")
DEFAULT_TEXT_MODEL = os.environ.get("MISTRAL_TEXT_MODEL", "mistral-large-latest")
DEFAULT_VISION_MODEL = os.environ.get("MISTRAL_VISION_MODEL", "mistral-large-latest")
VISION_FIRST = os.environ.get("MISTRAL_VISION_FIRST", "").strip() in {"1", "true", "TRUE", "yes", "YES"}


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

    processed_path, metadata, prep_errors = _prepare_image(path)
    errors.extend(prep_errors)

    if VISION_FIRST:
        vision_result = _vision_extract(processed_path, context)
        if vision_result.get("ok"):
            artifacts = vision_result.get("data", {})
            evidence = _build_vision_evidence(processed_path, artifacts)
            signals = _signals_from_artifacts(artifacts)
            artifacts["metadata"] = metadata
            return build_tool_result(
                tool_name="ScreenshotAnalyzer",
                artifacts=artifacts,
                evidence=evidence,
                signals=signals,
                errors=errors,
            )

        errors.append({"error": "vision_failed", "detail": vision_result.get("error")})
        return build_tool_result(
            tool_name="ScreenshotAnalyzer",
            artifacts={"metadata": metadata},
            evidence=[],
            signals={},
            errors=errors,
        )

    ocr_result = call_ocr(image_path=str(processed_path), model=DEFAULT_OCR_MODEL)
    if not ocr_result.get("ok"):
        vision_result = _vision_extract(processed_path, context)
        if vision_result.get("ok"):
            artifacts = vision_result.get("data", {})
            evidence = _build_vision_evidence(processed_path, artifacts)
            signals = _signals_from_artifacts(artifacts)
            artifacts["metadata"] = metadata
            return build_tool_result(
                tool_name="ScreenshotAnalyzer",
                artifacts=artifacts,
                evidence=evidence,
                signals=signals,
                errors=errors,
            )

        errors.append({"error": "ocr_failed", "detail": ocr_result.get("error")})
        errors.append({"error": "vision_failed", "detail": vision_result.get("error")})
        return build_tool_result(
            tool_name="ScreenshotAnalyzer",
            artifacts={"metadata": metadata},
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
            artifacts["metadata"] = metadata
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
        artifacts["metadata"] = metadata

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
                "file_path": str(processed_path),
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
        data["metadata"] = metadata

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


def _prepare_image(path: Path) -> Tuple[Path, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Convert to PNG and resize if needed. Returns processed path + metadata + errors.
    """
    errors: List[Dict[str, Any]] = []
    metadata = {
        "original_path": str(path),
        "original_bytes": path.stat().st_size if path.exists() else 0,
        "original_suffix": path.suffix.lower(),
    }

    try:
        from PIL import Image  # type: ignore
    except Exception:
        errors.append({"error": "image_processing_unavailable", "detail": "Pillow not installed"})
        return path, metadata, errors

    try:
        with Image.open(path) as img:
            metadata["original_size"] = img.size
            width, height = img.size
            scale = min(1.0, MAX_IMAGE_DIMENSION / max(width, height))
            if scale < 1.0:
                new_size = (int(width * scale), int(height * scale))
                img = img.resize(new_size)
                metadata["resized"] = True
                metadata["resized_size"] = new_size
            else:
                metadata["resized"] = False
                metadata["resized_size"] = (width, height)

            output_path = path.with_name(f"{path.stem}_normalized.png")
            img.convert("RGB").save(output_path, format="PNG")
            metadata["processed_path"] = str(output_path)
            return output_path, metadata, errors
    except Exception as exc:
        errors.append({"error": "image_processing_failed", "detail": str(exc)})
        return path, metadata, errors


def _vision_extract(image_path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
    image_b64 = base64.b64encode(image_path.read_bytes()).decode("ascii")
    data_url = f"data:image/png;base64,{image_b64}"
    prompt = _build_prompt(ocr_text="", context=context)
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
    return call_vision(
        model=DEFAULT_VISION_MODEL,
        messages_with_image=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }
        ],
        json_schema=schema,
    )


def _build_vision_evidence(image_path: Path, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "id": "e_vision_result",
            "kind": "screenshot",
            "file_path": str(image_path),
            "line": 0,
            "snippet": "\n".join(artifacts.get("visible_messages", [])[:5]),
            "note": "Vision model extracted screenshot details",
        }
    ]


def _extract_entities(text: str) -> Tuple[List[str], List[str], List[str]]:
    url_pattern = r"https?://[^\s'\"]+"
    urls = re.findall(url_pattern, text)

    host_pattern = r"\b([a-zA-Z0-9.-]+\.(com|net|org|io|internal|local))\b"
    hosts = [match[0] for match in re.findall(host_pattern, text)]

    # Match only path starts (not inner segments like "/generate-report" inside "/api/generate-report")
    endpoint_pattern = r"(?<![A-Za-z0-9_])/[A-Za-z0-9_\-/.]+"
    endpoints = re.findall(endpoint_pattern, text)
    endpoints = _filter_endpoints(endpoints)

    return _dedupe(urls), _dedupe(hosts), _dedupe(endpoints)


def _extract_error_messages(text: str) -> List[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    candidates = [line for line in lines if _looks_like_error_line(line)]
    return _dedupe(candidates)[:5]


def _extract_error_codes(text: str) -> List[str]:
    codes = re.findall(r"\b[A-Z]{2,10}-\d{2,6}\b", text)
    codes += re.findall(r"\bERR_[A-Z0-9_]+\b", text)
    codes += re.findall(r"\b[45]\d{2}\b", text)
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
        "api_key": r"\bsk-[A-Za-z0-9]{8,}\b",
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


def _filter_endpoints(endpoints: List[str]) -> List[str]:
    filtered = []
    for ep in endpoints:
        if ep.endswith((".py", ".js", ".ts")):
            continue
        if "API_URL" in ep or ep.startswith("/OPENAI"):
            continue
        filtered.append(ep)
    return filtered
