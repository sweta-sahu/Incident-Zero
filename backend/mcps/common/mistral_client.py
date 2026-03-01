import base64
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from mistralai import Mistral


logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRIES = 2


def call_text(
    model: str,
    messages: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """
    Call Mistral text model with basic retry and JSON validation.

    Returns:
      {
        "ok": bool,
        "data": dict,
        "error": str | None,
        "raw": dict | None,
      }
    """
    return _call_chat(
        model=model,
        messages=messages,
        json_schema=json_schema,
        timeout_seconds=timeout_seconds,
        retries=retries,
    )


def call_vision(
    model: str,
    messages_with_image: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """
    Call Mistral vision-capable model with basic retry and JSON validation.

    The messages payload should already include image content as required
    by the target model.
    """
    return _call_chat(
        model=model,
        messages=messages_with_image,
        json_schema=json_schema,
        timeout_seconds=timeout_seconds,
        retries=retries,
    )


def call_ocr(
    image_path: str,
    model: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """
    Call Mistral OCR endpoint via the official SDK. Expects image_path on disk.
    """
    api_key = os.environ.get("MISTRAL_API_KEY", "").strip()
    if not api_key:
        return _safe_error("MISTRAL_API_KEY not set")

    client = Mistral(api_key=api_key)

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            with open(image_path, "rb") as handle:
                image_data = base64.standard_b64encode(handle.read()).decode("utf-8")

            data_url = f"data:image/png;base64,{image_data}"
            raw = client.ocr.process(
                model=model,
                document={
                    "type": "image_url",
                    "image_url": {"url": data_url},
                },
            )

            raw_dict = _to_dict(raw)
            text_blocks = _extract_ocr_text(raw_dict)
            return {
                "ok": True,
                "data": {"text_blocks": text_blocks, "raw": raw_dict},
                "error": None,
                "raw": raw_dict,
            }
        except Exception as exc:
            last_error = str(exc)
            logger.warning("Mistral OCR request failed: %s", last_error)

        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    return _safe_error(last_error or "Unknown error")


def _call_chat(
    model: str,
    messages: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]],
    timeout_seconds: int,
    retries: int,
) -> Dict[str, Any]:
    api_key = os.environ.get("MISTRAL_API_KEY", "").strip()
    if not api_key:
        return _safe_error("MISTRAL_API_KEY not set")

    client = Mistral(api_key=api_key)

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            raw = client.chat.complete(
                model=model,
                messages=messages,
            )

            raw_dict = _to_dict(raw)
            content = _extract_content(raw_dict)
            parsed = _parse_json(content)
            if parsed is None:
                return _safe_error("Model response is not valid JSON", raw=raw_dict)
            if json_schema and not _validate_minimal_schema(parsed, json_schema):
                return _safe_error("Response failed minimal schema validation", raw=raw_dict)
            return {
                "ok": True,
                "data": parsed,
                "error": None,
                "raw": raw_dict,
            }
        except Exception as exc:
            last_error = str(exc)
            logger.warning("Mistral request failed: %s", last_error)

        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    return _safe_error(last_error or "Unknown error")


def _extract_content(raw: Dict[str, Any]) -> str:
    try:
        content = raw["choices"][0]["message"]["content"]
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            return "\n".join(parts)
        return str(content)
    except Exception:
        return ""


def _extract_ocr_text(raw: Dict[str, Any]) -> List[str]:
    """
    Normalize OCR response into list of text blocks.
    Handles common OCR response shapes.
    """
    if not raw:
        return []

    if isinstance(raw.get("text"), str):
        return [raw["text"]]

    blocks = []
    pages = raw.get("pages") or raw.get("page_results") or []
    for page in pages:
        if isinstance(page, dict) and isinstance(page.get("text"), str):
            blocks.append(page["text"])
        if isinstance(page, dict) and isinstance(page.get("markdown"), str):
            blocks.append(page["markdown"])
        for block in page.get("blocks", []) if isinstance(page, dict) else []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                blocks.append(block["text"])

    if not blocks and isinstance(raw.get("content"), str):
        blocks.append(raw["content"])

    return blocks


def _parse_json(content: str) -> Optional[Dict[str, Any]]:
    if not content:
        return None

    text = content.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced_match:
        try:
            parsed = json.loads(fenced_match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    candidate = _extract_first_json_object(text)
    if candidate:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return None


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(text)):
        ch = text[idx]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return None


def _validate_minimal_schema(payload: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    required = schema.get("required", []) if isinstance(schema, dict) else []
    for key in required:
        if key not in payload:
            return False
    return True


def _safe_error(message: str, raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "ok": False,
        "data": {},
        "error": message,
        "raw": raw,
    }


def _to_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "model_dump_json"):
        return json.loads(value.model_dump_json())
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {"raw": value}