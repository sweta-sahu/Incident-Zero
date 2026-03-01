import os
import json
import logging
import time
import base64
from typing import Any, Dict, List, Optional

import requests


logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRIES = 2
DEFAULT_BASE_URL = "https://api.mistral.ai/v1"
DEFAULT_OCR_PATH = "/ocr"


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
    Call Mistral OCR endpoint. Expects image_path on disk.

    The endpoint can be overridden via MISTRAL_OCR_URL. If not provided,
    it uses MISTRAL_API_BASE + /ocr.
    """
    api_key = os.environ.get("MISTRAL_API_KEY", "").strip()
    if not api_key:
        return _safe_error("MISTRAL_API_KEY not set")

    base_url = os.environ.get("MISTRAL_API_BASE", DEFAULT_BASE_URL).rstrip("/")
    ocr_url = os.environ.get("MISTRAL_OCR_URL", f"{base_url}{DEFAULT_OCR_PATH}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            # Read and encode image as base64
            with open(image_path, "rb") as handle:
                image_data = base64.standard_b64encode(handle.read()).decode("utf-8")
            
            # Mistral OCR API expects 'document' field with base64 image
            payload = {
                "model": model,
                "document": {
                    "type": "image_url",
                    "image_url": f"data:image/png;base64,{image_data}",
                },
            }
            response = requests.post(
                ocr_url, headers=headers, json=payload, timeout=timeout_seconds
            )
            if response.status_code >= 400:
                last_error = f"HTTP {response.status_code}: {response.text}"
                logger.warning("Mistral OCR error: %s", last_error)
            else:
                raw = response.json()
                text_blocks = _extract_ocr_text(raw)
                return {
                    "ok": True,
                    "data": {"text_blocks": text_blocks, "raw": raw},
                    "error": None,
                    "raw": raw,
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

    base_url = os.environ.get("MISTRAL_API_BASE", DEFAULT_BASE_URL).rstrip("/")
    url = f"{base_url}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
    }

    logger.debug("Mistral request model=%s", model)

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
            if response.status_code >= 400:
                last_error = f"HTTP {response.status_code}: {response.text}"
                logger.warning("Mistral error: %s", last_error)
            else:
                raw = response.json()
                content = _extract_content(raw)
                parsed = _parse_json(content)
                if parsed is None:
                    return _safe_error("Model response is not valid JSON", raw=raw)
                if json_schema and not _validate_minimal_schema(parsed, json_schema):
                    return _safe_error("Response failed minimal schema validation", raw=raw)
                return {
                    "ok": True,
                    "data": parsed,
                    "error": None,
                    "raw": raw,
                }
        except Exception as exc:
            last_error = str(exc)
            logger.warning("Mistral request failed: %s", last_error)

        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    return _safe_error(last_error or "Unknown error")


def _extract_content(raw: Dict[str, Any]) -> str:
    try:
        return raw["choices"][0]["message"]["content"]
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
        for block in page.get("blocks", []) if isinstance(page, dict) else []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                blocks.append(block["text"])

    if not blocks and isinstance(raw.get("content"), str):
        blocks.append(raw["content"])

    return blocks


def _parse_json(content: str) -> Optional[Dict[str, Any]]:
    if not content:
        return None
    try:
        return json.loads(content)
    except Exception:
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
