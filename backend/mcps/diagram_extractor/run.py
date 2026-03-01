import base64
import mimetypes
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.mistral_client import call_vision
from backend.mcps.common.types import build_tool_result


MAX_IMAGE_BYTES = 10 * 1024 * 1024
DEFAULT_VISION_MODEL = "mistral-large-latest"


def run(image_path: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    context = context or {}
    path = Path(image_path)
    errors: List[Dict[str, Any]] = []

    if not path.exists():
        errors.append({"error": "image_not_found", "path": image_path})
        return build_tool_result("DiagramExtractor", {}, [], {}, errors)

    if path.stat().st_size > MAX_IMAGE_BYTES:
        errors.append({"error": "image_too_large", "max_bytes": MAX_IMAGE_BYTES})
        return build_tool_result("DiagramExtractor", {}, [], {}, errors)

    mime_type = mimetypes.guess_type(path.name)[0] or "image/png"
    image_b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    data_url = f"data:{mime_type};base64,{image_b64}"

    prompt = _build_prompt(context)
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": data_url}},
            ],
        }
    ]

    schema = {
        "required": [
            "components",
            "data_stores",
            "connections",
            "entry_points",
            "trust_zones",
            "secrets_locations",
            "confidence",
        ]
    }

    result = call_vision(
        model=DEFAULT_VISION_MODEL,
        messages_with_image=messages,
        json_schema=schema,
    )

    if not result.get("ok"):
        errors.append({"error": "vision_failed", "detail": result.get("error")})
        return build_tool_result("DiagramExtractor", {}, [], {}, errors)

    artifacts = _normalize_artifacts(result.get("data", {}))
    evidence = _build_evidence(result.get("data", {}), path)
    signals = _signals_from_artifacts(artifacts)

    return build_tool_result(
        tool_name="DiagramExtractor",
        artifacts=artifacts,
        evidence=evidence,
        signals=signals,
        errors=errors,
    )


def _build_prompt(context: Dict[str, Any]) -> str:
    return (
        "You are analyzing an architecture diagram image. "
        "Return strict JSON with: components[] (name, type: api/db/cache/queue/ui), "
        "data_stores[], connections[] (from, to, protocol), entry_points[], "
        "trust_zones[] (public/private/internal), secrets_locations[]. "
        "If unsure, set confidence low. Do not invent components not visible. "
        "Also include extracted_text[] if any labels are visible.\n\n"
        f"Context: {context}"
    )


def _normalize_artifacts(data: Dict[str, Any]) -> Dict[str, Any]:
    components = data.get("components", []) or []
    normalized = []
    for comp in components:
        name = str(comp.get("name", "unknown")).strip()
        comp_type = str(comp.get("type", "unknown")).strip().lower()
        norm_name = _normalize_name(name)
        prefix = _type_prefix(comp_type)
        comp_id = f"{prefix}:{norm_name}" if norm_name else f"{prefix}:unknown"
        normalized.append({
            "id": comp_id,
            "name": name,
            "type": comp_type,
            "confidence": comp.get("confidence", "low"),
        })

    data_stores = data.get("data_stores", []) or []
    connections = data.get("connections", []) or []

    return {
        "components": normalized,
        "data_stores": data_stores,
        "connections": connections,
        "entry_points": data.get("entry_points", []) or [],
        "trust_zones": data.get("trust_zones", []) or [],
        "secrets_locations": data.get("secrets_locations", []) or [],
        "confidence": data.get("confidence", "low"),
        "extracted_text": data.get("extracted_text", []) or [],
    }


def _build_evidence(data: Dict[str, Any], path: Path) -> List[Dict[str, Any]]:
    text = data.get("extracted_text", []) or []
    if not text:
        return []
    return [
        {
            "id": "e_diagram_text",
            "kind": "image_text",
            "file_path": str(path),
            "line": 0,
            "snippet": "\n".join(text)[:1200],
            "note": "Text extracted from diagram",
        }
    ]


def _signals_from_artifacts(artifacts: Dict[str, Any]) -> Dict[str, Any]:
    signals: Dict[str, Any] = {}
    if artifacts.get("entry_points"):
        signals["entry_points"] = artifacts["entry_points"]
    if artifacts.get("trust_zones"):
        signals["trust_zones"] = artifacts["trust_zones"]
    if artifacts.get("secrets_locations"):
        signals["secrets_locations"] = artifacts["secrets_locations"]
    return signals


def _normalize_name(value: str) -> str:
    return value.strip().lower().replace(" ", "-")


def _type_prefix(comp_type: str) -> str:
    if comp_type in {"db", "database"}:
        return "db"
    if comp_type in {"api", "service"}:
        return "svc"
    if comp_type in {"queue", "mq"}:
        return "queue"
    if comp_type in {"cache"}:
        return "cache"
    if comp_type in {"ui", "frontend"}:
        return "ui"
    return "svc"