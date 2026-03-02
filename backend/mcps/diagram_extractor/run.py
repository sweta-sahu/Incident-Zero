import base64
import mimetypes
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.mistral_client import call_vision
from backend.mcps.common.types import build_tool_result


MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 1800
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

    processed_path, metadata, prep_errors = _prepare_image(path)
    errors.extend(prep_errors)

    mime_type = mimetypes.guess_type(processed_path.name)[0] or "image/png"
    image_b64 = base64.b64encode(processed_path.read_bytes()).decode("ascii")
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

    schema = {"required": ["components", "connections", "trust_zones"]}

    result = call_vision(
        model=DEFAULT_VISION_MODEL,
        messages_with_image=messages,
        json_schema=schema,
    )

    if not result.get("ok"):
        detail = str(result.get("error") or "")
        if "schema validation" in detail.lower():
            fallback = call_vision(
                model=DEFAULT_VISION_MODEL,
                messages_with_image=messages,
                json_schema=None,
            )
            if fallback.get("ok"):
                result = fallback
            else:
                errors.append({"error": "vision_failed", "detail": detail})
                errors.append(
                    {
                        "error": "vision_fallback_failed",
                        "detail": fallback.get("error"),
                    }
                )
                return build_tool_result("DiagramExtractor", {}, [], {}, errors)
        else:
            errors.append({"error": "vision_failed", "detail": detail})
            return build_tool_result("DiagramExtractor", {}, [], {}, errors)

    artifacts = _normalize_artifacts(result.get("data", {}))
    artifacts["metadata"] = metadata
    evidence = _build_evidence(result.get("data", {}), processed_path)
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
        "You are an architecture diagram parser. "
        "Only use what is visible in the image. "
        "Do NOT use code, logs, or assumptions. "
        "Return strict JSON with primary fields: "
        "components[] (id, name, type, zone, confidence), "
        "connections[] (from, to, protocol, confidence), "
        "trust_zones[] (name, level, confidence). "
        "Optional fields: entry_points[], data_stores[], secrets_locations[], extracted_text[], confidence. "
        "Component type must be one of: api, service, database, cache, storage, external, queue, ui, unknown. "
        "Trust level must be one of: untrusted, semi_trusted, internal, unknown. "
        "If unsure, use unknown and confidence=low. "
        "Do not invent hidden components or links.\n\n"
        f"Context: {context}"
    )


def _prepare_image(path: Path) -> Tuple[Path, Dict[str, Any], List[Dict[str, Any]]]:
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


def _normalize_artifacts(data: Dict[str, Any]) -> Dict[str, Any]:
    components = data.get("components", []) or []
    normalized_components: List[Dict[str, Any]] = []
    for comp in components:
        name = str(comp.get("name", "unknown")).strip()
        comp_type = _normalize_component_type(str(comp.get("type", "unknown")).strip().lower())
        norm_name = _normalize_name(str(comp.get("id") or name))
        prefix = _type_prefix(comp_type)
        comp_id = f"{prefix}:{norm_name}" if norm_name else f"{prefix}:unknown"
        normalized_components.append(
            {
                "id": comp_id,
                "name": name,
                "type": comp_type,
                "zone": _normalize_zone(str(comp.get("zone") or "").strip().lower()),
                "confidence": comp.get("confidence", "low"),
            }
        )

    id_set = {item["id"] for item in normalized_components}
    name_map = {_normalize_name(item["name"]): item["id"] for item in normalized_components}

    return {
        "components": normalized_components,
        "connections": _normalize_connections(data.get("connections", []) or [], id_set, name_map),
        "trust_zones": _normalize_trust_zones(data.get("trust_zones", []) or []),
        "entry_points": data.get("entry_points", []) or [],
        "data_stores": _normalize_data_stores(data.get("data_stores", []) or []),
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
    cleaned = value.strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned)
    return cleaned.strip("-")


def _normalize_component_type(value: str) -> str:
    aliases = {
        "db": "database",
        "database": "database",
        "postgres": "database",
        "postgresql": "database",
        "mysql": "database",
        "redis": "cache",
        "cache": "cache",
        "s3": "storage",
        "bucket": "storage",
        "storage": "storage",
        "api": "api",
        "gateway": "api",
        "service": "service",
        "external": "external",
        "queue": "queue",
        "mq": "queue",
        "ui": "ui",
        "frontend": "ui",
    }
    if value in {"api", "service", "database", "cache", "storage", "external", "queue", "ui"}:
        return value
    return aliases.get(value, "unknown")


def _normalize_zone(value: str) -> str:
    if not value:
        return "unknown"
    if "public" in value or "internet" in value:
        return "public"
    if "private" in value:
        return "private"
    if "internal" in value or "vpc" in value:
        return "internal"
    return "unknown"


def _normalize_trust_level(value: str) -> str:
    text = (value or "").strip().lower()
    if text in {"untrusted", "semi_trusted", "internal", "unknown"}:
        return text
    if "internet" in text or "public" in text:
        return "untrusted"
    if "semi" in text or "dmz" in text:
        return "semi_trusted"
    if "private" in text or "internal" in text or "vpc" in text:
        return "internal"
    return "unknown"


def _normalize_trust_zones(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    zones: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        raw_name = str(item.get("name") or "").strip()
        if not raw_name:
            continue
        name = _normalize_name(raw_name)
        if name in seen:
            continue
        seen.add(name)
        zones.append(
            {
                "name": name,
                "level": _normalize_trust_level(str(item.get("level") or item.get("type") or "")),
                "confidence": item.get("confidence", "low"),
            }
        )
    return zones


def _normalize_connections(
    items: List[Dict[str, Any]],
    known_component_ids: set,
    known_component_names: Dict[str, str],
) -> List[Dict[str, Any]]:
    connections: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        source = _resolve_component_ref(str(item.get("from") or ""), known_component_ids, known_component_names)
        target = _resolve_component_ref(str(item.get("to") or ""), known_component_ids, known_component_names)
        if source == "unknown" or target == "unknown":
            continue
        key = (source, target)
        if key in seen:
            continue
        seen.add(key)
        connections.append(
            {
                "from": source,
                "to": target,
                "protocol": str(item.get("protocol") or "unknown").strip().lower() or "unknown",
                "confidence": item.get("confidence", "low"),
            }
        )
    return connections


def _resolve_component_ref(
    value: str,
    known_component_ids: set,
    known_component_names: Dict[str, str],
) -> str:
    raw = value.strip()
    if not raw:
        return "unknown"
    if raw in known_component_ids:
        return raw
    name_key = _normalize_name(raw)
    if name_key in known_component_names:
        return known_component_names[name_key]
    return name_key or "unknown"


def _normalize_data_stores(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in items:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        normalized.append(
            {
                "name": name,
                "type": _normalize_component_type(str(item.get("type") or "").strip().lower()),
                "confidence": item.get("confidence", "low"),
            }
        )
    return normalized


def _type_prefix(comp_type: str) -> str:
    if comp_type in {"database"}:
        return "db"
    if comp_type in {"api", "service", "external"}:
        return "svc"
    if comp_type in {"queue"}:
        return "queue"
    if comp_type in {"cache"}:
        return "cache"
    if comp_type in {"ui"}:
        return "ui"
    if comp_type in {"storage"}:
        return "storage"
    return "svc"