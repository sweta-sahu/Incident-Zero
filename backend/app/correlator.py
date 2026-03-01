from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple


_ALLOWED_TYPES = {"hardcoded-secret", "sql-injection"}
_TYPE_MAP = {
    "hardcoded_secret": "hardcoded-secret",
    "sql_injection": "sql-injection",
}
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


def correlate_tool_results(tool_results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    multimodal_payloads: List[Dict[str, Any]] = []

    for result in tool_results:
        for finding in result.get("findings", []) or []:
            normalized = _normalize_finding(finding)
            if normalized is None:
                continue

            key = (
                normalized["type"],
                normalized["file_path"],
                normalized["line"],
            )

            existing = merged.get(key)
            if existing is None:
                merged[key] = normalized
                continue

            _merge_into(existing, normalized)

        payload = _normalize_multimodal_payload(result)
        if payload:
            multimodal_payloads.append(payload)

    findings = list(merged.values())
    _attach_multimodal_payloads(findings, multimodal_payloads)

    findings.sort(key=lambda f: (-_SEVERITY_ORDER.get(f.get("severity", "low"), 0)))
    return {
        "findings": findings,
        "summary": _build_summary(findings),
    }


def _normalize_finding(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw_type = finding.get("type") or finding.get("vulnerability_type")
    normalized_type = _TYPE_MAP.get(raw_type, raw_type)
    if normalized_type not in _ALLOWED_TYPES:
        return None

    evidence_list = [_normalize_evidence(e) for e in finding.get("evidence", []) or []]
    evidence_list = [e for e in evidence_list if e]
    signals = _normalize_signals(finding.get("signals"))

    severity = finding.get("severity", "low")
    if _has_runtime_proof(evidence_list) or bool(signals.get("runtime_proof")):
        severity = _bump_severity(severity)
        signals["runtime_proof"] = True

    return {
        "id": finding.get("id") or finding.get("finding_id") or "",
        "type": normalized_type,
        "title": finding.get("title") or "Security finding",
        "severity": severity,
        "confidence": finding.get("confidence", "low"),
        "description": finding.get("description") or finding.get("message") or "",
        "evidence": evidence_list,
        "signals": signals,
        "file_path": finding.get("file_path") or "",
        "line": int(finding.get("line") or finding.get("line_number") or 0),
    }


def _normalize_evidence(evidence: Any) -> Dict[str, Any]:
    if not evidence or not isinstance(evidence, dict):
        return {}
    return {
        "id": evidence.get("id") or "",
        "kind": evidence.get("kind") or "other",
        "file_path": evidence.get("file_path") or "",
        "line": int(evidence.get("line") or 0),
        "snippet": evidence.get("snippet") or "",
        "note": evidence.get("note") or "",
    }


def _normalize_signals(raw_signals: Any) -> Dict[str, Any]:
    if not raw_signals or not isinstance(raw_signals, dict):
        return {}
    return dict(raw_signals)


def _normalize_multimodal_payload(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    tool_name = str(result.get("tool_name") or result.get("tool") or "").strip().lower()
    evidence = [_normalize_evidence(e) for e in result.get("evidence", []) or []]
    evidence = [e for e in evidence if e]
    signals = _normalize_signals(result.get("signals"))
    artifacts = result.get("artifacts") or {}

    looks_like_log = _looks_like_log_payload(tool_name, signals, evidence)
    looks_like_screenshot = _looks_like_screenshot_payload(tool_name, signals, artifacts, evidence)

    if not looks_like_log and not looks_like_screenshot:
        return None

    return {
        "tool_name": tool_name,
        "evidence": evidence,
        "signals": signals,
        "artifacts": artifacts,
        "is_log": looks_like_log,
        "is_screenshot": looks_like_screenshot,
    }


def _attach_multimodal_payloads(
    findings: List[Dict[str, Any]], payloads: List[Dict[str, Any]]
) -> None:
    if not findings:
        return

    for payload in payloads:
        if payload.get("is_log"):
            _attach_log_payload(findings, payload)
        if payload.get("is_screenshot"):
            _attach_screenshot_payload(findings, payload)


def _attach_log_payload(findings: List[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    signals = _normalize_signals(payload.get("signals"))
    evidence = _build_log_evidence(payload)

    runtime_proof = bool(signals.get("runtime_proof")) or _has_runtime_proof(evidence)
    if runtime_proof:
        signals["runtime_proof"] = True

    for finding in findings:
        had_runtime_proof = bool((finding.get("signals") or {}).get("runtime_proof"))
        _attach_signals(finding, signals)
        _attach_evidence(finding, evidence)
        if runtime_proof and not had_runtime_proof:
            finding["severity"] = _bump_severity(finding.get("severity", "low"))


def _attach_screenshot_payload(findings: List[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    signals = _normalize_signals(payload.get("signals"))
    evidence = _build_screenshot_evidence(payload)
    if not evidence:
        return

    has_secret_exposure = bool(signals.get("secret_exposure_detected"))
    if not has_secret_exposure:
        artifacts = payload.get("artifacts", {}) or {}
        has_secret_exposure = bool(artifacts.get("possible_secret_exposure"))
        if has_secret_exposure:
            signals["secret_exposure_detected"] = True

    if has_secret_exposure:
        targets = [f for f in findings if f.get("type") == "hardcoded-secret"]
        if not targets:
            targets = [_pick_highest_severity_finding(findings)]
    else:
        targets = []

    for finding in targets:
        _attach_signals(finding, signals)
        _attach_evidence(finding, evidence)


def _pick_highest_severity_finding(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    return max(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low"), 0))


def _build_log_evidence(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = payload.get("evidence", []) or []
    log_evidence = [e for e in evidence if e.get("kind") in {"log", "runtime"}]
    if log_evidence:
        return log_evidence[:2]

    artifacts = payload.get("artifacts", {}) or {}
    chunks = artifacts.get("chunks", []) or []
    derived = []
    for idx, chunk in enumerate(chunks[:2], start=1):
        derived.append(
            {
                "id": f"e_log_chunk_{idx}",
                "kind": "log",
                "file_path": "",
                "line": 0,
                "snippet": str(chunk),
                "note": "Runtime log excerpt",
            }
        )
    return derived


def _build_screenshot_evidence(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = payload.get("evidence", []) or []
    artifacts = payload.get("artifacts", {}) or {}

    image_path = ""
    for item in evidence:
        file_path = str(item.get("file_path") or "").strip()
        if file_path:
            image_path = file_path
            break

    if not image_path:
        return []

    visible_messages = artifacts.get("visible_messages", []) or []
    secret_hits = artifacts.get("possible_secret_exposure", []) or []
    secret_types = [
        str(secret.get("type") or "secret")
        for secret in secret_hits
        if isinstance(secret, dict)
    ]
    preview_note = "Screenshot evidence"
    if secret_types:
        preview_note = f"Possible exposed key(s): {', '.join(secret_types[:3])}"

    screenshot_evidence = {
        "id": "e_screenshot_preview",
        "kind": "screenshot",
        "file_path": image_path,
        "line": 0,
        "snippet": str(visible_messages[0]) if visible_messages else "",
        "note": preview_note,
    }

    text_evidence = [e for e in evidence if e.get("kind") in {"ocr", "image_text"}]
    return [screenshot_evidence, *text_evidence[:1]]


def _attach_signals(finding: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    current = _normalize_signals(finding.get("signals"))
    finding["signals"] = _merge_signals(current, incoming)


def _merge_signals(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key not in merged:
            merged[key] = value
            continue

        current = merged[key]
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = current + [item for item in value if item not in current]
            continue

        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = {**current, **value}
            continue

        if isinstance(current, bool) and isinstance(value, bool):
            merged[key] = current or value
            continue

        merged[key] = value
    return merged


def _attach_evidence(finding: Dict[str, Any], incoming: List[Dict[str, Any]]) -> None:
    evidence_map = {e.get("id"): e for e in finding.get("evidence", []) if e}
    for evidence in incoming:
        if not evidence:
            continue
        eid = evidence.get("id")
        if eid and eid in evidence_map:
            continue
        evidence_map[eid or f"e_{len(evidence_map)+1}"] = evidence
    finding["evidence"] = list(evidence_map.values())


def _merge_into(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    if _SEVERITY_ORDER.get(incoming.get("severity", "low"), 0) > _SEVERITY_ORDER.get(
        target.get("severity", "low"), 0
    ):
        target["severity"] = incoming.get("severity")

    if _CONFIDENCE_ORDER.get(
        incoming.get("confidence", "low"), 0
    ) > _CONFIDENCE_ORDER.get(target.get("confidence", "low"), 0):
        target["confidence"] = incoming.get("confidence")

    _attach_evidence(target, incoming.get("evidence", []))
    _attach_signals(target, incoming.get("signals", {}))


def _looks_like_log_payload(
    tool_name: str,
    signals: Dict[str, Any],
    evidence: List[Dict[str, Any]],
) -> bool:
    if "log" in tool_name:
        return True
    if bool(signals.get("runtime_proof")):
        return True
    return any(item.get("kind") in {"log", "runtime"} for item in evidence)


def _looks_like_screenshot_payload(
    tool_name: str,
    signals: Dict[str, Any],
    artifacts: Dict[str, Any],
    evidence: List[Dict[str, Any]],
) -> bool:
    if "screenshot" in tool_name:
        return True
    if bool(signals.get("secret_exposure_detected")):
        return True
    if artifacts.get("possible_secret_exposure"):
        return True
    return any(item.get("kind") in {"ocr", "image_text", "screenshot"} for item in evidence)


def _has_runtime_proof(evidence_list: List[Dict[str, Any]]) -> bool:
    for evidence in evidence_list:
        if evidence.get("kind") in {"runtime", "log"}:
            return True
    return False


def _bump_severity(severity: str) -> str:
    if severity == "low":
        return "medium"
    if severity == "medium":
        return "high"
    if severity == "high":
        return "critical"
    return severity


def _build_summary(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No findings from active tools."

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = finding.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    total = len(findings)
    parts = [f"{total} findings"]
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            parts.append(f"{counts[sev]} {sev}")
    return ", ".join(parts) + "."
