from __future__ import annotations

import re
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
    _merge_synthesized_multimodal_findings(findings, multimodal_payloads)

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

    file_path = finding.get("file_path") or ""
    line = int(finding.get("line") or finding.get("line_number") or 0)
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
    if not finding_id:
        finding_id = _build_stable_finding_id(normalized_type, file_path, line)

    return {
        "id": finding_id,
        "type": normalized_type,
        "title": finding.get("title") or "Security finding",
        "severity": severity,
        "confidence": finding.get("confidence", "low"),
        "description": finding.get("description") or finding.get("message") or "",
        "evidence": evidence_list,
        "signals": signals,
        "file_path": file_path,
        "line": line,
        "source": _normalize_source_list(finding.get("source")) or ["code"],
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
    looks_like_diagram = _looks_like_diagram_payload(tool_name, signals, artifacts)

    if not looks_like_log and not looks_like_screenshot and not looks_like_diagram:
        return None

    return {
        "tool_name": tool_name,
        "evidence": evidence,
        "signals": signals,
        "artifacts": artifacts,
        "is_log": looks_like_log,
        "is_screenshot": looks_like_screenshot,
        "is_diagram": looks_like_diagram,
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
        if payload.get("is_diagram"):
            _attach_diagram_payload(findings, payload)


def _attach_log_payload(findings: List[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    signals = _normalize_signals(payload.get("signals"))
    evidence = _build_log_evidence(payload)

    runtime_proof = bool(signals.get("runtime_proof")) or _has_runtime_proof(evidence)
    if runtime_proof:
        signals["runtime_proof"] = True

    preferred_types: List[str] = []
    if signals.get("sql_injection_suspected") or signals.get("suspicious_log_activity"):
        preferred_types.append("sql-injection")
    if signals.get("auth_issue_suspected"):
        preferred_types.append("hardcoded-secret")

    targets = _select_target_findings(findings, signals, preferred_types)
    for finding in targets:
        _attach_sources(finding, ["logs"])
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
        targets = _select_target_findings(findings, signals, ["hardcoded-secret"])
        if not targets:
            targets = [_pick_highest_severity_finding(findings)]
    else:
        targets = []

    for finding in targets:
        _attach_sources(finding, ["screenshot"])
        _attach_signals(finding, signals)
        _attach_evidence(finding, evidence)


def _attach_diagram_payload(findings: List[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    signals = _normalize_signals(payload.get("signals"))
    evidence = payload.get("evidence", []) or []
    if not signals and not evidence:
        return

    targets = _select_target_findings(findings, signals, [])
    for finding in targets:
        _attach_sources(finding, ["diagram"])
        _attach_signals(finding, signals)
        _attach_evidence(finding, evidence[:1])


def _pick_highest_severity_finding(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    return max(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low"), 0))


def _build_stable_finding_id(vuln_type: str, file_path: str, line: int) -> str:
    safe_path = (file_path or "unknown").replace("\\", "/")
    safe_path = safe_path.replace("/", "_").replace(".", "_")
    return f"f_{vuln_type}_{safe_path}_{line if line > 0 else 0}"


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


def _attach_sources(finding: Dict[str, Any], incoming: List[str]) -> None:
    current = _normalize_source_list(finding.get("source"))
    finding["source"] = _merge_source_lists(current, incoming)


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
    _attach_sources(target, _normalize_source_list(incoming.get("source")))


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


def _looks_like_diagram_payload(
    tool_name: str,
    signals: Dict[str, Any],
    artifacts: Dict[str, Any],
) -> bool:
    if "diagram" in tool_name:
        return True
    if signals.get("entry_points") or signals.get("trust_zones") or signals.get("secrets_locations"):
        return True
    return bool(artifacts.get("components") or artifacts.get("connections"))


def _select_target_findings(
    findings: List[Dict[str, Any]],
    signals: Dict[str, Any],
    preferred_types: List[str],
) -> List[Dict[str, Any]]:
    finding_ids = signals.get("finding_ids") or []
    if isinstance(finding_ids, list) and finding_ids:
        id_set = {str(item).strip() for item in finding_ids if str(item).strip()}
        matched = [f for f in findings if str(f.get("id") or "").strip() in id_set]
        if matched:
            return matched

    if preferred_types:
        preferred = [f for f in findings if f.get("type") in preferred_types]
        if preferred:
            return preferred

    return findings


def _merge_synthesized_multimodal_findings(
    findings: List[Dict[str, Any]],
    payloads: List[Dict[str, Any]],
) -> None:
    synthesized = _synthesize_findings_from_multimodal(payloads)
    if not synthesized:
        return

    index: Dict[Tuple[str, str, int], Dict[str, Any]] = {
        (f.get("type", ""), f.get("file_path", ""), int(f.get("line", 0))): f for f in findings
    }
    for item in synthesized:
        key = (item.get("type", ""), item.get("file_path", ""), int(item.get("line", 0)))
        existing = index.get(key)
        if existing is None:
            findings.append(item)
            index[key] = item
            continue
        _merge_into(existing, item)


def _synthesize_findings_from_multimodal(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    synthesized: List[Dict[str, Any]] = []
    for payload in payloads:
        signals = _normalize_signals(payload.get("signals"))
        evidence = [e for e in payload.get("evidence", []) or [] if e]
        artifacts = payload.get("artifacts", {}) or {}

        if payload.get("is_screenshot") and (
            signals.get("secret_exposure_detected") or artifacts.get("possible_secret_exposure")
        ):
            file_path, line = _extract_file_line_from_evidence(evidence)
            synthesized.append(
                _build_synthetic_finding(
                    vuln_type="hardcoded-secret",
                    title="Possible hardcoded/exposed secret from screenshot evidence",
                    description=_first_non_empty(
                        artifacts.get("visible_messages", []),
                        "Screenshot indicates possible secret exposure.",
                    ),
                    evidence=evidence[:2],
                    signals=signals,
                    file_path=file_path,
                    line=line,
                )
            )

        if payload.get("is_log") and (
            signals.get("sql_injection_suspected") or signals.get("suspicious_log_activity")
        ):
            file_path, line = _extract_file_line_from_evidence(evidence)
            synthesized.append(
                _build_synthetic_finding(
                    vuln_type="sql-injection",
                    title="Possible SQL injection from runtime log evidence",
                    description="Log patterns indicate SQL injection-like runtime behavior.",
                    evidence=evidence[:2],
                    signals=signals,
                    file_path=file_path,
                    line=line,
                )
            )
    return synthesized


def _build_synthetic_finding(
    vuln_type: str,
    title: str,
    description: str,
    evidence: List[Dict[str, Any]],
    signals: Dict[str, Any],
    file_path: str,
    line: int,
) -> Dict[str, Any]:
    return {
        "id": _build_stable_finding_id(vuln_type, file_path, line),
        "type": vuln_type,
        "title": title,
        "severity": "high",
        "confidence": "medium",
        "description": description,
        "evidence": evidence,
        "signals": dict(signals),
        "file_path": file_path,
        "line": line,
        "source": _infer_synthetic_source(signals),
    }


def _extract_file_line_from_evidence(evidence_list: List[Dict[str, Any]]) -> Tuple[str, int]:
    pattern = r'File "([^"]+)", line (\d+)'
    for evidence in evidence_list:
        snippet = str(evidence.get("snippet") or "")
        match = re.search(pattern, snippet)
        if not match:
            continue
        file_path = match.group(1).strip()
        try:
            line_number = int(match.group(2))
        except ValueError:
            line_number = 0
        return file_path, line_number
    return "", 0


def _first_non_empty(values: Any, fallback: str) -> str:
    if isinstance(values, list):
        for value in values:
            text = str(value).strip()
            if text:
                return text
    return fallback


def _normalize_source_list(value: Any) -> List[str]:
    if isinstance(value, str):
        cleaned = value.strip().lower()
        return [cleaned] if cleaned else []
    if isinstance(value, list):
        normalized: List[str] = []
        for item in value:
            if not isinstance(item, str):
                continue
            cleaned = item.strip().lower()
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
        return normalized
    return []


def _merge_source_lists(base: List[str], incoming: List[str]) -> List[str]:
    merged: List[str] = []
    for item in base + incoming:
        cleaned = str(item).strip().lower()
        if cleaned and cleaned not in merged:
            merged.append(cleaned)
    return merged


def _infer_synthetic_source(signals: Dict[str, Any]) -> List[str]:
    source = ["runtime"]
    if signals.get("secret_exposure_detected"):
        source.append("screenshot")
    if signals.get("sql_injection_suspected") or signals.get("suspicious_log_activity"):
        source.append("logs")
    return _merge_source_lists([], source)


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
