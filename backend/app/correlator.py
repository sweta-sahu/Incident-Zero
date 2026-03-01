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

    findings = list(merged.values())
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

    severity = finding.get("severity", "low")
    if _has_runtime_proof(evidence_list):
        severity = _bump_severity(severity)

    return {
        "id": finding.get("id") or finding.get("finding_id") or "",
        "type": normalized_type,
        "title": finding.get("title") or "Security finding",
        "severity": severity,
        "confidence": finding.get("confidence", "low"),
        "description": finding.get("description") or finding.get("message") or "",
        "evidence": evidence_list,
        "file_path": finding.get("file_path") or "",
        "line": int(finding.get("line") or finding.get("line_number") or 0),
    }


def _normalize_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    if not evidence:
        return {}
    return {
        "id": evidence.get("id") or "",
        "kind": evidence.get("kind") or "other",
        "file_path": evidence.get("file_path") or "",
        "line": int(evidence.get("line") or 0),
        "snippet": evidence.get("snippet") or "",
        "note": evidence.get("note") or "",
    }


def _merge_into(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    if _SEVERITY_ORDER.get(incoming.get("severity", "low"), 0) > _SEVERITY_ORDER.get(
        target.get("severity", "low"), 0
    ):
        target["severity"] = incoming.get("severity")

    if _CONFIDENCE_ORDER.get(
        incoming.get("confidence", "low"), 0
    ) > _CONFIDENCE_ORDER.get(target.get("confidence", "low"), 0):
        target["confidence"] = incoming.get("confidence")

    evidence_map = {e.get("id"): e for e in target.get("evidence", []) if e}
    for e in incoming.get("evidence", []):
        if not e:
            continue
        eid = e.get("id")
        if eid and eid in evidence_map:
            continue
        evidence_map[eid or f"e_{len(evidence_map)+1}"] = e
    target["evidence"] = list(evidence_map.values())


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