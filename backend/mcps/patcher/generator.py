from __future__ import annotations

import difflib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .github import build_pr_automation_bundle


_SUPPORTED_TYPES = {"hardcoded-secret", "sql-injection"}
_TYPE_ALIASES = {
    "hardcoded_secret": "hardcoded-secret",
    "sql_injection": "sql-injection",
}


def generate_patches(
    findings: List[Dict[str, Any]],
    repo_path: str,
    github_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate deterministic security patches for supported findings.
    """
    repo_root = Path(repo_path).resolve()
    patches: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for idx, finding in enumerate(findings or [], start=1):
        finding_id = str(finding.get("id") or finding.get("finding_id") or f"f_{idx}")
        vuln_type = _normalize_type(finding.get("type") or finding.get("vulnerability_type"))
        if vuln_type not in _SUPPORTED_TYPES:
            skipped.append({"finding_id": finding_id, "reason": f"unsupported_type:{vuln_type}"})
            continue

        file_path = str(finding.get("file_path") or "").strip()
        if not file_path:
            skipped.append({"finding_id": finding_id, "reason": "missing_file_path"})
            continue

        line_number = _as_positive_int(finding.get("line") or finding.get("line_number"))
        if line_number <= 0:
            skipped.append({"finding_id": finding_id, "reason": "invalid_line_number"})
            continue

        absolute_path = repo_root / file_path
        if not absolute_path.exists():
            skipped.append({"finding_id": finding_id, "reason": "file_not_found"})
            continue

        try:
            original_text = absolute_path.read_text(encoding="utf-8", errors="ignore")
            original_lines = original_text.splitlines()

            patched_lines, summary, template_id = _apply_template(
                vuln_type=vuln_type,
                original_lines=original_lines,
                line_number=line_number,
                file_extension=absolute_path.suffix.lower(),
            )

            if patched_lines is None or patched_lines == original_lines:
                skipped.append({"finding_id": finding_id, "reason": "template_not_applicable"})
                continue

            diff_text = _build_unified_diff(file_path, original_lines, patched_lines)
            if not diff_text.strip():
                skipped.append({"finding_id": finding_id, "reason": "empty_diff"})
                continue

            patch_id = f"patch_{finding_id}"
            patches.append(
                {
                    "id": patch_id,
                    "finding_id": finding_id,
                    "file_path": file_path,
                    "diff": diff_text,
                    "summary": summary,
                    "template_id": template_id,
                    "vulnerability_type": vuln_type,
                    "line": line_number,
                }
            )
        except Exception as exc:
            errors.append({"finding_id": finding_id, "error": str(exc)})

    github_bundle = build_pr_automation_bundle(patches, github_config=github_config)

    return {
        "tool": "patcher",
        "tool_name": "PatchMCP",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "completed",
        "patches": patches,
        "github": github_bundle,
        "meta": {
            "repo_path": str(repo_root),
            "input_findings": len(findings or []),
            "generated_patches": len(patches),
            "skipped_findings": len(skipped),
            "errors": len(errors),
            "supported_types": sorted(_SUPPORTED_TYPES),
        },
        "skipped": skipped,
        "errors": errors or None,
    }


def _apply_template(
    vuln_type: str,
    original_lines: List[str],
    line_number: int,
    file_extension: str,
) -> Tuple[Optional[List[str]], str, str]:
    if vuln_type == "hardcoded-secret":
        return _patch_hardcoded_secret(original_lines, line_number, file_extension)
    if vuln_type == "sql-injection":
        return _patch_sql_injection(original_lines, line_number, file_extension)
    return None, "", ""


def _patch_hardcoded_secret(
    original_lines: List[str], line_number: int, file_extension: str
) -> Tuple[Optional[List[str]], str, str]:
    idx = line_number - 1
    if idx < 0 or idx >= len(original_lines):
        return None, "", ""

    line = original_lines[idx]
    if file_extension == ".py":
        patched = _patch_python_secret_line(original_lines, idx)
        if patched is None:
            return None, "", ""
        return (
            patched,
            "Replace hardcoded secret with environment-variable lookup.",
            "template-hardcoded-secret-python",
        )

    if file_extension in {".js", ".jsx", ".ts", ".tsx"}:
        patched = _patch_javascript_secret_line(original_lines, idx)
        if patched is None:
            return None, "", ""
        return (
            patched,
            "Replace hardcoded secret with process.env lookup.",
            "template-hardcoded-secret-js",
        )

    return None, "", ""


def _patch_sql_injection(
    original_lines: List[str], line_number: int, file_extension: str
) -> Tuple[Optional[List[str]], str, str]:
    idx = line_number - 1
    if idx < 0 or idx >= len(original_lines):
        return None, "", ""

    line = original_lines[idx]

    if file_extension == ".py":
        match = re.match(r"^(\s*)([A-Za-z_]\w*)\s*=.*$", line)
        if not match:
            return None, "", ""
        indent, variable = match.group(1), match.group(2)
        sql_template = _extract_sql_template(line, placeholder="%s")
        patched_line = (
            f'{indent}{variable} = "{sql_template}"'
            "  # PatchMCP: parameterized query template"
        )
        patched = list(original_lines)
        patched[idx] = patched_line
        return (
            patched,
            "Replace dynamic SQL string construction with parameterized template.",
            "template-sql-injection-python",
        )

    if file_extension in {".js", ".jsx", ".ts", ".tsx"}:
        match = re.match(r"^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=.*$", line)
        if not match:
            return None, "", ""
        indent, keyword, variable = match.group(1), match.group(2), match.group(3)
        sql_template = _extract_sql_template(line, placeholder="?")
        patched_line = (
            f'{indent}{keyword} {variable} = "{sql_template}";'
            " // PatchMCP: parameterized query template"
        )
        patched = list(original_lines)
        patched[idx] = patched_line
        return (
            patched,
            "Replace dynamic SQL string construction with parameterized template.",
            "template-sql-injection-js",
        )

    return None, "", ""


def _patch_python_secret_line(original_lines: List[str], target_idx: int) -> Optional[List[str]]:
    line = original_lines[target_idx]
    match = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]).*?\3\s*$", line)
    if not match:
        return None

    indent, variable = match.group(1), match.group(2)
    env_name = _normalize_env_key(variable)
    replacement = f'{indent}{variable} = os.environ.get("{env_name}", "")'

    patched = list(original_lines)
    patched[target_idx] = replacement
    if not _has_python_os_import(patched):
        insert_index = _python_import_insertion_index(patched)
        patched.insert(insert_index, "import os")
    return patched


def _patch_javascript_secret_line(
    original_lines: List[str], target_idx: int
) -> Optional[List[str]]:
    line = original_lines[target_idx]
    match = re.match(
        r"^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['\"]).*?\4\s*;?\s*$",
        line,
    )
    if not match:
        return None

    indent, keyword, variable = match.group(1), match.group(2), match.group(3)
    env_name = _normalize_env_key(variable)
    replacement = f'{indent}{keyword} {variable} = process.env.{env_name} || "";'

    patched = list(original_lines)
    patched[target_idx] = replacement
    return patched


def _extract_sql_template(line: str, placeholder: str) -> str:
    """
    Create a deterministic parameterized SQL template from a vulnerable line.
    """
    sql_candidate = ""
    literal_matches = re.findall(r"(['\"`])((?:(?!\1).)*)\1", line)
    for _, literal in literal_matches:
        if re.search(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b", literal):
            sql_candidate = literal
            break
    if not sql_candidate and literal_matches:
        sql_candidate = literal_matches[0][1]

    if not sql_candidate:
        sql_candidate = "SELECT * FROM table WHERE id = VALUE"

    sql_candidate = re.sub(r"\$\{[^}]+\}", placeholder, sql_candidate)
    sql_candidate = re.sub(r"\{[^}]+\}", placeholder, sql_candidate)
    sql_candidate = sql_candidate.replace("{}", placeholder)

    if "+" in line and placeholder not in sql_candidate:
        sql_candidate = f"{sql_candidate} {placeholder}"

    sql_candidate = re.sub(r"\s+", " ", sql_candidate).strip()
    return sql_candidate.replace('"', '\\"')


def _build_unified_diff(file_path: str, before: List[str], after: List[str]) -> str:
    diff_lines = difflib.unified_diff(
        before,
        after,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    diff_text = "\n".join(diff_lines)
    if diff_text:
        return diff_text + "\n"
    return ""


def _normalize_type(vuln_type: Any) -> str:
    raw = str(vuln_type or "").strip()
    return _TYPE_ALIASES.get(raw, raw)


def _as_positive_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _normalize_env_key(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name).upper()


def _has_python_os_import(lines: List[str]) -> bool:
    for line in lines:
        if re.match(r"^\s*import\s+os(\s|$)", line):
            return True
        if re.match(r"^\s*from\s+os\s+import\s+", line):
            return True
    return False


def _python_import_insertion_index(lines: List[str]) -> int:
    last_import = -1
    for i, line in enumerate(lines[:80]):
        if re.match(r"^\s*(import|from)\s+[A-Za-z0-9_\.]+", line):
            last_import = i
    if last_import >= 0:
        return last_import + 1

    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    while idx < len(lines) and (not lines[idx].strip() or lines[idx].lstrip().startswith("#")):
        idx += 1
    return idx

