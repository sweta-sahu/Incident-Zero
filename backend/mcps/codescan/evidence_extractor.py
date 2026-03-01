"""
Evidence extraction for findings.
Extracts code context and builds structured evidence artifacts.
"""

import re
from typing import Any, Dict, List, Optional


def extract_evidence(
    file_path: str,
    line_number: int,
    content: str,
    finding_id: str = "",
) -> List[Dict[str, Any]]:
    """
    Extract evidence context around a vulnerability.

    Args:
        file_path: Path to the file
        line_number: Line number of the vulnerability
        content: Full file content
        finding_id: Optional finding identifier for deterministic evidence IDs

    Returns:
        List of evidence dictionaries with normalized artifact fields and
        compatibility fields used by existing tests and callers.
    """
    lines = content.split("\n")
    evidence: List[Dict[str, Any]] = []

    # 1) Primary evidence: target line with context window.
    context_window_size = 5
    context_start = max(0, line_number - context_window_size - 1)
    context_end = min(len(lines), line_number + context_window_size)

    context_lines = []
    for i in range(context_start, context_end):
        context_lines.append(
            {
                "line_number": i + 1,
                "content": lines[i],
                "is_target": (i + 1) == line_number,
                "indentation_level": len(lines[i]) - len(lines[i].lstrip()),
            }
        )

    primary_evidence = {
        "id": _build_evidence_id(finding_id, 1),
        "kind": "code",
        "file_path": file_path,
        "line": line_number,
        "snippet": _safe_line(lines, line_number).strip(),
        "context_window": f"+/-{context_window_size} lines",
        "context_window_lines": {
            "before": context_window_size,
            "after": context_window_size,
            "start_line": context_start + 1,
            "end_line": context_end,
        },
        "note": "Pattern-matched line with surrounding context.",
        "type": "code_context",
        "source_file": file_path,
        "target_line": line_number,
        "context_lines": context_lines,
        "proof_type": "regex_match",
        "severity_indicator": "code_pattern",
        "line_count": len(context_lines),
    }
    evidence.append(primary_evidence)

    # 2) Secondary evidence: nearest containing function/class.
    function_context = _extract_function_context(lines, line_number)
    if function_context:
        function_context["id"] = _build_evidence_id(finding_id, len(evidence) + 1)
        function_context["file_path"] = file_path
        evidence.append(function_context)

    # 3) Tertiary evidence: simple variable assignment tracing.
    variable_context = _extract_variable_context(lines, line_number)
    if variable_context:
        variable_context["id"] = _build_evidence_id(finding_id, len(evidence) + 1)
        variable_context["file_path"] = file_path
        evidence.append(variable_context)

    return evidence


def _extract_function_context(
    lines: List[str], line_number: int
) -> Optional[Dict[str, Any]]:
    """
    Extract the function or class definition containing the vulnerable line.
    """
    start = min(max(line_number - 1, 0), len(lines) - 1) if lines else -1
    for i in range(start, -1, -1):
        line = lines[i]

        # Python function definition
        if re.match(r"^\s*def\s+(\w+)\s*\(", line):
            func_name = re.search(r"def\s+(\w+)\s*\(", line).group(1)
            return {
                "kind": "code",
                "line": i + 1,
                "snippet": line.strip(),
                "context_window": {
                    "before": 0,
                    "after": 0,
                    "start_line": i + 1,
                    "end_line": i + 1,
                },
                "note": "Enclosing function declaration.",
                "type": "function_context",
                "function_name": func_name,
                "definition_line": i + 1,
                "context": line.strip(),
                "proof_type": "scope_analysis",
            }

        # Python class definition
        if re.match(r"^\s*class\s+(\w+)", line):
            class_name = re.search(r"class\s+(\w+)", line).group(1)
            return {
                "kind": "code",
                "line": i + 1,
                "snippet": line.strip(),
                "context_window": {
                    "before": 0,
                    "after": 0,
                    "start_line": i + 1,
                    "end_line": i + 1,
                },
                "note": "Enclosing class declaration.",
                "type": "class_context",
                "class_name": class_name,
                "definition_line": i + 1,
                "context": line.strip(),
                "proof_type": "scope_analysis",
            }

        # JavaScript/TypeScript function declaration/assignment
        if re.match(r"^\s*(function|const|let|var)\s+(\w+)\s*(=>|\()?", line):
            match = re.search(r"(function|const|let|var)\s+(\w+)", line)
            if match:
                func_name = match.group(2)
                return {
                    "kind": "code",
                    "line": i + 1,
                    "snippet": line.strip(),
                    "context_window": {
                        "before": 0,
                        "after": 0,
                        "start_line": i + 1,
                        "end_line": i + 1,
                    },
                    "note": "Enclosing function-like declaration.",
                    "type": "function_context",
                    "function_name": func_name,
                    "definition_line": i + 1,
                    "context": line.strip(),
                    "proof_type": "scope_analysis",
                }

    return None


def _extract_variable_context(
    lines: List[str], line_number: int
) -> Optional[Dict[str, Any]]:
    """
    Extract variable assignments that may feed the vulnerable line.
    """
    target_line = _safe_line(lines, line_number)
    var_pattern = r"\b([a-zA-Z_]\w*)\b"
    variables = re.findall(var_pattern, target_line)

    if not variables:
        return None

    assignments = []
    search_start = line_number - 2
    search_end = max(0, line_number - 20)
    for i in range(search_start, search_end, -1):
        if i < 0 or i >= len(lines):
            continue
        for var in variables:
            assignment_pattern = rf"{var}\s*[=:]"
            if re.search(assignment_pattern, lines[i]):
                assignments.append(
                    {
                        "variable": var,
                        "line_number": i + 1,
                        "assignment": lines[i].strip(),
                    }
                )

    if assignments:
        return {
            "kind": "other",
            "line": line_number,
            "snippet": target_line.strip(),
            "context_window": {
                "before": 20,
                "after": 0,
                "start_line": max(1, line_number - 20),
                "end_line": line_number,
            },
            "note": "Nearby assignments for variables used on vulnerable line.",
            "type": "variable_tracking",
            "tracked_variables": variables[:5],
            "assignments": assignments[:3],
            "proof_type": "data_flow",
            "description": "Variable assignments that feed into vulnerability",
        }

    return None


def get_code_snippet(file_path: str, line_number: int, window: int = 2) -> str:
    """
    Get a code snippet around a line from the file system.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)

        snippet_parts = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == line_number else "    "
            snippet_parts.append(f"{marker}{line_num:4d}: {lines[i].rstrip()}")

        return "\n".join(snippet_parts)
    except Exception as exc:
        return f"Error reading file: {str(exc)}"


def build_evidence_summary(evidence_list: List[Dict[str, Any]]) -> str:
    """
    Build a human-readable summary of evidence.
    """
    summary_parts = []

    for evidence in evidence_list:
        if evidence.get("type") == "code_context":
            summary_parts.append("Code Context:")
            for ctx_line in evidence.get("context_lines", []):
                if ctx_line["is_target"]:
                    summary_parts.append(
                        f"  >>> Line {ctx_line['line_number']}: {ctx_line['content'].strip()}"
                    )
                else:
                    summary_parts.append(
                        f"      Line {ctx_line['line_number']}: {ctx_line['content'].strip()}"
                    )

        elif evidence.get("type") == "function_context":
            summary_parts.append(f"Function: {evidence.get('function_name')}")
            summary_parts.append(
                f"   Defined at line {evidence.get('definition_line')}"
            )

        elif evidence.get("type") == "class_context":
            summary_parts.append(f"Class: {evidence.get('class_name')}")
            summary_parts.append(
                f"   Defined at line {evidence.get('definition_line')}"
            )

        elif evidence.get("type") == "variable_tracking":
            summary_parts.append("Variable Tracking:")
            for assignment in evidence.get("assignments", []):
                summary_parts.append(
                    f"   Line {assignment['line_number']}: {assignment['assignment']}"
                )

    return "\n".join(summary_parts)


def _build_evidence_id(finding_id: str, ordinal: int) -> str:
    """Build deterministic evidence IDs for downstream correlation."""
    if finding_id:
        return f"{finding_id}_e_{ordinal}"
    return f"evidence_{ordinal}"


def _safe_line(lines: List[str], line_number: int) -> str:
    """Return a 1-based line from lines, or empty string if out of range."""
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""
