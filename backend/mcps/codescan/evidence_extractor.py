"""
Evidence extraction for findings.
Extracts code context and builds structured evidence artifacts.
"""

import re
from typing import List, Dict, Any
from pathlib import Path


def extract_evidence(file_path: str, line_number: int, content: str) -> List[Dict[str, Any]]:
    """
    Extract evidence context around a vulnerability.
    
    Args:
        file_path: Path to the file
        line_number: Line number of the vulnerability
        content: Full file content
        
    Returns:
        List of evidence dictionaries with context
    """
    lines = content.split('\n')
    evidence = []
    
    # 1. PRIMARY EVIDENCE: Code Context (5 lines before and after)
    context_window_size = 5
    context_start = max(0, line_number - context_window_size - 1)
    context_end = min(len(lines), line_number + context_window_size)
    
    context_lines = []
    for i in range(context_start, context_end):
        if i < len(lines):
            context_lines.append({
                "line_number": i + 1,
                "content": lines[i],
                "is_target": (i + 1) == line_number,
                "indentation_level": len(lines[i]) - len(lines[i].lstrip())
            })
    
    evidence.append({
        "type": "code_context",
        "source_file": file_path,
        "target_line": line_number,
        "context_lines": context_lines,
        "context_window": f"±{context_window_size} lines",
        "proof_type": "regex_match",
        "severity_indicator": "code_pattern",
        "line_count": len(context_lines)
    })
    
    # 2. SECONDARY EVIDENCE: Function/Class context (where is this vulnerability located)
    function_context = _extract_function_context(lines, line_number)
    if function_context:
        evidence.append(function_context)
    
    # 3. TERTIARY EVIDENCE: Variable assignment tracking (trace source of dangerous vars)
    var_evidence = _extract_variable_context(lines, line_number)
    if var_evidence:
        evidence.append(var_evidence)
    
    return evidence


def _extract_function_context(lines: List[str], line_number: int) -> Dict[str, Any]:
    """
    Extract the function or class definition that contains the vulnerability.
    
    Args:
        lines: All lines of the file
        line_number: Target line number
        
    Returns:
        Function/class context evidence or None
    """
    # Search backward for function/class definition
    for i in range(line_number - 1, -1, -1):
        line = lines[i]
        
        # Python function definition
        if re.match(r'^\s*def\s+(\w+)\s*\(', line):
            func_name = re.search(r'def\s+(\w+)\s*\(', line).group(1)
            return {
                "type": "function_context",
                "function_name": func_name,
                "definition_line": i + 1,
                "context": line.strip(),
                "proof_type": "scope_analysis"
            }
        
        # Python class definition
        if re.match(r'^\s*class\s+(\w+)', line):
            class_name = re.search(r'class\s+(\w+)', line).group(1)
            return {
                "type": "class_context",
                "class_name": class_name,
                "definition_line": i + 1,
                "context": line.strip(),
                "proof_type": "scope_analysis"
            }
        
        # JavaScript/TypeScript function
        if re.match(r'^\s*(function|const|let|var)\s+(\w+)\s*(=>|\()?', line):
            match = re.search(r'(function|const|let|var)\s+(\w+)', line)
            if match:
                func_name = match.group(2)
                return {
                    "type": "function_context",
                    "function_name": func_name,
                    "definition_line": i + 1,
                    "context": line.strip(),
                    "proof_type": "scope_analysis"
                }
    
    return None


def _extract_variable_context(lines: List[str], line_number: int) -> Dict[str, Any]:
    """
    Extract variable assignments that feed into the vulnerability.
    Trace back to see where dangerous variables come from.
    
    Args:
        lines: All lines of the file
        line_number: Target line number
        
    Returns:
        Variable context evidence or None
    """
    target_line = lines[line_number - 1] if line_number <= len(lines) else ""
    
    # Extract variable names used in the vulnerable line
    var_pattern = r'\b([a-zA-Z_]\w*)\b'
    variables = re.findall(var_pattern, target_line)
    
    if not variables:
        return None
    
    # Search backward for assignments to these variables
    assignments = []
    for i in range(line_number - 2, max(0, line_number - 20), -1):
        for var in variables:
            assignment_pattern = rf'{var}\s*[=:]'
            if re.search(assignment_pattern, lines[i]):
                assignments.append({
                    "variable": var,
                    "line_number": i + 1,
                    "assignment": lines[i].strip()
                })
    
    if assignments:
        return {
            "type": "variable_tracking",
            "tracked_variables": variables[:5],  # Limit to 5
            "assignments": assignments[:3],  # Limit to 3
            "proof_type": "data_flow",
            "description": "Variable assignments that feed into vulnerability"
        }
    
    return None


def get_code_snippet(file_path: str, line_number: int, window: int = 2) -> str:
    """
    Get a code snippet around a line from file system.
    
    Args:
        file_path: Path to the file
        line_number: Line number to center on
        window: Lines before/after to include
        
    Returns:
        Code snippet string with line numbers
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)
        
        snippet_parts = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == line_number else "    "
            snippet_parts.append(f"{marker}{line_num:4d}: {lines[i].rstrip()}")
        
        return "\n".join(snippet_parts)
    except Exception as e:
        return f"Error reading file: {str(e)}"


def build_evidence_summary(evidence_list: List[Dict[str, Any]]) -> str:
    """
    Build a human-readable summary of evidence.
    
    Args:
        evidence_list: List of evidence dictionaries
        
    Returns:
        Formatted evidence summary string
    """
    summary_parts = []
    
    for evidence in evidence_list:
        if evidence.get("type") == "code_context":
            summary_parts.append("📍 Code Context:")
            for ctx_line in evidence.get("context_lines", []):
                if ctx_line["is_target"]:
                    summary_parts.append(f"  >>> Line {ctx_line['line_number']}: {ctx_line['content'].strip()}")
                else:
                    summary_parts.append(f"      Line {ctx_line['line_number']}: {ctx_line['content'].strip()}")
        
        elif evidence.get("type") == "function_context":
            summary_parts.append(f"📦 Function: {evidence.get('function_name')}")
            summary_parts.append(f"   Defined at line {evidence.get('definition_line')}")
        
        elif evidence.get("type") == "class_context":
            summary_parts.append(f"📦 Class: {evidence.get('class_name')}")
            summary_parts.append(f"   Defined at line {evidence.get('definition_line')}")
        
        elif evidence.get("type") == "variable_tracking":
            summary_parts.append("🔍 Variable Tracking:")
            for assignment in evidence.get("assignments", []):
                summary_parts.append(f"   Line {assignment['line_number']}: {assignment['assignment']}")
    
    return "\n".join(summary_parts)
