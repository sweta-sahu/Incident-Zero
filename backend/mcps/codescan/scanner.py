"""
Main scanning logic for CodeScan MCP.
Orchestrates rule application across repository files.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from .rules import VULNERABILITY_RULES
from .evidence_extractor import extract_evidence

# Set up logging
logger = logging.getLogger(__name__)


class ScanResult:
    """Encapsulates scan results with metadata."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.findings: List[Dict[str, Any]] = []
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []
        self.start_time = datetime.now(timezone.utc)
        self.end_time: Optional[datetime] = None

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to results."""
        self.findings.append(finding)

    def add_error(self, file_path: str, error: str) -> None:
        """Log a scanning error."""
        self.errors.append({
            "file": file_path,
            "error": str(error)
        })

    def finalize(self) -> Dict[str, Any]:
        """Generate final ToolResult JSON."""
        self.end_time = datetime.now(timezone.utc)
        duration = (self.end_time - self.start_time).total_seconds()

        # Sort findings by severity (high → medium → low)
        severity_order = {"high": 0, "medium": 1, "low": 2}
        self.findings.sort(
            key=lambda f: (
                severity_order.get(f.get("severity", "low"), 3),
                -f.get("confidence_score", 0)
            )
        )

        timeline_event = {
            "ts": self.end_time.isoformat().replace("+00:00", "Z"),
            "stage": "scan",
            "message": "CodeScan completed",
            "status": "done",
        }

        return {
            "tool": "codescan",
            "tool_name": "CodeScan",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "completed",
            "findings": self.findings,
            "timeline": [timeline_event],
            "meta": {
                "repo_path": str(self.repo_path),
                "total_findings": len(self.findings),
                "scanned_files": self.scanned_files,
            },
            "metadata": {
                "repo_path": str(self.repo_path),
                "scan_duration_seconds": round(duration, 2),
                "total_findings": len(self.findings),
                "findings_by_severity": self._count_by_severity(),
                "findings_by_type": self._count_by_type(),
                "scanned_files": self.scanned_files,
                "skipped_files": self.skipped_files,
                "total_errors": len(self.errors),
                "rules_applied": len(VULNERABILITY_RULES),
                "rules": [rule.rule_id for rule in VULNERABILITY_RULES]
            },
            "errors": self.errors if self.errors else None
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            severity = finding.get("severity", "low")
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_type(self) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for finding in self.findings:
            vuln_type = finding.get("vulnerability_type", "unknown")
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts


def scan_repository(repo_path: str) -> Dict[str, Any]:
    """
    Scan a repository for vulnerabilities using registered rules.
    Main entry point for CodeScan MCP.

    Args:
        repo_path: Root directory of the repository to scan

    Returns:
        ToolResult JSON with findings and metadata
    """
    result = ScanResult(repo_path)

    # Validate repo path
    if not Path(repo_path).exists():
        result.add_error(repo_path, "Repository path does not exist")
        return result.finalize()

    # Directories to skip during traversal
    skip_dirs = {
        ".git", "node_modules", ".venv", "venv", "env",
        "__pycache__", ".env", "dist", "build", "coverage",
        ".pytest_cache", ".tox", ".mypy_cache", ".hypothesis",
        "egg-info", ".eggs", "vendor", "migrations"
    }

    # File extensions to scan
    scannable_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c"
    }

    # Walk through repository
    for root, dirs, files in os.walk(result.repo_path):
        # Prevent traverse into skip directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for file in files:
            file_path = Path(root) / file
            relative_path = file_path.relative_to(result.repo_path)

            # Check if file should be scanned
            if file_path.suffix not in scannable_extensions:
                continue

            result.scanned_files += 1

            try:
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Apply each rule to this file
                for rule in VULNERABILITY_RULES:
                    matches = rule.check(content, str(file_path))

                    for match in matches:
                        confidence_score = match.get("confidence", rule.confidence)
                        finding_id = f"{rule.rule_id}_{len(result.findings)}"

                        # Extract comprehensive evidence
                        evidence_list = extract_evidence(
                            file_path=str(relative_path),
                            line_number=match["line_number"],
                            content=content,
                            finding_id=finding_id,
                        )

                        # Build finding object
                        finding = {
                            "id": finding_id,
                            "finding_id": finding_id,
                            "type": rule.vulnerability_type,
                            "vulnerability_type": rule.vulnerability_type,
                            "title": _get_finding_title(rule.vulnerability_type),
                            "severity": rule.severity,
                            "file_path": str(relative_path),
                            "line": match["line_number"],
                            "line_number": match["line_number"],
                            "code_snippet": match.get("snippet", ""),
                            "confidence": _to_confidence_label(confidence_score),
                            "confidence_score": confidence_score,
                            "evidence": evidence_list,
                            "evidence_ids": [e["id"] for e in evidence_list if "id" in e],
                            "rule_id": rule.rule_id,
                            "rule_name": rule.description,
                            "description": match.get("message", rule.description),
                            "message": match.get("message", rule.description),
                            "pattern_matched": match.get("pattern_used", ""),
                            "remediation_hint": _get_remediation_hint(rule.vulnerability_type),
                            "cwe_id": _get_cwe_id(rule.vulnerability_type)
                        }

                        result.add_finding(finding)

            except Exception as e:
                result.add_error(str(file_path), str(e))
                logger.debug(f"Error scanning {file_path}: {e}")

    return result.finalize()


def _get_remediation_hint(vulnerability_type: str) -> str:
    """Get remediation hints for vulnerability types."""
    hints = {
        "hardcoded_secret": "Move secrets to environment variables or secure vaults (AWS Secrets Manager, HashiCorp Vault)",
        "sql_injection": "Use parameterized queries or prepared statements instead of string concatenation",
        "weak_cryptography": "Use bcrypt, scrypt, or Argon2 for passwords; SHA-256 or stronger for hashing"
    }
    return hints.get(vulnerability_type, "Review findings and apply appropriate security fix")


def _get_finding_title(vulnerability_type: str) -> str:
    """Return a short user-friendly finding title."""
    titles = {
        "hardcoded_secret": "Hardcoded secret found",
        "sql_injection": "Potential SQL injection",
        "weak_cryptography": "Weak cryptography usage",
    }
    return titles.get(vulnerability_type, "Security finding")


def _to_confidence_label(score: float) -> str:
    """
    Map numeric confidence to contract-aligned confidence labels.

    Thresholds:
      - high: >= 0.85
      - medium: >= 0.60
      - low: < 0.60
    """
    if score >= 0.85:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


def _get_cwe_id(vulnerability_type: str) -> str:
    """Get CWE (Common Weakness Enumeration) ID for vulnerability types."""
    cwe_mapping = {
        "hardcoded_secret": "CWE-798",
        "sql_injection": "CWE-89",
        "weak_cryptography": "CWE-326"
    }
    return cwe_mapping.get(vulnerability_type, "CWE-Unknown")
