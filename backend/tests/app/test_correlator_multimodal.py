"""
Multimodal correlator behavior checks.
"""

import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))

from backend.app.correlator import correlate_tool_results


def test_runtime_log_proof_bumps_severity_and_attaches_signal():
    codescan = {
        "tool_name": "CodeScan",
        "findings": [
            {
                "id": "f_sql_1",
                "type": "sql_injection",
                "severity": "medium",
                "confidence": "high",
                "title": "Potential SQL injection",
                "description": "User input reaches query string.",
                "file_path": "src/db.py",
                "line": 41,
                "evidence": [
                    {
                        "id": "e_code_1",
                        "kind": "code",
                        "file_path": "src/db.py",
                        "line": 41,
                        "snippet": "query = f\"select ... {user_input}\"",
                        "note": "Unsanitized query build",
                    }
                ],
            }
        ],
    }
    log_reasoner = {
        "tool_name": "LogReasoner",
        "evidence": [
            {
                "id": "e_log_1",
                "kind": "log",
                "file_path": "/tmp/app.log",
                "line": 0,
                "snippet": "ERROR: SQL syntax error near UNION SELECT",
                "note": "Runtime log excerpt",
            }
        ],
        "signals": {"runtime_proof": True, "suspicious_log_activity": True},
    }

    result = correlate_tool_results([codescan, log_reasoner])

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["severity"] == "high"
    assert finding["signals"]["runtime_proof"] is True
    assert any(item["kind"] == "log" for item in finding["evidence"])


def test_screenshot_secret_exposure_links_to_secret_finding():
    codescan = {
        "tool_name": "CodeScan",
        "findings": [
            {
                "id": "f_secret_1",
                "type": "hardcoded_secret",
                "severity": "high",
                "confidence": "high",
                "title": "Hardcoded secret found",
                "description": "API key hardcoded in source.",
                "file_path": "src/config.py",
                "line": 12,
                "evidence": [],
            }
        ],
    }
    screenshot = {
        "tool_name": "ScreenshotAnalyzer",
        "artifacts": {
            "visible_messages": ["Stack trace rendered in browser"],
            "possible_secret_exposure": [{"type": "aws_access_key", "example": "AK***YZ"}],
        },
        "evidence": [
            {
                "id": "e_ocr_text",
                "kind": "ocr",
                "file_path": "/tmp/runtime.png",
                "line": 0,
                "snippet": "AKIA....",
                "note": "OCR text extracted from screenshot",
            }
        ],
        "signals": {"secret_exposure_detected": True},
    }

    result = correlate_tool_results([codescan, screenshot])

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "hardcoded-secret"
    assert finding["signals"]["secret_exposure_detected"] is True

    kinds = {item["kind"] for item in finding["evidence"]}
    assert "screenshot" in kinds
    assert "ocr" in kinds


def test_screenshot_secret_exposure_falls_back_to_highest_severity_finding():
    codescan = {
        "tool_name": "CodeScan",
        "findings": [
            {
                "id": "f_sql_1",
                "type": "sql_injection",
                "severity": "high",
                "confidence": "high",
                "title": "Potential SQL injection",
                "description": "User input reaches query string.",
                "file_path": "src/db.py",
                "line": 41,
                "evidence": [],
            }
        ],
    }
    screenshot = {
        "tool_name": "ScreenshotAnalyzer",
        "artifacts": {
            "visible_messages": ["Token leaked on error page"],
            "possible_secret_exposure": [{"type": "generic_token", "example": "ab***yz"}],
        },
        "evidence": [
            {
                "id": "e_ocr_text",
                "kind": "ocr",
                "file_path": "/tmp/runtime.png",
                "line": 0,
                "snippet": "Token: abcdef...",
                "note": "OCR text extracted from screenshot",
            }
        ],
        "signals": {"secret_exposure_detected": True},
    }

    result = correlate_tool_results([codescan, screenshot])

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["signals"]["secret_exposure_detected"] is True
    assert any(item["kind"] == "screenshot" for item in finding["evidence"])
