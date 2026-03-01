"""
Tests for PatchMCP generation and PR automation payloads.
"""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcps.patcher.generator import generate_patches


def test_generate_hardcoded_secret_patch_python(temp_repo):
    target = temp_repo / "src" / "config.py"
    target.write_text('API_KEY = "sk_live_1234567890abcdef"\n')

    findings = [
        {
            "id": "f_secret_1",
            "type": "hardcoded-secret",
            "file_path": "src/config.py",
            "line": 1,
        }
    ]

    result = generate_patches(findings, str(temp_repo))
    assert result["tool"] == "patcher"
    assert len(result["patches"]) == 1

    patch = result["patches"][0]
    assert patch["finding_id"] == "f_secret_1"
    assert patch["file_path"] == "src/config.py"
    assert "--- a/src/config.py" in patch["diff"]
    assert "+++ b/src/config.py" in patch["diff"]
    assert 'os.environ.get("API_KEY", "")' in patch["diff"]


def test_generate_sql_injection_patch_python(temp_repo):
    target = temp_repo / "src" / "db.py"
    target.write_text(
        "def run(user_id):\n"
        '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "    return db.execute(query)\n"
    )

    findings = [
        {
            "id": "f_sql_1",
            "type": "sql-injection",
            "file_path": "src/db.py",
            "line": 2,
        }
    ]

    result = generate_patches(findings, str(temp_repo))
    assert len(result["patches"]) == 1
    patch = result["patches"][0]
    assert patch["finding_id"] == "f_sql_1"
    assert "parameterized template" in patch["summary"].lower()
    assert "%s" in patch["diff"]


def test_generate_patches_skips_unsupported_type(temp_repo):
    target = temp_repo / "src" / "app.py"
    target.write_text("x = 1\n")

    findings = [
        {
            "id": "f_unknown_1",
            "type": "weak-cryptography",
            "file_path": "src/app.py",
            "line": 1,
        }
    ]

    result = generate_patches(findings, str(temp_repo))
    assert len(result["patches"]) == 0
    assert result["meta"]["skipped_findings"] == 1


def test_generate_patches_builds_github_pr_payload(temp_repo):
    target = temp_repo / "src" / "config.js"
    target.write_text('const API_KEY = "sk_test_abcdef1234567890";\n')

    findings = [
        {
            "id": "f_secret_js_1",
            "type": "hardcoded-secret",
            "file_path": "src/config.js",
            "line": 1,
        }
    ]

    github_config = {
        "repo": "owner/example-repo",
        "base_branch": "main",
        "head_branch": "incident-zero/auto-patches",
        "open_pr": False,
    }
    result = generate_patches(findings, str(temp_repo), github_config=github_config)

    assert len(result["patches"]) == 1
    assert result["github"]["enabled"] is True
    assert result["github"]["repo"] == "owner/example-repo"
    assert result["github"]["pull_request"] is not None
    assert result["github"]["pull_request"]["base"] == "main"
    assert result["github"]["pull_request"]["head"] == "incident-zero/auto-patches"
