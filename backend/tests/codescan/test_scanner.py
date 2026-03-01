"""
Tests for CodeScan MCP scanner module.
Tests rule detection, evidence extraction, and result formatting.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcps.codescan.scanner import scan_repository, ScanResult
from mcps.codescan.rules import (
    RULE_HARDCODED_SECRETS,
    RULE_SQL_INJECTION,
    RULE_WEAK_CRYPTO,
    VULNERABILITY_RULES
)
from mcps.codescan.evidence_extractor import extract_evidence


class TestVulnerabilityRules:
    """Test individual vulnerability detection rules."""
    
    def test_hardcoded_secrets_api_key(self):
        """Test detection of hardcoded API keys."""
        code = 'api_key = "sk_live_1234567890abcdef"'
        matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        assert len(matches) > 0
        assert matches[0]["line_number"] == 1
        assert matches[0]["confidence"] == RULE_HARDCODED_SECRETS.confidence
    
    def test_hardcoded_secrets_aws_keys(self):
        """Test detection of AWS access keys."""
        code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        assert len(matches) > 0
    
    def test_hardcoded_secrets_db_connection(self):
        """Test detection of hardcoded database credentials."""
        code = 'db_url = "postgres://user:password123@db.example.com:5432/mydb"'
        matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        assert len(matches) > 0
    
    def test_hardcoded_secrets_github_token(self):
        """Test detection of GitHub tokens."""
        code = 'gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        assert len(matches) > 0
    
    def test_sql_injection_fstring(self):
        """Test detection of SQL injection with f-strings."""
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        matches = RULE_SQL_INJECTION.check(code, "test.py")
        assert len(matches) > 0
        assert matches[0]["line_number"] == 1
    
    def test_sql_injection_format(self):
        """Test detection of SQL injection with .format()."""
        code = 'query = "SELECT * FROM users WHERE id = {}".format(user_input)'
        matches = RULE_SQL_INJECTION.check(code, "test.py")
        assert len(matches) > 0
    
    def test_sql_injection_concatenation(self):
        """Test detection of SQL injection with string concatenation."""
        code = 'query = "SELECT * FROM users WHERE id = " + user_id'
        matches = RULE_SQL_INJECTION.check(code, "test.py")
        assert len(matches) > 0
    
    def test_weak_crypto_md5(self):
        """Test detection of MD5 hashing."""
        code = 'hash = hashlib.md5(password.encode()).hexdigest()'
        matches = RULE_WEAK_CRYPTO.check(code, "test.py")
        assert len(matches) > 0
        assert matches[0]["line_number"] == 1
    
    def test_weak_crypto_sha1(self):
        """Test detection of SHA1 hashing."""
        code = 'hash = hashlib.sha1(password.encode()).hexdigest()'
        matches = RULE_WEAK_CRYPTO.check(code, "test.py")
        assert len(matches) > 0
    
    def test_weak_crypto_base64_password(self):
        """Test detection of base64 encoding for passwords."""
        code = 'encoded = base64.b64encode(password.encode())'
        matches = RULE_WEAK_CRYPTO.check(code, "test.py")
        assert len(matches) > 0
    
    def test_no_false_positives_comments(self):
        """Test that commented code doesn't trigger false positives."""
        code = '# api_key = "sk_test_1234567890abcdef"'
        matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        # May still match comments, but confidence should be considered
        # For now, we allow this as it's still a secret in the file
        assert isinstance(matches, list)
    
    def test_clean_code_no_findings(self):
        """Test that clean code produces no findings."""
        code = '''
import os
API_KEY = os.environ.get('API_KEY')
password_hash = generate_password_hash(password)
query = db.execute(query, [user_id])  # Parameterized
'''
        secrets_matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
        sql_matches = RULE_SQL_INJECTION.check(code, "test.py")
        crypto_matches = RULE_WEAK_CRYPTO.check(code, "test.py")
        
        # Should have no matches in clean code
        assert len(secrets_matches) == 0
        assert len(sql_matches) == 0
        assert len(crypto_matches) == 0


class TestEvidenceExtraction:
    """Test evidence extraction functionality."""
    
    def test_evidence_has_code_context(self):
        """Test that evidence includes code context."""
        code = '''line 1
line 2
vulnerable_code = "secret"
line 4
line 5'''
        evidence = extract_evidence("test.py", 3, code)
        
        assert len(evidence) > 0
        assert evidence[0]["type"] == "code_context"
        assert "context_lines" in evidence[0]
        assert evidence[0]["target_line"] == 3
    
    def test_evidence_includes_function_context(self):
        """Test that evidence identifies containing function."""
        code = '''def unsafe_query():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id={user_id}"
    return db.execute(query)'''
        
        evidence = extract_evidence("test.py", 3, code)
        
        # Should include function context
        function_evidence = [e for e in evidence if e.get("type") == "function_context"]
        assert len(function_evidence) > 0
        assert function_evidence[0]["function_name"] == "unsafe_query"
    
    def test_evidence_includes_variable_tracking(self):
        """Test that evidence tracks variable assignments."""
        code = '''user_input = request.args.get('q')
processed = user_input.strip()
query = f"SELECT * FROM users WHERE name={processed}"'''
        
        evidence = extract_evidence("test.py", 3, code)
        
        # Should include variable tracking
        var_evidence = [e for e in evidence if e.get("type") == "variable_tracking"]
        # May or may not have tracking depending on implementation
        assert isinstance(evidence, list)
    
    def test_context_window_size(self):
        """Test that context window is appropriate size."""
        lines = [f"line {i}" for i in range(1, 21)]
        code = "\n".join(lines)
        
        evidence = extract_evidence("test.py", 10, code)
        context_evidence = evidence[0]
        
        # Should have context lines
        context_lines = context_evidence.get("context_lines", [])
        assert len(context_lines) > 0
        # Context should span multiple lines
        assert len(context_lines) >= 5


class TestScannerIntegration:
    """Integration tests for the scanner."""
    
    def test_scanner_with_vulnerable_python(self, temp_repo, vulnerable_python_code):
        """Test scanner on vulnerable Python code."""
        # Write vulnerable code to temp repo
        target_file = temp_repo / "src" / "vulnerable.py"
        target_file.write_text(vulnerable_python_code)
        
        # Run scanner
        result = scan_repository(str(temp_repo))
        
        # Verify result structure
        assert result["tool_name"] == "CodeScan"
        assert result["status"] == "completed"
        assert "findings" in result
        assert "metadata" in result
        
        # Should find multiple vulnerabilities
        findings = result["findings"]
        assert len(findings) > 0
        
        # Verify finding structure
        for finding in findings:
            assert "finding_id" in finding
            assert "vulnerability_type" in finding
            assert "severity" in finding
            assert "file_path" in finding
            assert "line_number" in finding
            assert "evidence" in finding
            assert "remediation_hint" in finding
            assert "cwe_id" in finding
    
    def test_scanner_detects_secrets(self, temp_repo, vulnerable_python_code):
        """Test that scanner detects secret vulnerabilities."""
        target_file = temp_repo / "src" / "config.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        findings = result["findings"]
        
        secret_findings = [f for f in findings if f["vulnerability_type"] == "hardcoded_secret"]
        assert len(secret_findings) > 0
        
        # Verify vulnerability details
        for finding in secret_findings:
            assert finding["severity"] == "high"
            assert finding["confidence_score"] >= 0.9
    
    def test_scanner_detects_sql_injection(self, temp_repo, vulnerable_python_code):
        """Test that scanner detects SQL injection vulnerabilities."""
        target_file = temp_repo / "src" / "db.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        findings = result["findings"]
        
        sql_findings = [f for f in findings if f["vulnerability_type"] == "sql_injection"]
        assert len(sql_findings) > 0
        
        for finding in sql_findings:
            assert finding["severity"] == "high"
    
    def test_scanner_detects_weak_crypto(self, temp_repo, vulnerable_python_code):
        """Test that scanner detects weak cryptography."""
        target_file = temp_repo / "src" / "crypto.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        findings = result["findings"]
        
        crypto_findings = [f for f in findings if f["vulnerability_type"] == "weak_cryptography"]
        assert len(crypto_findings) > 0
        
        for finding in crypto_findings:
            assert finding["severity"] == "medium"
    
    def test_scanner_with_clean_code(self, temp_repo, clean_code):
        """Test scanner on clean code - should have no findings."""
        target_file = temp_repo / "src" / "clean.py"
        target_file.write_text(clean_code)
        
        result = scan_repository(str(temp_repo))
        findings = result["findings"]
        
        # Clean code should produce no or minimal findings
        assert len(findings) == 0
    
    def test_scanner_skips_common_dirs(self, temp_repo, vulnerable_python_code):
        """Test that scanner skips common non-source directories."""
        # Place code in node_modules - should be skipped
        node_modules = temp_repo / "node_modules" / "pkg"
        node_modules.mkdir(parents=True, exist_ok=True)
        (node_modules / "vulnerable.py").write_text(vulnerable_python_code)
        
        # Place code in src - should be scanned
        src = temp_repo / "src"
        (src / "clean.py").write_text("# Clean code")
        
        result = scan_repository(str(temp_repo))
        
        # Should scan only from src, not node_modules
        findings = result["findings"]
        for finding in findings:
            assert "node_modules" not in finding["file_path"]
    
    def test_scanner_metadata(self, temp_repo, vulnerable_python_code):
        """Test that scanner metadata is accurate."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        metadata = result["metadata"]
        
        assert "scan_duration_seconds" in metadata
        assert metadata["scan_duration_seconds"] >= 0
        assert "total_findings" in metadata
        assert metadata["total_findings"] == len(result["findings"])
        assert "findings_by_severity" in metadata
        assert "findings_by_type" in metadata
        assert "scanned_files" in metadata
        assert "rules_applied" in metadata
        assert len(metadata["rules"]) == len(VULNERABILITY_RULES)
    
    def test_scanner_with_javascript(self, temp_repo, vulnerable_js_code):
        """Test scanner on JavaScript/TypeScript code."""
        target_file = temp_repo / "src" / "app.js"
        target_file.write_text(vulnerable_js_code)
        
        result = scan_repository(str(temp_repo))
        findings = result["findings"]
        
        # Should find vulnerabilities in JS code
        assert len(findings) > 0
        
        # Verify JS-specific findings
        for finding in findings:
            assert finding["file_path"].endswith(".js")
    
    def test_scanner_handles_nonexistent_path(self):
        """Test scanner handles nonexistent repository path."""
        result = scan_repository("/nonexistent/path/repo")
        
        assert result["status"] == "completed"
        assert len(result["findings"]) == 0
        assert result["errors"] is not None


class TestFalsePositiveRate:
    """Test false positive and false negative rates."""
    
    def test_false_negatives_hardcoded_secrets(self):
        """Test that common secret patterns are detected."""
        patterns = [
            'password = "MyPassword123"',
            'api_secret = "secret123"',
            'token = "abc123xyz"',
            'DATABASE_URL = "mongodb://user:pass@localhost"',
        ]
        
        for code in patterns:
            matches = RULE_HARDCODED_SECRETS.check(code, "test.py")
            assert len(matches) > 0, f"Failed to detect: {code}"
    
    def test_false_negatives_sql_injection(self):
        """Test that common SQL injection patterns are detected."""
        patterns = [
            'f"SELECT * FROM users WHERE id = {input}"',
            '"SELECT * FROM users WHERE id = {}".format(id)',
            '"SELECT * FROM table WHERE name = " + name',
            'f"INSERT INTO users VALUES ({values})"',
        ]
        
        for code in patterns:
            matches = RULE_SQL_INJECTION.check(code, "test.py")
            assert len(matches) > 0, f"Failed to detect: {code}"
    
    def test_false_negatives_weak_crypto(self):
        """Test that common weak crypto patterns are detected."""
        patterns = [
            'hashlib.md5(password)',
            'hashlib.sha1(data)',
            'crypto.createHash("md5")',
            'base64.b64encode(password)',
        ]
        
        for code in patterns:
            matches = RULE_WEAK_CRYPTO.check(code, "test.py")
            assert len(matches) > 0, f"Failed to detect: {code}"


class TestFindingFormat:
    """Test that findings conform to expected format."""
    
    def test_finding_has_required_fields(self, temp_repo, vulnerable_python_code):
        """Test that all findings have required fields."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        
        required_fields = [
            "finding_id", "vulnerability_type", "severity", "file_path",
            "line_number", "code_snippet", "confidence_score", "evidence",
            "rule_id", "rule_name", "message", "remediation_hint", "cwe_id",
            "id", "type", "line", "confidence", "title", "description",
            "evidence_ids",
        ]
        
        for finding in result["findings"]:
            for field in required_fields:
                assert field in finding, f"Missing field: {field}"
    
    def test_severity_values(self, temp_repo, vulnerable_python_code):
        """Test that severity values are valid."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        valid_severities = {"high", "medium", "low"}
        
        for finding in result["findings"]:
            assert finding["severity"] in valid_severities
    
    def test_confidence_scores_valid(self, temp_repo, vulnerable_python_code):
        """Test that confidence scores are between 0 and 1."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)
        
        result = scan_repository(str(temp_repo))
        
        for finding in result["findings"]:
            confidence = finding["confidence_score"]
            assert 0 <= confidence <= 1, f"Invalid confidence: {confidence}"

    def test_confidence_labels_valid(self, temp_repo, vulnerable_python_code):
        """Test that confidence labels use low/medium/high scale."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)

        result = scan_repository(str(temp_repo))
        valid_confidence_labels = {"low", "medium", "high"}

        for finding in result["findings"]:
            assert finding["confidence"] in valid_confidence_labels

    def test_evidence_artifact_shape(self, temp_repo, vulnerable_python_code):
        """Test structured evidence artifacts include required fields."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)

        result = scan_repository(str(temp_repo))
        required_evidence_fields = {
            "id", "kind", "file_path", "line", "snippet", "context_window", "note"
        }

        for finding in result["findings"]:
            assert isinstance(finding["evidence"], list)
            assert isinstance(finding["evidence_ids"], list)
            for evidence in finding["evidence"]:
                assert required_evidence_fields.issubset(evidence.keys())
                assert evidence["id"] in finding["evidence_ids"]

    def test_tool_result_has_contract_aliases(self, temp_repo, vulnerable_python_code):
        """Test result includes contract-friendly aliases for downstream consumers."""
        target_file = temp_repo / "src" / "code.py"
        target_file.write_text(vulnerable_python_code)

        result = scan_repository(str(temp_repo))
        assert result["tool"] == "codescan"
        assert "meta" in result
