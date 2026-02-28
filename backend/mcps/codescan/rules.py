"""
Vulnerability detection rules for CodeScan MCP.
Each rule defines a pattern and scanning logic.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class VulnerabilityRule:
    """Base class for vulnerability rules."""
    
    rule_id: str
    vulnerability_type: str
    severity: str  # "high", "medium", "low"
    confidence: float  # 0.0 to 1.0
    description: str
    patterns: List[str]  # Regex patterns
    
    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Check content against rule patterns.
        
        Args:
            content: File content to scan
            file_path: Path to the file (for context)
            
        Returns:
            List of findings with line numbers and matches
        """
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern in self.patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({
                            "line_number": line_num,
                            "snippet": line.strip(),
                            "confidence": self.confidence,
                            "pattern_used": pattern
                        })
                        break  # Don't double-count same line
                except re.error:
                    pass
        
        return matches


# Define vulnerability rules for Phase 1

RULE_HARDCODED_SECRETS = VulnerabilityRule(
    rule_id="HARDCODED_SECRETS",
    vulnerability_type="hardcoded_secret",
    severity="high",
    confidence=0.95,
    description="Hardcoded secrets detected (API keys, passwords, credentials)",
    patterns=[
        # Generic secrets
        r"api_key\s*=\s*['\"]([a-zA-Z0-9\-_]{8,})['\"]",
        r"api_secret\s*=\s*['\"](.+?)['\"]",
        r"password\s*=\s*['\"](.{4,})['\"]",
        r"secret\s*=\s*['\"](.+?)['\"]",
        r"token\s*=\s*['\"]([a-zA-Z0-9\-_.]{5,})['\"]",
        r"access_key\s*=\s*['\"](.+?)['\"]",
        r"private_key\s*=\s*['\"](.+?)['\"]",
        r"(sk_live|sk_test|pk_live|pk_test)_[a-zA-Z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"aws_access_key_id\s*=\s*['\"](.+?)['\"]",
        r"aws_secret_access_key\s*=\s*['\"](.+?)['\"]",
        r"github_token\s*=\s*['\"]gh[a-zA-Z0-9_]{36,}['\"]",
        r"ghp_[a-zA-Z0-9]{36,}",
        r"(mongodb|postgres|mysql|mssql)://[a-zA-Z0-9:]+:(.+?)@",
        r"db_password\s*=\s*['\"](.+?)['\"]",
        r"database_url\s*=\s*['\"](.+?)@(.+?)['\"]",
        r"firebase_api_key\s*=\s*['\"](.+?)['\"]",
        r"client_secret\s*=\s*['\"]([a-zA-Z0-9\-_]{20,})['\"]",
        r"oauth_token\s*=\s*['\"](.+?)['\"]",
    ]
)

RULE_SQL_INJECTION = VulnerabilityRule(
    rule_id="SQL_INJECTION",
    vulnerability_type="sql_injection",
    severity="high",
    confidence=0.85,
    description="Potential SQL injection vulnerability (unsafe query construction)",
    patterns=[
        r'f["\']SELECT\s+.*?\{',
        r'f["\']INSERT\s+.*?\{',
        r'f["\']UPDATE\s+.*?\{',
        r'f["\']DELETE\s+.*?\{',
        r'f["\']DROP\s+.*?\{',
        r'["\']SELECT\s+.*?["\']\.format\(',
        r'["\']INSERT\s+.*?["\']\.format\(',
        r'["\']UPDATE\s+.*?["\']\.format\(',
        r'["\']DELETE\s+.*?["\']\.format\(',
        r'SELECT.*?["\']?\s*\+\s*',
        r'INSERT.*?["\']?\s*\+\s*',
        r'query\s*=\s*["\'].*?SELECT.*?["\']\s*\+\s*',
        r'query\s*=\s*["\'].*?INSERT.*?["\']\s*\+\s*',
        r'execute\s*\(\s*query\s*\+\s*',
        r'db\.execute\s*\(\s*["\'].*?["\']\s*\+\s*',
        r"WHERE\s+\w+\s*=\s*['\"].*?['\"].*?\+\s*",
        r"WHERE.*?\+\s*user",
        r"WHERE.*?\+\s*request",
        r"WHERE.*?\+\s*input",
    ]
)

RULE_WEAK_CRYPTO = VulnerabilityRule(
    rule_id="WEAK_CRYPTO",
    vulnerability_type="weak_cryptography",
    severity="medium",
    confidence=0.90,
    description="Weak cryptography detected (MD5, SHA1, base64 for passwords)",
    patterns=[
        r'hashlib\.md5\(',
        r'hashlib\.sha1\(',
        r'md5\s*\(',
        r'sha1\s*\(',
        r'\.md5\(',
        r'\.sha1\(',
        r'base64\.b64encode\s*\(\s*password',
        r'base64\.encode\s*\(\s*password',
        r'btoa\s*\(\s*password',
        r'from\s+hashlib\s+import.*?\bmd5\b',
        r'from\s+hashlib\s+import.*?\bsha1\b',
        r'import\s+.*?\bmd5\b',
        r'import\s+.*?\bsha1\b',
        r'crypto\.createHash\s*\(["\']md5["\']',
        r'crypto\.createHash\s*\(["\']sha1["\']',
        r'password_hash\s*=\s*hashlib\.(md5|sha1)',
        r'hashed\s*=\s*(md5|sha1)\(',
    ]
)

# List of all rules to apply
VULNERABILITY_RULES = [
    RULE_HARDCODED_SECRETS,
    RULE_SQL_INJECTION,
    RULE_WEAK_CRYPTO,
]
