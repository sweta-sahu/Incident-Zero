"""
CodeScan MCP - Pattern-based vulnerability detection module.
Responsible for static code analysis and finding extraction.
"""

from .scanner import scan_repository
from .rules import VULNERABILITY_RULES

__all__ = ["scan_repository", "VULNERABILITY_RULES"]
