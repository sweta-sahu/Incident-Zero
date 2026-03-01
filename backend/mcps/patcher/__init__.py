"""
PatchMCP module exports.
"""

from .generator import generate_patches
from .github import GitHubPRConfig, build_pr_automation_bundle

__all__ = ["generate_patches", "GitHubPRConfig", "build_pr_automation_bundle"]

