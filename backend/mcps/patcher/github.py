from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


@dataclass
class GitHubPRConfig:
    """Configuration for PR payload generation and optional PR creation."""

    repo: str = ""
    base_branch: str = "main"
    head_branch: str = "incident-zero/auto-patches"
    token: Optional[str] = None
    open_pr: bool = False
    api_url: str = "https://api.github.com"

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "GitHubPRConfig":
        if not data:
            return cls()
        return cls(
            repo=str(data.get("repo") or "").strip(),
            base_branch=str(data.get("base_branch") or "main").strip(),
            head_branch=str(data.get("head_branch") or "incident-zero/auto-patches").strip(),
            token=data.get("token"),
            open_pr=bool(data.get("open_pr", False)),
            api_url=str(data.get("api_url") or "https://api.github.com").rstrip("/"),
        )


def build_pr_automation_bundle(
    patches: List[Dict[str, Any]],
    github_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a PR-ready payload for GitHub and optionally create a pull request.
    """
    config = GitHubPRConfig.from_dict(github_config)

    bundle: Dict[str, Any] = {
        "enabled": bool(config.repo),
        "repo": config.repo or None,
        "commit_message": _build_commit_message(patches),
        "pull_request": None,
        "creation": {
            "attempted": False,
            "success": False,
            "url": None,
            "error": None,
        },
    }

    if not config.repo:
        return bundle

    payload = {
        "title": "Incident Zero: Automated security patch set",
        "body": _build_pr_body(patches),
        "head": config.head_branch,
        "base": config.base_branch,
        "draft": True,
    }
    bundle["pull_request"] = payload

    if config.open_pr:
        bundle["creation"]["attempted"] = True
        try:
            response = create_pull_request(config, payload)
            bundle["creation"]["success"] = True
            bundle["creation"]["url"] = response.get("html_url")
        except Exception as exc:
            bundle["creation"]["error"] = str(exc)

    return bundle


def create_pull_request(config: GitHubPRConfig, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a pull request using GitHub REST API.

    Notes:
    - This call only works when branch contents already exist remotely.
    - It is intentionally optional and disabled by default.
    """
    if not config.token:
        raise ValueError("GitHub token is required when open_pr=True")
    if not config.repo:
        raise ValueError("GitHub repo is required when open_pr=True")

    url = f"{config.api_url}/repos/{config.repo}/pulls"
    headers = {
        "Authorization": f"Bearer {config.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=20)
    if resp.status_code >= 400:
        raise RuntimeError(f"GitHub PR creation failed ({resp.status_code}): {resp.text}")
    return resp.json()


def _build_commit_message(patches: List[Dict[str, Any]]) -> str:
    if not patches:
        return "chore(security): no automated patches generated"
    return f"fix(security): apply {len(patches)} automated patch(es) from Incident Zero"


def _build_pr_body(patches: List[Dict[str, Any]]) -> str:
    if not patches:
        return "No patches were generated."

    lines = [
        "## Incident Zero Auto-Generated Patch Set",
        "",
        "This PR was prepared by PatchMCP using deterministic security fix templates.",
        "",
        "### Included Patches",
    ]

    for patch in patches:
        lines.append(
            f"- `{patch.get('file_path')}` ({patch.get('id')}): {patch.get('summary')}"
        )

    lines.extend(
        [
            "",
            "### Validation Checklist",
            "- [ ] Review each diff for correctness in context",
            "- [ ] Run unit/integration tests",
            "- [ ] Confirm no behavior regression",
        ]
    )
    return "\n".join(lines)

