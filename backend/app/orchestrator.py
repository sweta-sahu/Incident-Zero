from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.mcps.codescan.scanner import scan_repository
from backend.mcps.diagram_extractor.run import run as run_diagram_extractor
from backend.mcps.log_reasoner.run import run as run_log_reasoner
from backend.mcps.diagram_extractor.run import run as run_diagram_extractor
from backend.mcps.patcher.generator import generate_patches
from backend.mcps.screenshot_analyzer.run import run as run_screenshot_analyzer

from .correlator import correlate_tool_results
from .graph import build_attack_graph
from .store import Job, job_store


STUB_STAGES: List[Dict[str, str]] = [
    {"stage": "finalize", "message": "Result bundle ready", "status": "done"},
]


def run_job(job_id: str) -> None:
    job = job_store.get_job(job_id)
    if job is None:
        return

    repo_path = str(job.repo_path or "").strip()

    try:
        if not repo_path:
            _mark_job_error(job, stage="scan", message="No repo_path provided")
            return

        if _looks_like_remote_repo(repo_path):
            _mark_job_error(
                job,
                stage="scan",
                message=(
                    "repo_path is a remote URL. Provide a local repository path; "
                    "auto-clone is not supported yet."
                ),
            )
            return

        resolved_repo_path = _resolve_repo_path(repo_path)
        if resolved_repo_path is None:
            _mark_job_error(job, stage="scan", message=f"Invalid repo_path syntax: {repo_path}")
            return

        if not Path(resolved_repo_path).exists():
            _mark_job_error(
                job,
                stage="scan",
                message=f"Repository path does not exist: {resolved_repo_path}",
            )
            return

        tool_result = scan_repository(resolved_repo_path)
        total_findings = (tool_result.get("meta") or {}).get("total_findings", 0)
        job_store.add_event(
            job,
            stage="scan",
            message=f"CodeScan completed ({total_findings} findings)",
            status="done",
        )

        job_store.add_event(
            job,
            stage="correlate",
            message="Correlation started",
            status="in_progress",
        )

        tool_results: List[Dict[str, Any]] = [tool_result]
        diagram_result: Optional[Dict[str, Any]] = None

        if job.log_path:
            log_result = run_log_reasoner(job.log_path, context={"repo_path": resolved_repo_path})
            tool_results.append(log_result)
            job_store.add_event(
                job,
                stage="correlate",
                message=_multimodal_event_message(
                    "Log parser MCP completed", log_result.get("errors")
                ),
                status="done",
            )

        if job.screenshot_path:
            screenshot_result = run_screenshot_analyzer(
                job.screenshot_path,
                context={"repo_path": resolved_repo_path},
            )
            tool_results.append(screenshot_result)
            job_store.add_event(
                job,
                stage="correlate",
                message=_multimodal_event_message(
                    "Screenshot analyzer MCP completed", screenshot_result.get("errors")
                ),
                status="done",
            )

        if getattr(job, "diagram_path", None):
            diagram_result = run_diagram_extractor(
                job.diagram_path,
                context={"repo_path": resolved_repo_path},
            )
            tool_results.append(diagram_result)
            job_store.add_event(
                job,
                stage="correlate",
                message=_multimodal_event_message(
                    "Diagram extractor MCP completed", diagram_result.get("errors")
                ),
                status="done",
            )

        correlation = correlate_tool_results(tool_results)
        job_store.add_event(
            job,
            stage="correlate",
            message="Correlation complete",
            status="done",
        )

        graph = build_attack_graph(correlation["findings"])
        job_store.add_event(
            job,
            stage="graph",
            message="Attack graph built",
            status="done",
        )

        patch_result = generate_patches(correlation["findings"], repo_path=resolved_repo_path)
        patch_count = (patch_result.get("meta") or {}).get("generated_patches", 0)
        job_store.add_event(
            job,
            stage="patch",
            message=f"Patch generation complete ({patch_count} patches)",
            status="done",
        )

        for event in STUB_STAGES:
            job_store.add_event(job, **event)

        job.status = "done"
        job.result = {
            "job_id": job.job_id,
            "status": job.status,
            "findings": correlation["findings"],
            "graph": graph,
            "patches": patch_result.get("patches", []),
            "manual_fix_recommendations": patch_result.get("manual_fix_recommendations", []),
            "timeline": job.timeline,
            "summary": correlation["summary"],
            "diagram": diagram_result,
        }
    except Exception as exc:
        _mark_job_error(job, stage="finalize", message=f"Pipeline failed: {exc}")


def _resolve_repo_path(repo_path: str) -> Optional[str]:
    try:
        return str(Path(repo_path).resolve())
    except OSError:
        return None


def _looks_like_remote_repo(value: str) -> bool:
    lower = value.lower()
    if lower.startswith(("http://", "https://", "ssh://", "git://")):
        return True
    return value.startswith("git@")


def _mark_job_error(job: Job, stage: str, message: str) -> None:
    job_store.add_event(job, stage=stage, message=message, status="error")
    job.status = "error"
    job.result = {
        "job_id": job.job_id,
        "status": job.status,
        "findings": [],
        "graph": {"nodes": [], "edges": [], "top_paths": []},
        "patches": [],
        "manual_fix_recommendations": [],
        "timeline": job.timeline,
        "summary": message,
    }


def _multimodal_event_message(base: str, errors: Any) -> str:
    error_count = len(errors or [])
    if error_count == 0:
        return base
    return f"{base} with {error_count} issue(s)"
