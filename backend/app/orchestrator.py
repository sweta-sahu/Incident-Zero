from __future__ import annotations

from typing import Dict, List

from backend.mcps.codescan.scanner import scan_repository
from backend.mcps.patcher.generator import generate_patches

from .correlator import correlate_tool_results
from .graph import build_attack_graph
from .store import job_store


STUB_STAGES: List[Dict[str, str]] = [
    {"stage": "finalize", "message": "Result bundle ready", "status": "done"},
]


def run_job(job_id: str) -> None:
    job = job_store.get_job(job_id)
    if job is None:
        return

    if not job.repo_path:
        job_store.add_event(
            job,
            stage="scan",
            message="No repo_path provided",
            status="error",
        )
        job.status = "error"
        job.result = {
            "job_id": job.job_id,
            "status": job.status,
            "findings": [],
            "graph": {"nodes": [], "edges": [], "top_paths": []},
            "patches": [],
            "timeline": job.timeline,
            "summary": "No repo_path provided; scan skipped.",
        }
        return

    tool_result = scan_repository(job.repo_path)
    total_findings = (tool_result.get("meta") or {}).get("total_findings", 0)
    job_store.add_event(
        job,
        stage="scan",
        message=f"CodeScan completed ({total_findings} findings)",
        status="done",
    )

    correlation = correlate_tool_results([tool_result])
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

    patch_result = generate_patches(correlation["findings"], repo_path=job.repo_path)
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
        "timeline": job.timeline,
        "summary": correlation["summary"],
    }