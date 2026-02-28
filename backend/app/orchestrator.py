from __future__ import annotations

from typing import Dict, List

from .store import job_store


STAGES: List[Dict[str, str]] = [
    {"stage": "scan", "message": "CodeScan completed", "status": "done"},
    {"stage": "correlate", "message": "Correlation complete", "status": "done"},
    {"stage": "graph", "message": "Attack graph built", "status": "done"},
    {"stage": "patch", "message": "Patch generation complete", "status": "done"},
    {"stage": "finalize", "message": "Result bundle ready", "status": "done"},
]


def run_job(job_id: str) -> None:
    job = job_store.get_job(job_id)
    if job is None:
        return

    for event in STAGES:
        job_store.add_event(job, **event)

    job.status = "done"
    job.result = {
        "job_id": job.job_id,
        "status": job.status,
        "findings": [],
        "graph": {"nodes": [], "edges": [], "top_paths": []},
        "patches": [],
        "timeline": job.timeline,
        "summary": "No findings yet. MCPs not wired in.",
    }