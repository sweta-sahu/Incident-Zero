from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass
class Job:
    job_id: str
    status: str
    repo_path: Optional[str]
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)


class JobStore:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}

    def create_job(self, repo_path: Optional[str]) -> Job:
        job_id = f"job_{uuid4().hex[:8]}"
        job = Job(job_id=job_id, status="running", repo_path=repo_path)
        self._jobs[job_id] = job
        self.add_event(job, stage="ingest", message="Repository received", status="done")
        self.add_event(job, stage="scan", message="CodeScan started", status="in_progress")
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def add_event(self, job: Job, stage: str, message: str, status: str) -> None:
        job.timeline.append(
            {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "stage": stage,
                "message": message,
                "status": status,
            }
        )


job_store = JobStore()