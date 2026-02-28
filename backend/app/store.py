from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import asyncio


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
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}

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
        event = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "stage": stage,
            "message": message,
            "status": status,
        }
        job.timeline.append(event)
        for queue in self._subscribers.get(job.job_id, []):
            queue.put_nowait(event)

    def subscribe(self, job_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_id, []).append(queue)
        return queue

    def unsubscribe(self, job_id: str, queue: asyncio.Queue) -> None:
        queues = self._subscribers.get(job_id)
        if not queues:
            return
        try:
            queues.remove(queue)
        except ValueError:
            return
        if not queues:
            self._subscribers.pop(job_id, None)


job_store = JobStore()
