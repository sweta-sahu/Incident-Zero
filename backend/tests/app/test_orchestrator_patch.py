"""
Integration checks for orchestrator patch stage wiring.
"""

import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))

from backend.app.orchestrator import run_job
from backend.app.store import job_store


def test_run_job_generates_patch_results(temp_repo, vulnerable_python_code):
    target_file = temp_repo / "src" / "vulnerable.py"
    target_file.write_text(vulnerable_python_code)

    job = job_store.create_job(repo_path=str(temp_repo))
    run_job(job.job_id)

    finished_job = job_store.get_job(job.job_id)
    assert finished_job is not None
    assert finished_job.status == "done"
    assert "patches" in finished_job.result
    assert isinstance(finished_job.result["patches"], list)
    assert len(finished_job.result["patches"]) > 0

    patch_events = [e for e in finished_job.timeline if e.get("stage") == "patch"]
    assert patch_events
    assert "stub" not in patch_events[-1].get("message", "").lower()
