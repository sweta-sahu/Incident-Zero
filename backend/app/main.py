from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from .orchestrator import run_job
from .store import job_store


class AnalyzeRequest(BaseModel):
    repo_path: str | None = None


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str


app = FastAPI(title="Incident Zero API")


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks) -> AnalyzeResponse:
    job = job_store.create_job(repo_path=req.repo_path)
    background_tasks.add_task(run_job, job.job_id)
    return AnalyzeResponse(job_id=job.job_id, status=job.status)


@app.get("/status/{job_id}")
def status(job_id: str) -> dict:
    job = job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job.job_id, "status": job.status, "timeline": job.timeline}


@app.get("/result/{job_id}")
def result(job_id: str) -> dict:
    job = job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status != "done":
        return {"job_id": job.job_id, "status": job.status, "timeline": job.timeline}
    return job.result