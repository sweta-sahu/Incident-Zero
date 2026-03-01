import asyncio
import json

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import StreamingResponse

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


@app.get("/events/{job_id}")
async def events(job_id: str, request: Request) -> StreamingResponse:
    job = job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")

    queue = job_store.subscribe(job_id)

    async def stream():
        try:
            for event in job.timeline:
                yield f"data: {json.dumps(event)}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            job_store.unsubscribe(job_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/result/{job_id}")
def result(job_id: str) -> dict:
    job = job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status != "done":
        return {"job_id": job.job_id, "status": job.status, "timeline": job.timeline}
    return job.result