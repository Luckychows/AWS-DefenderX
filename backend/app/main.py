from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

from .integrations import build_sinks, emit_findings
from .models import FindingStatus, IngestRequest, IngestResponse, RemediationAction
from .rules.engine import run_rules
from .sample_events import sample_events
from .settings import load_settings
from .store import SqliteFindingsStore, StoreConfig
from .summarizer import RiskSummarizer


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BACKEND_DIR = BASE_DIR.parent

# Load env vars from backend/.env (preferred) or backend/.env.example (fallback).
dotenv_path = BACKEND_DIR / ".env"
dotenv_example_path = BACKEND_DIR / ".env.example"
if dotenv_path.exists():
    load_dotenv(dotenv_path=dotenv_path, override=False)
elif dotenv_example_path.exists():
    load_dotenv(dotenv_path=dotenv_example_path, override=False)

app = FastAPI(title="Cloud Misconfiguration Simulator", version="0.1.0")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

store = SqliteFindingsStore(StoreConfig(sqlite_path=DATA_DIR / "findings.sqlite3"))
summarizer = RiskSummarizer()
settings = load_settings()
alert_sinks = build_sinks(settings)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/ingest", response_model=IngestResponse)
async def ingest(req: IngestRequest) -> IngestResponse:
    findings = run_rules(req.events)
    store.upsert_many(findings)
    await emit_findings(alert_sinks, findings)
    return IngestResponse(
        findings_created=len(findings),
        finding_ids=[f.finding_id for f in findings],
    )


@app.post("/api/simulate/load-sample", response_model=IngestResponse)
async def load_sample() -> IngestResponse:
    return await ingest(IngestRequest(events=sample_events()))


@app.get("/api/findings")
async def list_findings(
    status: Optional[FindingStatus] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
):
    return {"findings": store.list_findings(status=status, limit=limit)}


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str):
    f = store.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": f, "remediations": store.list_remediations(finding_id)}


@app.post("/api/findings/{finding_id}/summarize")
async def summarize_finding(finding_id: str):
    f = store.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    summary = await summarizer.summarize(f)
    store.set_ai_summary(finding_id, summary)
    return {"finding_id": finding_id, "ai_summary": summary}


@app.post("/api/findings/{finding_id}/remediate")
async def remediate_finding(finding_id: str):
    f = store.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Local MVP: we only record the remediation action. AWS implementation comes later.
    action = RemediationAction(
        finding_id=finding_id,
        status="recorded",
        details={
            "note": "Local MVP recorded remediation request. Implement AWS remediation later.",
            "suggested_action": f.recommendation,
        },
    )
    store.add_remediation(action)
    store.update_status(finding_id, FindingStatus.remediated)
    return {"remediation": action, "finding_status": FindingStatus.remediated}

