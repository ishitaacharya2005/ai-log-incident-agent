"""
main.py
--------
FastAPI application exposing the log analysis pipeline as a web service.

Endpoints:
  GET  /                       -> serves the dashboard UI
  POST /api/analyze            -> upload one or more log files, run full
                                   pipeline (parse -> detect -> triage ->
                                   report), return JSON report
  GET  /api/sample-report      -> run the pipeline against bundled sample
                                   logs (handy for demos without needing
                                   to find/upload real log files)
  GET  /health                 -> basic liveness check
"""

from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.core.log_parser import parse_line, parsing_coverage
from app.core.anomaly_detector import run_all_detectors
from app.agents.triage_agent import triage_all
from app.agents.report_agent import generate_report, report_to_dict
from dotenv import load_dotenv
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOG_DIR = BASE_DIR.parent / "data" / "sample_logs"

app = FastAPI(
    title="AI Log & Incident Analyst Agent",
    description="Parses security logs, detects anomalies via rule-based "
                 "and ML detectors, and uses a LangChain + Hugging Face "
                 "agent to triage and summarize incidents.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _run_pipeline(raw_text: str, use_llm: bool = False) -> dict:
    lines = raw_text.splitlines()
    events = [parse_line(line) for line in lines if line.strip()]
    coverage = parsing_coverage(events)

    incidents = run_all_detectors(events)
    triage_results = triage_all(incidents, use_llm=use_llm)
    report = generate_report(triage_results, use_llm=use_llm)

    result = report_to_dict(report)
    result["parsing_coverage"] = round(coverage, 3)
    result["total_log_lines"] = len(events)
    return result


@app.get("/", response_class=HTMLResponse)
def dashboard():
    html_path = BASE_DIR / "templates" / "index.html"
    return HTMLResponse(html_path.read_text())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(files: list[UploadFile] = File(...), use_llm: bool = False):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    combined_text = ""
    for f in files:
        content = await f.read()
        combined_text += content.decode("utf-8", errors="ignore") + "\n"

    try:
        return _run_pipeline(combined_text, use_llm=use_llm)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


@app.get("/api/sample-report")
def sample_report(use_llm: bool = False):
    combined_text = ""
    for log_file in SAMPLE_LOG_DIR.glob("*.log"):
        combined_text += log_file.read_text() + "\n"

    if not combined_text.strip():
        raise HTTPException(status_code=404, detail="No sample logs found")

    return _run_pipeline(combined_text, use_llm=use_llm)
