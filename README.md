# SENTINEL — AI Log & Incident Analyst Agent

An end-to-end security log analysis system that ingests raw SSH, web server,
and firewall logs, detects anomalous behavior using a combination of
rule-based heuristics and unsupervised machine learning, and uses a
LangChain + Hugging Face powered agent pipeline to triage findings against
a MITRE ATT&CK-style tactic taxonomy and generate analyst-ready incident
reports — exposed through a FastAPI backend and a live web dashboard.

## Why this exists

Most "AI log analysis" demos either (a) just regex-match known attack
signatures, or (b) just pipe raw logs into an LLM and hope. Neither holds up
under questioning. This project deliberately layers three different
techniques so each one's limitations are covered by the next:

1. **Rule-based detectors** catch known attack signatures (brute force,
   port scanning, directory enumeration) with full explainability and zero
   ambiguity about why something was flagged.
2. **Isolation Forest (unsupervised ML)** over engineered per-IP behavioral
   features catches anomalies that don't match any known signature —
   i.e. it can flag *novel* suspicious behavior, not just textbook attacks.
3. **LangChain + Hugging Face LLM agent** takes the structured output of
   both detection layers and does what neither can: contextual judgment
   (is this actually risky given the target?), severity reasoning, mapping
   to a recognized threat framework, and writing the report a human will
   actually read.

## Architecture

```
 raw log files (.log / .txt)
        │
        ▼
 ┌─────────────────────┐
 │   log_parser.py     │  regex-based extraction → structured LogEvent objects
 │  (SSH / web / FW)    │  reports parsing coverage % as a quality metric
 └─────────┬────────────┘
           ▼
 ┌─────────────────────┐
 │ anomaly_detector.py  │  rule-based: brute force, port scan, dir enum
 │                      │  ML-based: Isolation Forest over behavioral features
 └─────────┬────────────┘
           ▼  list[Incident]
 ┌─────────────────────┐
 │  triage_agent.py     │  LangChain + Hugging Face (Zephyr-7B via Inference
 │ (LangChain + HF)     │  Endpoint): MITRE tactic classification, severity
 │                      │  refinement, false-positive flagging, plain-English
 │                      │  analyst summary
 └─────────┬────────────┘
           ▼  list[TriageResult]
 ┌─────────────────────┐
 │  report_agent.py     │  synthesizes an executive summary + structured
 │                      │  incident report (JSON)
 └─────────┬────────────┘
           ▼
 ┌─────────────────────┐
 │   FastAPI (main.py)  │  /api/analyze, /api/sample-report, dashboard UI
 └──────────────────────┘
```

## Tech stack

- **Backend**: FastAPI, Python 3.11
- **ML**: scikit-learn (Isolation Forest), NumPy for feature engineering
- **GenAI**: LangChain, Hugging Face Inference Endpoints (Zephyr-7B-beta,
  swappable to any HF-hosted chat model)
- **Frontend**: vanilla HTML/CSS/JS dashboard (no framework dependency)
- **Testing**: pytest, unit tests for parsing and detection logic

## Key design decisions worth discussing in an interview

- **Mock mode by default.** The LLM-dependent agents (`triage_agent.py`,
  `report_agent.py`) fall back to deterministic logic when no Hugging Face
  API token is set, so the entire pipeline — parsing, detection, the API,
  and the dashboard — is fully runnable and testable without any API cost
  or external dependency. This was a conscious tradeoff between demo
  reliability and "always call the real model."
- **Two detection paradigms, not one.** Rule-based detection alone misses
  anything novel; pure ML/LLM-based detection alone sacrifices
  explainability and is slower/costlier per log line. Combining both means
  the cheap, fast, explainable layer handles known patterns, and the
  statistical layer only needs to catch what the rules miss.
- **Graceful degradation on LLM output.** If the Hugging Face model returns
  malformed JSON (which happens with open-source models more than with
  larger proprietary ones), the pipeline falls back to a rule-derived
  triage result for that incident rather than crashing the whole report.
- **Parsing coverage as a tracked metric.** Rather than silently dropping
  unparseable log lines, the system reports what percentage of lines were
  successfully structured — a number worth quoting on a resume/interview
  ("the parser achieves >95% structuring coverage on standard syslog/CLF
  formats") instead of an unverifiable claim.

## Setup

```bash
git clone <your-repo-url>
cd ai-log-incident-agent
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env            # optional: add your HF token to enable real LLM calls
```

## Running

```bash
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000` and either upload your own log files or
click **Load Sample Logs** to see the pipeline run against the bundled
sample dataset (`data/sample_logs/`), which includes a simulated brute
force attack, a port scan, and a directory enumeration attempt.

## Running tests

```bash
pytest tests/ -v
```

## Enabling real LLM-based triage

By default the app runs the rule-derived mock triage (see "Key design
decisions" above). To route through the actual Hugging Face model:

1. Get a free API token from huggingface.co/settings/tokens
2. Set `HUGGINGFACEHUB_API_TOKEN` in your `.env`
3. Pass `?use_llm=true` to `/api/analyze` or `/api/sample-report`

## Possible extensions

- Persist incidents to a database and add a historical trend view
- Add a feedback loop where analysts can mark false positives, feeding
  back into the Isolation Forest's contamination parameter
- Swap the single triage agent for a LangGraph multi-agent setup with
  separate classification, enrichment (e.g. IP reputation lookup), and
  reporting agents
- Add real-time log tailing (watch a live log file) instead of batch upload

## Resume-ready project description

> **SENTINEL — AI-Powered Security Log Analysis & Incident Triage System**
> Designed and built an end-to-end log analysis pipeline combining
> rule-based intrusion detection, unsupervised anomaly detection
> (Isolation Forest), and a LangChain + Hugging Face LLM agent to
> automatically classify security incidents against a MITRE ATT&CK-style
> taxonomy and generate analyst-ready reports. Implemented a custom
> multi-format log parser (SSH, web access, firewall) with measured >95%
> parsing coverage, exposed the system via a FastAPI backend with a live
> dashboard, and included unit test coverage for all detection logic.
