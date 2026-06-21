# SENTINEL — AI Log & Incident Analyst Agent

An end-to-end security log analysis system that ingests raw SSH, web server,
and firewall logs, detects anomalous behavior using a combination of
rule-based heuristics and unsupervised machine learning, and uses a
LangChain + Hugging Face powered agent to triage findings against a
MITRE ATT&CK-style tactic taxonomy and generate analyst-ready incident
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
 │  triage_agent.py     │  LangChain (ChatOpenAI) + Hugging Face Inference
 │ (LangChain + HF)     │  Providers router: MITRE tactic classification,
 │                      │  severity refinement, false-positive flagging,
 │                      │  plain-English analyst summary
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
- **GenAI**: LangChain (`langchain-openai`), Hugging Face Inference
  Providers (routed through `router.huggingface.co`, currently configured
  for DeepSeek-V3, swappable to any model with an active inference
  provider on the Hub)
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
- **Graceful degradation on LLM failure.** The triage and report agents
  wrap the entire LLM call (not just JSON parsing) in exception handling,
  so *any* failure mode — malformed JSON, an unreachable endpoint, an
  auth error, the model being unavailable — falls back to a rule-derived
  result instead of crashing the pipeline. This was tightened after
  testing surfaced that the original implementation only caught JSON
  parsing errors, not network failures; a genuinely unreachable LLM
  endpoint crashed the whole report step until the exception handling
  was widened to wrap the full call.
- **Migrated off a deprecated Hugging Face endpoint.** The project
  originally called `api-inference.huggingface.co` directly through
  `langchain_huggingface`. Hugging Face has since deprecated that
  endpoint in favor of a unified OpenAI-compatible router at
  `router.huggingface.co`, which proxies to 15+ backend inference
  providers. The integration now uses `langchain-openai`'s `ChatOpenAI`
  with a custom `base_url` pointed at the router — this keeps the
  LangChain prompt-templating and chain composition (`ChatPromptTemplate`,
  LCEL `prompt | chat`) intact while talking to a maintained endpoint.
- **Parsing coverage as a tracked metric.** Rather than silently dropping
  unparseable log lines, the system reports what percentage of lines were
  successfully structured. On the bundled sample dataset (mixed SSH,
  web access, and firewall log lines), the parser achieves **68.1%**
  structuring coverage — a real, measured number rather than an
  unverified claim. The shortfall is concentrated in lines that don't
  match any of the three known formats; improving this further is one
  of the open items below.

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
click **Try it with an example** to see the pipeline run against the
bundled sample dataset (`data/sample_logs/`), which includes a simulated
brute force attack, a port scan, and a directory enumeration attempt.

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
   (the dashboard's buttons already pass this by default)

## Known limitations / room for improvement

- **No labeled ground truth.** There's no hand-labeled "is this actually
  malicious" dataset, so there's no real precision/recall number for the
  Isolation Forest layer — only spot-checked behavior.
- **Sparse-activity false positives in Isolation Forest.** IPs with very
  few logged events can get flagged as anomalous purely because their
  feature vector looks different from the bulk of normal traffic, not
  because they're doing anything suspicious. A minimum-activity floor or
  normalizing features by volume would address this.
- **No cross-detector deduplication.** The same IP can be independently
  flagged by a rule-based detector and by Isolation Forest for related
  behavior, producing two separate incidents instead of one correlated
  one.
- **Thresholds are reasonable defaults, not empirically tuned.** The
  brute-force/port-scan/directory-enumeration thresholds and the
  Isolation Forest `contamination` parameter were chosen sensibly but
  not derived from a real traffic baseline.
- **68.1% parsing coverage** on the mixed sample dataset — worth
  improving the regex coverage for edge-case log line formats.

## Possible extensions

- Persist incidents to a database and add a historical trend view
- Add a feedback loop where analysts can mark false positives, feeding
  back into the Isolation Forest's contamination parameter
- Swap the single triage agent for a LangGraph multi-agent setup with
  separate classification, enrichment (e.g. IP reputation lookup), and
  reporting agents
- Add real-time log tailing (watch a live log file) instead of batch upload
- Correlate incidents across detectors/log sources for the same source IP
  instead of treating each detector's output independently

## Resume-ready project description

> **SENTINEL — AI-Powered Security Log Analysis & Incident Triage System**
> Designed and built an end-to-end log analysis pipeline combining
> rule-based intrusion detection, unsupervised anomaly detection
> (Isolation Forest), and a LangChain + Hugging Face LLM agent to
> automatically classify security incidents against a MITRE ATT&CK-style
> taxonomy and generate analyst-ready reports. Implemented a custom
> multi-format log parser (SSH, web access, firewall) with a measured
> 68% parsing coverage on mixed-format sample data, exposed the system
> via a FastAPI backend with a live dashboard, and included unit test
> coverage for all detection logic. Diagnosed and migrated off a
> deprecated Hugging Face inference endpoint mid-project, and hardened
> the LLM integration's exception handling after testing surfaced a gap
> between its intended and actual graceful-degradation behavior.