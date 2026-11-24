# SentinelPR — Autonomous DevSecOps & Security Remediation Agent

SentinelPR is an agentic pull-request security auditor and remediation workflow powered by **LangGraph**, **FastAPI**, and **Next.js**. It inspects GitHub pull requests, checks dependencies against **OSV** advisories, scrubs sensitive data and PII via regex and **Microsoft Presidio**, enforces prompt/input guardrails, and routes side-effecting actions through a **Human-in-the-Loop (HITL)** approval gate with real-time execution telemetry.

---

## Architecture & Workflow

SentinelPR models PR auditing and remediation as a deterministic state machine with explicit observability and human approval checkpoints:

1. **Guardrail & Scrubbing Layer:** Validates incoming prompts/inputs, strips secrets and PII (regex + Microsoft Presidio), and blocks prompt-injection attempts before downstream model calls.
2. **Planner & State Orchestration (LangGraph):** Coordinates read-only inspection (`fetch_github_pr`, vulnerability/OSV checks) and remediation planning while streaming node transitions and timings to the UI telemetry panel.
3. **Human-in-the-Loop (HITL) Gate:** Pauses execution before any external write or remediation action (such as commenting or opening a fix PR) until an engineer explicitly approves or rejects.
4. **Operator Console (Next.js + FastAPI):** Pairs a conversational audit thread with live X-Ray node telemetry (`guardrail`, `planner`, `read_tools`, execution status).

---

## Project Structure

```text
sentinel-pr/
├── apps/
│   ├── api/                        # FastAPI backend & LangGraph state machine
│   │   └── app/
│   │       ├── main.py             # API entry point & SSE/streaming endpoints
│   │       ├── agent.py            # LangGraph graph definition, state & HITL flow
│   │       ├── safety.py           # Guardrails, injection filters & PII/secret scrubbing
│   │       ├── tools.py            # GitHub PR fetcher, OSV & remediation tools
│   │       └── config.py           # Environment & runtime configuration
│   └── web/                        # Next.js operator UI & telemetry workbench
│       └── src/
│           └── app/                # App Router views, chat thread & X-Ray panel
├── docker-compose.yml              # Multi-service local/container orchestration
└── .gitignore                      # Excludes .env, virtualenvs & build artifacts
```

---

## Engineering Challenges & Solutions

### 1. Security-Prompt False Positives in Guardrails
* **Challenge:** Strict injection patterns frequently flagged legitimate security audit prompts containing terms like `ignore`, `override`, `exploit`, or raw diff snippets discussing vulnerabilities.
* **Solution:** Tuned `OBVIOUS_INJECTION_PATTERNS` to target adversarial instruction-hijacking structures rather than domain security vocabulary, reducing false blocks during real PR audits.

### 2. Upstream Quota & Transient Errors (`429` / `503`) During Testing
* **Challenge:** Rate limits or transient upstream availability errors (`429`, `503`) can stall iterative development and evaluation runs.
* **Solution:** Added a controlled fail-open fallback path for quota/transient outages during testing so workflows surface degraded status clearly instead of crashing mid-run.

### 3. Preventing Unintended Write Actions in Autonomous Agents
* **Challenge:** Giving an LLM direct write access to repositories or PR comments creates high blast radius if a model hallucinates a patch or misreads a diff.
* **Solution:** Separated read-only PR inspection from write/remediation actions behind an explicit **Human-in-the-Loop (HITL)** approval gate—clean read-only audits finish directly, while actionable writes require human sign-off.

### 4. Secrets & PII Leakage in Logs, Prompts, and Diffs
* **Challenge:** PR diffs, issue bodies, and user prompts can contain tokens, credentials, or personal identifiers that should never leak into logs or unredacted downstream contexts.
* **Solution:** Combined deterministic regex secret matching with **Microsoft Presidio** entity scrubbing and enforced strict `.gitignore` rules so local `.env` secrets never enter version control.

---

## Local Development

### 1. Backend API (`apps/api`)
```powershell
cd apps\api
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

### 2. Frontend Workbench (`apps/web`)
```powershell
cd apps\web
npm run dev
```

Open `http://localhost:3000`, start a **New Thread**, and submit a public GitHub Pull Request URL (e.g., `https://github.com/pallets/flask/pull/5918`) to inspect the audit report and X-Ray telemetry.

---

## Security & Trust Boundaries

* **Untrusted Inputs:** Pull request diffs, PR descriptions, and external repository metadata are treated as untrusted data that may contain prompt-injection payloads or sensitive tokens.
* **Data Sanitization:** Secrets and PII are scrubbed before downstream model calls using regex patterns and **Microsoft Presidio**, while local `.env` files stay excluded via `.gitignore`.
* **Action Gating:** Read-only inspection (`fetch_github_pr`, vulnerability checks) runs without side effects; state-changing or external write actions require **Human-in-the-Loop (HITL)** approval.

---

## Configuration (`apps/api/.env`)

Configure environment variables in `apps/api/.env` using the settings defined in `apps/api/app/config.py` (never commit real secrets):

```env
# Required API keys
GEMINI_API_KEY=your_gemini_api_key_here
GITHUB_TOKEN=your_github_token_here

# Infrastructure (defaults shown)
DATABASE_URL=postgresql://sentinel:sentinel_password@localhost:5432/sentinel_db
REDIS_URL=redis://localhost:6379/0

# Pinned models
PRIMARY_MODEL=gemini-4-hydrogen
FAST_GUARDRAIL_MODEL=gemini-4-hydrogen

# Security & cost circuit breakers
MAX_AGENT_ITERATIONS=8
RATE_LIMIT_REQUESTS_PER_MINUTE=10
ALLOWED_ORIGINS=["http://localhost:3000"]
```

---

## Current Scope & Limitations

* **Fail-Open Testing Mode:** Quota or transient upstream errors (`429` / `503`) can use a fail-open path during local testing/evaluation; production deployments should evaluate whether fail-closed behavior is preferred for your risk tolerance.
* **Action Scope:** Remediation workflows are gated behind human approval rather than auto-merging changes into target repositories.