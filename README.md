# LLM Security Scanner

Production-ready full-stack platform for red-teaming LLM endpoints against prompt injection, jailbreak, and data leakage vulnerabilities.

## What was implemented

This workspace now contains a complete backend and frontend setup based on the specification docs under `.kiro/specs/llm-security-scanner`.

- Async FastAPI backend with modular scanner architecture
- React + TypeScript dashboard with scan orchestration and findings view
- Attack library with 200 prompts across required categories
- Plugin-driven detector system (prompt injection, jailbreak, data leakage)
- Asynchronous scan execution with concurrency and rate limiting controls
- Structured report generation in JSON and Markdown
- Replay endpoint for re-running specific prompts from prior scans
- PostgreSQL persistence models for scans, responses, configs, vulnerabilities
- Supabase-ready deployment for backend and frontend

## Repository layout

- `backend/`: FastAPI app, scanner core, detectors, prompt library, tests
- `frontend/`: React dashboard (Vite)
- `docker/`: backend and frontend Dockerfiles
- `docker-compose.yml`: local orchestration for backend + frontend (external DB)
- `.env.example`: environment variable reference

## Backend architecture highlights

- `backend/app/services/orchestrator.py`: scan lifecycle orchestration
- `backend/app/services/executor.py`: async prompt execution against target endpoint
- `backend/app/detectors/`: built-in detector plugins
- `backend/app/core/plugin_manager.py`: detector plugin registration/selection
- `backend/app/core/aggregator.py`: finding dedupe and severity/confidence normalization
- `backend/app/services/reporting.py`: JSON/Markdown reporting
- `backend/app/services/scan_service.py`: API-facing service layer and async task kickoff

## Frontend architecture highlights

- `frontend/src/pages/HomePage.tsx`: scan launch workflow
- `frontend/src/pages/ScanPage.tsx`: polling status + findings exploration
- `frontend/src/components/VulnerabilityList.tsx`: severity/type filtering
- `frontend/src/components/VulnerabilityDetail.tsx`: exploit/evidence/remediation detail
- `frontend/src/pages/HistoryPage.tsx`: historical scan list

## API endpoints

Base path: `/api/v1`

- `POST /scan`: queue a scan
- `GET /scan/{scan_id}`: status and progress
- `GET /report/{scan_id}?format=json|markdown`: fetch report
- `POST /scan/{scan_id}/replay`: replay a single prompt
- `GET /history`: recent scans
- `GET /health`: health check

Authenticated endpoints require header:

- `X-Scanner-Token: <API_AUTH_TOKEN>`

## Attack prompt categories

The prompt library contains 200 prompts total (50 each):

- `instruction_override`
- `role_confusion`
- `data_exfiltration`
- `hidden_instruction_extraction`

Prompt files are in:

- `backend/app/attack_library/prompts/`

### Prompt library source and expansion

- Built-in curated library: `backend/app/attack_library/prompts/*.json` (200 prompts total)
- Generator script: `backend/scripts/generate_attack_prompts.py`

Regenerate the built-in library:

```bash
cd backend
/home/zoro/miniconda3/bin/python scripts/generate_attack_prompts.py
```

You can also import additional prompts from public red-team datasets (for example OWASP LLM guidance test cases, custom internal attack playbooks, or licensed benchmark sets) by appending JSON entries to those category files. Keep IDs unique and category values aligned with scanner categories.

### Run a 100-prompt scan

Frontend:

- Open the scan form.
- Set `Max Prompts` to `100`.
- Choose your categories.
- Start scan.

CLI:

```bash
cd backend
SCANNER_API_BASE=http://127.0.0.1:8000/api/v1 \
SCANNER_API_TOKEN=change-me \
/home/zoro/miniconda3/bin/python -m app.cli scan \
  http://127.0.0.1:11434/api/chat \
  --model llama3.2:3b \
  --template-preset chat \
  --requests-per-second 20 \
  --max-concurrent-requests 20 \
  --max-prompts 100 \
  --categories instruction_override,role_confusion,data_exfiltration,hidden_instruction_extraction
```

Note: prompt selection is round-robin across selected categories, so `100` prompts over all four default categories yields a balanced `25` prompts per category.

Performance notes:

- The backend now processes responses as they complete (streaming), so progress updates are visible earlier.
- Database progress updates are committed in batches to reduce transaction overhead.
- API defaults are tuned for faster scans (`requests_per_second=10`, `max_concurrent_requests=10`), and can be raised to `20/20` when the target endpoint can sustain it.

## Production-grade hardening checklist

For real production deployments, apply the following:

1. Run API with a process manager and workers
  - Use Gunicorn + Uvicorn workers behind Nginx/Traefik instead of dev `uvicorn --reload`.
2. Move scan execution to a background worker queue
  - Replace in-process `asyncio.create_task` execution with Celery/RQ/Arq workers and Redis.
3. Enforce secrets and auth hardening
  - Rotate `API_AUTH_TOKEN`, keep only secret-manager backed env vars, and enforce TLS everywhere.
4. Add database resilience
  - Enable managed DB backups/PITR, connection pool tuning, migration pipeline, and query monitoring.
5. Add observability and alerting
  - Structured logs, metrics (latency/error/rate), tracing, and on-call alerts.
6. Add rate limiting and abuse controls at edge
  - API gateway/WAF policies per IP/token, request size/time limits, and DDoS controls.
7. Add CI quality gates
  - Enforce backend tests, frontend build, linting, SAST/dependency scanning, and image scanning.
8. Add container runtime hardening
  - Non-root containers, pinned base images, regular CVE patching, minimal image footprint.
9. Add report/data governance
  - Retention rules, encrypted backups, PII/sensitive payload scrubbing policy.
10. Add staged rollout strategy
  - Dev/stage/prod isolation, canary releases, and rollback runbooks.

## Local development

### 1) Environment setup

Copy the sample env file:

```bash
cp .env.example backend/.env
```

Set values for at least:

- `DATABASE_URL`
- `API_AUTH_TOKEN`
- `ENCRYPTION_KEY` (recommended for non-dev)

### 2) Configure Supabase connection

Use your Supabase pooled Postgres URI in `backend/.env`:

```bash
DATABASE_URL=postgresql+asyncpg://postgres.project-ref:your-db-password@aws-0-your-region.pooler.supabase.com:6543/postgres
```

### 3) Backend

```bash
cd backend
/home/zoro/miniconda3/bin/python -m pip install -r requirements-dev.txt
/home/zoro/miniconda3/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend default: `http://localhost:5173`

Backend default: `http://localhost:8000`

## Docker run (full stack)

```bash
docker compose up --build
```

Services:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- Database: Supabase via `DATABASE_URL`

## Testing and validation

### Backend tests

```bash
cd backend
/home/zoro/miniconda3/bin/python -m pytest tests -q
```

### Frontend production build

```bash
cd frontend
npm run build
```

## CLI usage

The backend includes a CLI entrypoint:

```bash
cd backend
/home/zoro/miniconda3/bin/python -m app.cli --help
```

Core commands:

- `scan`
- `status`
- `report`
- `list-categories`

You can configure API connection via env vars:

- `SCANNER_API_BASE`
- `SCANNER_API_TOKEN`

## Security defaults included

- Encrypted target API key storage (Fernet)
- Sensitive log key redaction for tokens/API keys
- Input validation on endpoint URL, template placeholders, and scan config
- In-memory API request rate limiting middleware
- Security headers middleware

## Notes

- The backend creates schema tables at startup.
- The current implementation uses in-process async task execution (MVP friendly); queue-based workers can be plugged in later.
- Future plugin interfaces for RAG auditing, agent testing, monitoring, risk scoring, and compliance are scaffolded under `backend/app/plugins/interfaces/`.
