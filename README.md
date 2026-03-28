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
- Dockerized deployment for backend, frontend, and PostgreSQL

## Repository layout

- `backend/`: FastAPI app, scanner core, detectors, prompt library, tests
- `frontend/`: React dashboard (Vite)
- `docker/`: backend and frontend Dockerfiles
- `docker-compose.yml`: local orchestration with PostgreSQL
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

## Local development

### 1) Environment setup

Copy the sample env file:

```bash
cp .env.example .env
```

Set values for at least:

- `DATABASE_URL`
- `API_AUTH_TOKEN`
- `ENCRYPTION_KEY` (recommended for non-dev)

### 2) Start PostgreSQL (Docker)

```bash
docker compose up -d db
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
- PostgreSQL: `localhost:5432`

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
