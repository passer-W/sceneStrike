# SceneStrike — Scene-Aware Web Penetration Testing Framework

Modern Web applications increasingly combine frontend components, backend APIs, and multi-step business workflows to support complex functionality. These workflows span multiple API calls and application states, creating interaction dependencies that may only expose vulnerabilities when specific sequences of actions are followed. Such vulnerabilities are therefore difficult to detect through isolated request analysis.

**SceneStrike** is a scene-aware penetration testing framework that models Web applications as structured interaction scenes rather than isolated endpoints. It consists of three key stages:

1. **Scene Reconstruction** — integrates frontend artifacts and runtime traffic to recover API-level execution contexts.
2. **Attack Scene Graph (ASG) Construction** — organizes cross-API control, data, and semantic dependencies into an Attack Scene Graph.
3. **Scene-guided Vulnerability Detection** — leverages the ASG to perform context-aware vulnerability reasoning and state-consistent multi-step attack validation.

On a dedicated multi-API benchmark, SceneStrike achieves a **100% attack success rate**, demonstrating its effectiveness in identifying vulnerabilities that depend on chained interactions. On the widely used **XBow Benchmark**, it reaches **93.0% accuracy** and outperforms state-of-the-art systems. SceneStrike further discovers **12 previously unreported CVEs**, showing its effectiveness in detecting context-dependent vulnerabilities in real-world Web applications.

---

## Repository Layout

```
.
├── agent/                       # Core attack agent (SceneStrike runtime)
│   ├── flaghunter.py            # Single-target entry point
│   ├── contest_hunter.py        # Multi-challenge contest entry point
│   ├── agents/                  # Explorer / Scanner / Exploiter agents
│   ├── addons/                  # Request, fuzz, encoding helpers
│   ├── config/                  # LLM keys, payloads, knowledge base, PoCs
│   ├── utils/                   # Agent manager, logger, helpers
│   └── requirements.txt
└── server/                      # Task control plane + UI
    ├── backend/                 # Flask + Celery API
    │   ├── app.py               # Flask entry
    │   ├── celery_config.py     # Celery setup
    │   ├── tasks.py             # Async task definitions
    │   ├── controllers/         # REST blueprints
    │   ├── models.py            # SQLAlchemy models
    │   ├── Dockerfile
    │   └── requirements.txt
    ├── frontend/                # Pre-built Web UI (nginx)
    │   ├── dist.zip             # Static assets
    │   ├── nginx.conf
    │   └── Dockerfile
    └── docker-compose.yaml
```

---

## Quick Start (Docker — Recommended)

The bundled `docker-compose.yaml` brings up the **Flask backend** (port `5000`) and the **Nginx-served frontend** (port `85`). Redis and the attack agent are not included in compose and must be started separately (see below).

```bash
cd server

# 1. Build images
docker build -t ctfui-backend:latest  ./backend
docker build -t ctfui-frontend:latest ./frontend

# 2. Launch the control plane
docker compose up -d

# 3. Verify
curl http://localhost:5000/health
# Open the UI at http://localhost:85
```

After the control plane is up, start at least one **agent** so the backend can dispatch tasks to it (see "Running the Agent" below).

---

## Manual Start (Development)

### 1. Prerequisites

| Component | Version  | Purpose                          |
|-----------|----------|----------------------------------|
| Python    | 3.11     | Backend + Agent runtime          |
| Redis     | 6.x+     | Celery broker / result backend   |
| SQLite    | bundled  | Task persistence                 |
| Nginx     | optional | Serving the frontend `dist.zip`  |

Install Redis (macOS example):

```bash
brew install redis
brew services start redis
```

### 2. Start the Backend (Flask + Celery)

```bash
cd server/backend
pip install -r requirements.txt
pip install celery redis     # required by Dockerfile; not in requirements.txt
```

Open three terminals:

```bash
# Terminal A — Flask API
cd server/backend
python app.py
# Listens on http://0.0.0.0:5000

# Terminal B — Celery worker
cd server/backend
celery -A tasks worker --loglevel=info

# Terminal C (optional) — Flower monitor
cd server/backend
celery -A tasks flower
```

### 3. Start the Frontend

```bash
cd server/frontend
unzip -o dist.zip -d public
# Serve the extracted `public/` directory with any static-file server, e.g.:
npx serve -l 85 public
# Or use the provided nginx.conf
```

### 4. Run the Agent

The agent registers itself with the backend, sends heartbeats every 30 s, and waits for tasks. Configure the backend address and LLM keys first.

```bash
cd agent
pip install -r requirements.txt

# Edit agent/config/config.py and fill in:
#   SERVER_URL        — backend address, e.g. http://localhost:5000
#   DEEPSEEK_API_KEY  (or TENCENT_/SILCON_ keys)
#   CONTEST_API_TOKEN — only required for contest_hunter.py
```

Start a single-target agent:

```bash
cd agent
python flaghunter.py \
    --name agent-01 \
    --mode deepseek
```

Start the multi-challenge contest runner (auto-fetches challenges, dispatches parallel agents):

```bash
cd agent
export CONTEST_API_TOKEN=<your-token>
python contest_hunter.py --mode deepseek
```

Once the agent is running, dispatch tasks through the Web UI at `http://localhost:85` (or via the REST API, e.g. `POST /api/tasks`).

---

## API Cheat Sheet

| Method | Endpoint                       | Description                  |
|--------|--------------------------------|------------------------------|
| GET    | `/health`                      | Liveness probe               |
| GET    | `/api/agents`                  | List registered agents       |
| POST   | `/api/tasks`                   | Create and start a task      |
| POST   | `/api/tasks/{task_id}/start`   | Manually start a task        |
| POST   | `/api/tasks/{task_id}/stop`    | Stop a running task          |
| GET    | `/api/tasks/status/{celery_id}`| Inspect Celery task status   |

---

## Notes

- `agent/config/config.py` is the single source of truth for LLM endpoints, server address, timeouts, and path constants.
- The default backend URL in the agent config points to a remote instance; change `SERVER_URL` to `http://localhost:5000` when running locally.
- `celery_worker.py` is referenced in `CELERY_SETUP.md` for older deployments; the current equivalent is `celery -A tasks worker --loglevel=info`.
