.PHONY: setup db-up db-down api web worker worker-scale test seed fmt load-test

setup:            ## Install python + web dependencies
	uv sync --all-packages
	cd apps/web && npm install

db-up:            ## Start postgres + redis
	docker compose -f infra/compose/docker-compose.dev.yml up -d

db-down:
	docker compose -f infra/compose/docker-compose.dev.yml down

api:              ## Run FastAPI (reload)
	uv run python -m uvicorn venomscan_api.main:app --reload --port 8000

worker:           ## Run Celery worker (dev, single process; needs TASK_MODE=celery)
	uv run python -m celery -A venomscan_workers.celery_app worker -l info --pool=solo

worker-scale:     ## Run Celery worker with autoscaling (production-style)
	uv run python -m celery -A venomscan_workers.celery_app worker -l info --pool=prefork --concurrency=2 --autoscale=6,2 --max-tasks-per-child=50

web:              ## Run Next.js
	cd apps/web && npm run dev

test:
	uv run pytest

seed:
	uv run python -m venomscan_api.seed

load-test:        ## p95 latency check + optional concurrent scans (API must be running)
	uv run python scripts/load_test.py --scans 5

fmt:
	uv run ruff format .
