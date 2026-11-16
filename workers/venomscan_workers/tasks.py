from __future__ import annotations

from venomscan_api.services.runner import execute_scan

from venomscan_workers.celery_app import app


@app.task(name="venomscan.execute_scan", acks_late=True)
def execute_scan_task(scan_id: str) -> None:
    execute_scan(scan_id)
