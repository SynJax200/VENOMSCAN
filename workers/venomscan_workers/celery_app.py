from __future__ import annotations

import os

from celery import Celery

broker = os.environ.get("REDIS_URL", "redis://127.0.0.1:56379/0")
app = Celery("venomscan", broker=broker, backend=broker)
app.conf.update(
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    # A scan shares one wall-clock budget with the engine; the hard limit is the
    # backstop in case a check ignores cancellation.
    task_soft_time_limit=int(os.environ.get("TASK_SOFT_TIME_LIMIT", "540")),
    task_time_limit=int(os.environ.get("TASK_TIME_LIMIT", "600")),
    # Recycle children so a leaked Chromium/nuclei process cannot pin a slot forever.
    worker_max_tasks_per_child=int(os.environ.get("WORKER_MAX_TASKS_PER_CHILD", "50")),
    worker_max_memory_per_child=int(os.environ.get("WORKER_MAX_MEMORY_KB", "600000")),
    result_expires=3600,
    broker_transport_options={"visibility_timeout": 3600},
)
app.autodiscover_tasks(["venomscan_workers"])
