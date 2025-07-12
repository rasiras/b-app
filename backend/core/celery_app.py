from celery import Celery
from celery.schedules import crontab
from core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "bug_bounty_automation",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "scheduler.tasks",
        "scanners.tasks",
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT,
    task_soft_time_limit=settings.SCAN_TIMEOUT - 300,  # 5 minutes before hard timeout
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    task_routes={
        "scheduler.tasks.*": {"queue": "scheduler"},
        "scanners.tasks.*": {"queue": "scanner"},
    },
    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "check-scheduled-scans": {
        "task": "scheduler.tasks.check_scheduled_scans",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
    },
    "update-cve-database": {
        "task": "scheduler.tasks.update_cve_database",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
    },
    "cleanup-old-scans": {
        "task": "scheduler.tasks.cleanup_old_scans",
        "schedule": crontab(hour=3, minute=0),  # Daily at 3 AM
    },
    "send-pending-notifications": {
        "task": "scheduler.tasks.send_pending_notifications",
        "schedule": crontab(minute="*/10"),  # Every 10 minutes
    },
}

# Task retry configuration
celery_app.conf.task_annotations = {
    "scanners.tasks.run_subdomain_scan": {
        "rate_limit": "10/m",
        "retry_kwargs": {"max_retries": 3, "countdown": 60},
    },
    "scanners.tasks.run_port_scan": {
        "rate_limit": "5/m",
        "retry_kwargs": {"max_retries": 2, "countdown": 120},
    },
    "scanners.tasks.run_vulnerability_scan": {
        "rate_limit": "3/m",
        "retry_kwargs": {"max_retries": 2, "countdown": 300},
    },
}

if __name__ == "__main__":
    celery_app.start()