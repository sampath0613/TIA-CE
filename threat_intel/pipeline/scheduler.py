"""APScheduler configuration for periodic feed ingestion."""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from threat_intel.config import Settings, get_settings
from threat_intel.db.database import AsyncSessionLocal
from threat_intel.feeds.registry import FEED_REGISTRY
from threat_intel.pipeline.ingestor import run_ingestion

logger = logging.getLogger(__name__)


def _interval_minutes_for_source(source_id: str, settings: Settings) -> int:
    """Resolve ingestion interval in minutes for a source ID."""
    mapping = {
        "alienvault_otx": settings.ingest_interval_otx,
        "urlhaus": settings.ingest_interval_urlhaus,
        "feodo_tracker": settings.ingest_interval_feodo,
        "emerging_threats": settings.ingest_interval_emerging,
    }
    return max(mapping.get(source_id, 60), 1)


async def _scheduled_ingestion_job(source_id: str) -> None:
    """Run a single scheduled ingestion with an isolated DB session."""
    async with AsyncSessionLocal() as db:
        summary = await run_ingestion(source_id=source_id, db=db)
        logger.info(
            "scheduled_ingestion_complete source_id=%s status=%s fetched=%s",
            source_id,
            summary.status,
            summary.records_fetched,
        )


def create_scheduler(settings: Settings | None = None) -> AsyncIOScheduler:
    """Create and configure an AsyncIOScheduler with per-feed jobs."""
    active_settings = settings or get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")

    for source_id in FEED_REGISTRY:
        interval_minutes = _interval_minutes_for_source(source_id, active_settings)
        scheduler.add_job(
            _scheduled_ingestion_job,
            trigger=IntervalTrigger(minutes=interval_minutes),
            args=[source_id],
            id=f"ingest_{source_id}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )

    return scheduler
