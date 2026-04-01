"""Feed ingestion orchestration pipeline."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import httpx
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, async_sessionmaker

from threat_intel.config import get_settings
from threat_intel.db import crud
from threat_intel.db.database import AsyncSessionLocal
from threat_intel.feeds.base import FeedFetchError
from threat_intel.feeds.registry import FEED_REGISTRY
from threat_intel.pipeline.deduplicator import upsert_ioc

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class IngestionSummary:
    """Summary returned by each ingestion run."""

    source_id: str
    status: str
    records_fetched: int
    records_new: int
    records_updated: int
    error_message: str | None


async def run_ingestion(source_id: str, db: AsyncSession) -> IngestionSummary:
    """Run end-to-end ingestion for a single feed source."""
    started_at = datetime.now(UTC)
    ingestion_log = await crud.create_ingestion_log(
        source_id=source_id,
        started_at=started_at,
        db=db,
    )

    adapter_cls = FEED_REGISTRY.get(source_id)
    if adapter_cls is None:
        error = f"Unknown feed source_id={source_id}"
        await crud.finalize_ingestion_log(
            ingestion_log,
            completed_at=datetime.now(UTC),
            records_fetched=0,
            records_new=0,
            records_updated=0,
            status="failed",
            error_message=error,
            db=db,
        )
        await crud.update_source_ingestion_status(
            source_id,
            last_ingestion_at=None,
            last_ingestion_count=0,
            last_ingestion_error=error,
            db=db,
        )
        await db.commit()
        return IngestionSummary(
            source_id=source_id,
            status="failed",
            records_fetched=0,
            records_new=0,
            records_updated=0,
            error_message=error,
        )

    try:
        settings = get_settings()
        async with httpx.AsyncClient() as client:
            adapter = adapter_cls(settings=settings, http_client=client)
            normalized_iocs = await adapter.fetch()

        records_new = 0
        records_updated = 0

        for normalized in normalized_iocs:
            existed = await crud.get_ioc_by_value_type(
                normalized.ioc_value,
                normalized.ioc_type.value,
                db,
                for_update=False,
            )
            await upsert_ioc(normalized=normalized, db=db)
            if existed is None:
                records_new += 1
            else:
                records_updated += 1

        completed_at = datetime.now(UTC)
        await crud.finalize_ingestion_log(
            ingestion_log,
            completed_at=completed_at,
            records_fetched=len(normalized_iocs),
            records_new=records_new,
            records_updated=records_updated,
            status="success",
            error_message=None,
            db=db,
        )
        await crud.update_source_ingestion_status(
            source_id,
            last_ingestion_at=completed_at,
            last_ingestion_count=len(normalized_iocs),
            last_ingestion_error=None,
            db=db,
        )
        await db.commit()

        logger.info(
            "ingestion_complete source_id=%s fetched=%s new=%s updated=%s",
            source_id,
            len(normalized_iocs),
            records_new,
            records_updated,
        )

        return IngestionSummary(
            source_id=source_id,
            status="success",
            records_fetched=len(normalized_iocs),
            records_new=records_new,
            records_updated=records_updated,
            error_message=None,
        )
    except FeedFetchError as exc:
        error = str(exc)
        await crud.finalize_ingestion_log(
            ingestion_log,
            completed_at=datetime.now(UTC),
            records_fetched=0,
            records_new=0,
            records_updated=0,
            status="failed",
            error_message=error,
            db=db,
        )
        await crud.update_source_ingestion_status(
            source_id,
            last_ingestion_at=None,
            last_ingestion_count=0,
            last_ingestion_error=error,
            db=db,
        )
        await db.commit()

        logger.exception("ingestion_failed source_id=%s error=%s", source_id, error)

        return IngestionSummary(
            source_id=source_id,
            status="failed",
            records_fetched=0,
            records_new=0,
            records_updated=0,
            error_message=error,
        )


async def run_all_feeds(db: AsyncSession) -> None:
    """Run all registered feeds concurrently using separate DB sessions."""
    bind = cast(AsyncEngine | AsyncConnection | None, db.bind)
    if bind is None:
        session_factory = AsyncSessionLocal
    else:
        session_factory = async_sessionmaker(
            bind=bind,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def _run_source(source_id: str) -> None:
        async with session_factory() as session:
            await run_ingestion(source_id=source_id, db=session)

    await asyncio.gather(*[_run_source(source_id) for source_id in FEED_REGISTRY])
