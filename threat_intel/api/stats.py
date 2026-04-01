"""Statistics API routes."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud
from threat_intel.db.database import get_db_session

router = APIRouter(tags=["stats"])


@router.get("/stats/feed-health")
async def get_feed_health(
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, object]]:
    """Return feed-health summary rows including computed ingestion error rates."""
    rows = await crud.get_feed_health_rows(db)
    return cast(list[dict[str, object]], rows)


@router.get("/stats/ioc-volume")
async def get_ioc_volume(
    days: int = Query(default=7, ge=1, le=365),
    source_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, str | int]]:
    """Return IOC volume time series grouped by day and feed source."""
    return await crud.get_ioc_volume_rows(days=days, source_id=source_id, db=db)


@router.get("/stats/confidence-distribution")
async def get_confidence_distribution(
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, str | int]]:
    """Return confidence-score histogram in 0.1-width buckets."""
    return await crud.get_confidence_distribution_rows(db)
