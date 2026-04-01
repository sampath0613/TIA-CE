"""Administrative API routes."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from anyio import Path as AnyPath
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from threat_intel.analytics.feed_quality import generate_feed_quality_report
from threat_intel.db import crud
from threat_intel.db.database import AsyncSessionLocal, get_db_session
from threat_intel.feeds.registry import FEED_REGISTRY
from threat_intel.pipeline.ingestor import run_ingestion
from threat_intel.scoring.engine import compute_confidence, score_to_verdict

router = APIRouter(tags=["admin"])
logger = logging.getLogger(__name__)
project_root = Path(__file__).resolve().parents[2]


class SourceWeightPatchRequest(BaseModel):
    """Request body for source weight updates."""

    source_weight: float = Field(ge=0.0, le=1.0)


async def _recompute_source_ioc_confidence(
    source_id: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Recompute confidence for all IOCs observed by one source."""
    async with session_factory() as db:
        ioc_ids = await crud.get_ioc_ids_by_source(source_id, db)
        for ioc_id in ioc_ids:
            ioc = await crud.get_ioc_by_id(ioc_id, db)
            if ioc is None:
                continue

            updated_score = await compute_confidence(ioc_id, db)
            await crud.update_ioc_confidence_and_verdict(
                ioc=ioc,
                confidence_score=updated_score,
                verdict=score_to_verdict(updated_score).value,
                db=db,
            )
            await crud.create_ioc_score_history(
                ioc_id=ioc.id,
                confidence_score=updated_score,
                verdict=score_to_verdict(updated_score).value,
                reason="source_weight_patch",
                db=db,
            )

        await db.commit()
        logger.info(
            "source_weight_recompute_completed source_id=%s affected_iocs=%s",
            source_id,
            len(ioc_ids),
        )


@router.get("/admin/source-weights")
async def get_source_weights(
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, object]]:
    """Return configured source settings and quality counters."""
    source_rows = await crud.get_all_source_configs(db)
    return [
        {
            "source_id": row.id,
            "display_name": row.display_name,
            "source_weight": row.source_weight,
            "lambda_ip": row.lambda_ip,
            "lambda_domain": row.lambda_domain,
            "lambda_hash": row.lambda_hash,
            "lambda_url": row.lambda_url,
            "last_ingestion_at": row.last_ingestion_at,
            "last_ingestion_count": row.last_ingestion_count,
            "last_error": row.last_ingestion_error,
            "cumulative_fp_count": row.cumulative_fp_count,
            "cumulative_tp_count": row.cumulative_tp_count,
        }
        for row in source_rows
    ]


@router.patch("/admin/source-weights/{source_id}")
async def patch_source_weight(
    source_id: str,
    payload: SourceWeightPatchRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str | int]:
    """Update source weight and trigger background confidence recalculation."""
    if source_id not in FEED_REGISTRY:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")

    updated = await crud.update_source_weight(source_id, payload.source_weight, db)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")

    affected_ioc_ids = await crud.get_ioc_ids_by_source(source_id, db)
    await db.commit()

    bind = cast(AsyncEngine | AsyncConnection | None, db.bind)
    if bind is None:
        session_factory = AsyncSessionLocal
    else:
        session_factory = async_sessionmaker(
            bind=bind,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    background_tasks.add_task(_recompute_source_ioc_confidence, source_id, session_factory)
    return {
        "status": "accepted",
        "source_id": source_id,
        "affected_ioc_count": len(affected_ioc_ids),
    }


@router.post("/admin/ingest/{source_id}")
async def post_admin_ingest(
    source_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str | int | None]:
    """Trigger immediate ingestion for a specific source."""
    if source_id not in FEED_REGISTRY:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")

    summary = await run_ingestion(source_id, db)
    return asdict(summary)


@router.post("/admin/generate-report")
async def post_admin_generate_report(
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
    """Generate and persist markdown feed-quality report from live data."""
    report_markdown = await generate_feed_quality_report(db)

    report_path = AnyPath(str(project_root / "docs" / "feed-quality-report.md"))
    await report_path.parent.mkdir(parents=True, exist_ok=True)
    await report_path.write_text(report_markdown, encoding="utf-8")

    return {
        "report_path": "docs/feed-quality-report.md",
        "generated_at": datetime.now(UTC).isoformat(),
    }
