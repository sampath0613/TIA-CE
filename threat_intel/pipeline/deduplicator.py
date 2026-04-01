"""IOC deduplication and upsert logic."""

from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud
from threat_intel.models.ioc import NormalizedIOC
from threat_intel.scoring.engine import compute_confidence, score_to_verdict

logger = logging.getLogger(__name__)


async def upsert_ioc(normalized: NormalizedIOC, db: AsyncSession) -> uuid.UUID:
    """Upsert a normalized IOC and recompute confidence.

    Steps:
    1. Lookup existing IOC by (ioc_value, ioc_type) using row lock.
    2. Insert or update IOC and source observation.
    3. Recompute confidence and derived verdict.

    Args:
        normalized: Normalized IOC record from feed adapter.
        db: Async database session.

    Returns:
        IOC identifier.
    """
    ioc = await crud.get_ioc_by_value_type(
        normalized.ioc_value,
        normalized.ioc_type.value,
        db,
        for_update=True,
    )

    raw_tags = json.dumps(normalized.raw_tags)

    if ioc is None:
        ioc = await crud.create_ioc(
            ioc_value=normalized.ioc_value,
            ioc_type=normalized.ioc_type.value,
            first_seen=normalized.first_seen,
            last_seen=normalized.last_seen,
            db=db,
        )
        await crud.create_observation(
            ioc_id=ioc.id,
            source_id=normalized.source_id,
            first_seen_by_source=normalized.first_seen,
            last_seen_by_source=normalized.last_seen,
            raw_tags=raw_tags,
            confidence_raw=normalized.confidence_raw,
            db=db,
        )
    else:
        await crud.update_ioc_seen_window(
            ioc=ioc,
            first_seen=normalized.first_seen,
            last_seen=normalized.last_seen,
            db=db,
        )

        observation = await crud.get_observation(
            ioc_id=ioc.id,
            source_id=normalized.source_id,
            db=db,
            for_update=True,
        )
        if observation is None:
            await crud.create_observation(
                ioc_id=ioc.id,
                source_id=normalized.source_id,
                first_seen_by_source=normalized.first_seen,
                last_seen_by_source=normalized.last_seen,
                raw_tags=raw_tags,
                confidence_raw=normalized.confidence_raw,
                db=db,
            )
            await crud.increment_ioc_observation_count(ioc=ioc, db=db)
        else:
            await crud.update_observation(
                observation=observation,
                first_seen_by_source=normalized.first_seen,
                last_seen_by_source=normalized.last_seen,
                raw_tags=raw_tags,
                confidence_raw=normalized.confidence_raw,
                db=db,
            )

    confidence_score = await compute_confidence(ioc.id, db)
    verdict = score_to_verdict(confidence_score).value
    await crud.update_ioc_confidence_and_verdict(
        ioc=ioc,
        confidence_score=confidence_score,
        verdict=verdict,
        db=db,
    )
    await crud.create_ioc_score_history(
        ioc_id=ioc.id,
        confidence_score=confidence_score,
        verdict=verdict,
        reason="ingestion_upsert",
        db=db,
    )

    logger.info(
        "ioc_upserted ioc_id=%s source_id=%s ioc_value=%s ioc_type=%s confidence=%.4f verdict=%s",
        str(ioc.id),
        normalized.source_id,
        normalized.ioc_value,
        normalized.ioc_type.value,
        confidence_score,
        verdict,
    )

    return ioc.id
