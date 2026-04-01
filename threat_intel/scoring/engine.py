"""Confidence scoring engine for normalized IOC observations."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud
from threat_intel.models.ioc import IOCType, Verdict
from threat_intel.scoring.corroboration import corroboration_boost
from threat_intel.scoring.decay import recency_decay
from threat_intel.scoring.weights import get_source_weight


def score_to_verdict(score: float) -> Verdict:
    """Map confidence score to verdict band."""
    if score >= 0.6:
        return Verdict.malicious
    if score >= 0.3:
        return Verdict.suspicious
    return Verdict.clean


def _resolve_lambda_for_ioc_type(
    ioc_type: IOCType,
    lambda_ip: float,
    lambda_domain: float,
    lambda_hash: float,
    lambda_url: float,
) -> float:
    """Resolve source-specific decay lambda by IOC type."""
    if ioc_type == IOCType.ip:
        return lambda_ip
    if ioc_type == IOCType.domain:
        return lambda_domain
    if ioc_type == IOCType.hash:
        return lambda_hash
    return lambda_url


async def compute_confidence(ioc_id: uuid.UUID, db: AsyncSession) -> float:
    """Compute IOC confidence from source observations.

    Args:
        ioc_id: IOC primary key.
        db: Async database session.

    Returns:
        Confidence score clamped to [0.0, 1.0].
    """
    ioc = await crud.get_ioc_by_id(ioc_id, db)
    if ioc is None:
        return 0.0

    try:
        ioc_type = IOCType(ioc.ioc_type)
    except ValueError:
        return 0.0

    observations = await crud.get_ioc_observations(ioc_id, db)
    if not observations:
        return 0.0

    weighted_sum = 0.0
    for observation in observations:
        source_config = await crud.get_source_config(observation.source_id, db)
        if source_config is None:
            continue

        lambda_value = _resolve_lambda_for_ioc_type(
            ioc_type=ioc_type,
            lambda_ip=float(source_config.lambda_ip),
            lambda_domain=float(source_config.lambda_domain),
            lambda_hash=float(source_config.lambda_hash),
            lambda_url=float(source_config.lambda_url),
        )

        decay = recency_decay(
            last_seen=observation.last_seen_by_source,
            ioc_type=ioc_type,
            lambda_val=lambda_value,
        )
        source_weight = await get_source_weight(observation.source_id, db)
        weighted_sum += source_weight * decay

    score = weighted_sum * corroboration_boost(len(observations))
    return max(0.0, min(score, 1.0))
