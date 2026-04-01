"""Source weight retrieval and adaptive calibration logic."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud

logger = logging.getLogger(__name__)


async def get_source_weight(source_id: str, db: AsyncSession) -> float:
    """Read source weight from source configuration table.

    Args:
        source_id: Source identifier.
        db: Async database session.

    Returns:
        Source weight in range [0.0, 1.0]. Falls back to 0.5 if source is missing.
    """
    source_config = await crud.get_source_config(source_id, db)
    if source_config is None:
        logger.warning("source_config_missing source_id=%s fallback_weight=0.5", source_id)
        return 0.5
    return float(source_config.source_weight)


async def auto_adjust_weight(source_id: str, db: AsyncSession) -> None:
    """Auto-calibrate source weight from cumulative FP/TP feedback.

    Formula:
        new_weight = current_weight * (1 - fp_rate * 0.1)
        fp_rate = cumulative_fp_count / (cumulative_fp_count + cumulative_tp_count)

    A floor of 0.1 is applied to avoid fully silencing a source.

    Args:
        source_id: Source identifier.
        db: Async database session.
    """
    source_config = await crud.get_source_config(source_id, db)
    if source_config is None:
        logger.warning("source_config_missing source_id=%s auto_adjust_skipped=true", source_id)
        return

    current_weight = float(source_config.source_weight)
    fp_count = int(source_config.cumulative_fp_count)
    tp_count = int(source_config.cumulative_tp_count)
    total = fp_count + tp_count
    fp_rate = (fp_count / total) if total else 0.0

    new_weight = current_weight * (1 - fp_rate * 0.1)
    new_weight = max(0.1, new_weight)

    source_config.source_weight = new_weight
    await db.flush()

    logger.info(
        "source_weight_auto_adjusted source_id=%s old_weight=%.4f new_weight=%.4f fp_rate=%.4f",
        source_id,
        current_weight,
        new_weight,
        fp_rate,
    )
