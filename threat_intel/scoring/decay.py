"""Recency decay utilities for IOC confidence scoring."""

from __future__ import annotations

import math
from datetime import UTC, datetime

from threat_intel.models.ioc import IOCType

DEFAULT_LAMBDA_BY_TYPE: dict[IOCType, float] = {
    IOCType.ip: 0.015,
    IOCType.domain: 0.008,
    IOCType.url: 0.020,
    IOCType.hash: 0.002,
}


def recency_decay(last_seen: datetime, ioc_type: IOCType, lambda_val: float) -> float:
    """Compute recency decay using an exponential function.

    Formula:
        exp(-lambda_val * days_since_last_seen)

    Args:
        last_seen: Last timestamp this IOC was observed for a source.
        ioc_type: IOC type used for type-aware lambda strategy.
        lambda_val: Source+type specific decay rate.

    Returns:
        A decay multiplier in [0.0, 1.0].
    """
    _ = ioc_type
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    days_since_last_seen = max((now - last_seen).total_seconds() / 86400.0, 0.0)
    decay = math.exp(-lambda_val * days_since_last_seen)
    return max(0.0, min(decay, 1.0))
