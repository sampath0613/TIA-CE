"""Cross-source corroboration boost functions."""

from __future__ import annotations

import math

MAX_SOURCES = 10


def corroboration_boost(observation_count: int) -> float:
    """Return a corroboration multiplier in [1.0, 1.5].

    The function uses log scaling to avoid linear over-rewarding when additional
    source confirmations arrive. It anchors:
    - 1 source -> 1.0
    - 10+ sources -> 1.5

    Args:
        observation_count: Number of distinct sources that observed an IOC.

    Returns:
        Corroboration multiplier between 1.0 and 1.5.
    """
    if observation_count <= 1:
        return 1.0

    numerator = math.log(1 + observation_count) - math.log(1 + 1)
    denominator = math.log(1 + MAX_SOURCES) - math.log(1 + 1)
    normalized = numerator / denominator if denominator > 0 else 0.0
    normalized = max(0.0, min(normalized, 1.0))

    boost = 1.0 + (0.5 * normalized)
    return max(1.0, min(boost, 1.5))
