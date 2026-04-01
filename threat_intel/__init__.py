"""Threat Intel Aggregator package initialization."""

from __future__ import annotations

import logging


def setup_logging(level: str = "INFO") -> None:
    """Configure structured application logging.

    Args:
        level: Logging level name.
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s level=%(levelname)s logger=%(name)s message=%(message)s",
    )


setup_logging()
