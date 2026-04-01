"""CLI entrypoint for seeding default source configuration rows."""

from __future__ import annotations

import asyncio
import logging

from threat_intel.config import get_settings
from threat_intel.db.database import AsyncSessionLocal
from threat_intel.db.seed import seed_source_configs

logger = logging.getLogger(__name__)


async def seed_defaults() -> None:
    """Seed source_configs table with configured defaults."""
    settings = get_settings()
    async with AsyncSessionLocal() as db:
        await seed_source_configs(db, settings)
        await db.commit()

    logger.info("source_config_seed_completed")


def main() -> None:
    """Run async seeding entrypoint."""
    logging.basicConfig(level=logging.INFO)
    asyncio.run(seed_defaults())


if __name__ == "__main__":
    main()
