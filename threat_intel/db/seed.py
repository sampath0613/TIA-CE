"""Database seed helpers for source configuration defaults."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.config import Settings
from threat_intel.db import crud
from threat_intel.feeds.alienvault_otx import AlienVaultOTXFeed
from threat_intel.feeds.emerging_threats import EmergingThreatsFeed
from threat_intel.feeds.feodo_tracker import FeodoTrackerFeed
from threat_intel.feeds.urlhaus import URLHausFeed


async def seed_source_configs(db: AsyncSession, settings: Settings) -> None:
    """Insert or update default source configuration rows."""
    await crud.upsert_source_config(
        source_id=AlienVaultOTXFeed.source_id,
        display_name=AlienVaultOTXFeed.display_name,
        source_weight=settings.default_weight_alienvault_otx,
        lambda_ip=settings.default_lambda_ip,
        lambda_domain=settings.default_lambda_domain,
        lambda_hash=settings.default_lambda_hash,
        lambda_url=settings.default_lambda_url,
        db=db,
    )
    await crud.upsert_source_config(
        source_id=URLHausFeed.source_id,
        display_name=URLHausFeed.display_name,
        source_weight=settings.default_weight_urlhaus,
        lambda_ip=settings.default_lambda_ip,
        lambda_domain=settings.default_lambda_domain,
        lambda_hash=settings.default_lambda_hash,
        lambda_url=settings.default_lambda_url,
        db=db,
    )
    await crud.upsert_source_config(
        source_id=FeodoTrackerFeed.source_id,
        display_name=FeodoTrackerFeed.display_name,
        source_weight=settings.default_weight_feodo_tracker,
        lambda_ip=settings.default_lambda_ip,
        lambda_domain=settings.default_lambda_domain,
        lambda_hash=settings.default_lambda_hash,
        lambda_url=settings.default_lambda_url,
        db=db,
    )
    await crud.upsert_source_config(
        source_id=EmergingThreatsFeed.source_id,
        display_name=EmergingThreatsFeed.display_name,
        source_weight=settings.default_weight_emerging_threats,
        lambda_ip=settings.default_lambda_ip,
        lambda_domain=settings.default_lambda_domain,
        lambda_hash=settings.default_lambda_hash,
        lambda_url=settings.default_lambda_url,
        db=db,
    )
