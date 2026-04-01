"""Unit tests for IOC deduplication and upsert behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud
from threat_intel.models.db import IOCScoreHistory
from threat_intel.models.ioc import IOCType, NormalizedIOC
from threat_intel.pipeline.deduplicator import upsert_ioc


def _ensure_utc(value: datetime) -> datetime:
    """Coerce naive datetimes returned by SQLite to UTC-aware values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@pytest.mark.asyncio
async def test_first_observation_creates_ioc_and_observation(db_session: AsyncSession) -> None:
    """First sighting should create both canonical IOC and source observation."""
    now = datetime.now(UTC)
    normalized = NormalizedIOC(
        ioc_value="10.10.10.10",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        first_seen=now,
        last_seen=now,
        raw_tags=["malware"],
        confidence_raw=0.8,
    )

    ioc_id = await upsert_ioc(normalized, db_session)
    await db_session.commit()

    ioc = await crud.get_ioc_by_id(ioc_id, db_session)
    observations = await crud.get_ioc_observations(ioc_id, db_session)

    assert ioc is not None
    assert ioc.ioc_value == "10.10.10.10"
    assert ioc.observation_count == 1
    assert len(observations) == 1
    assert observations[0].source_id == "urlhaus"


@pytest.mark.asyncio
async def test_second_observation_same_source_updates_not_increment(
    db_session: AsyncSession,
) -> None:
    """Same source repeat should update timestamps without increasing observation_count."""
    first_seen = datetime.now(UTC) - timedelta(days=2)
    second_seen = datetime.now(UTC)

    first = NormalizedIOC(
        ioc_value="11.11.11.11",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        first_seen=first_seen,
        last_seen=first_seen,
        raw_tags=["initial"],
        confidence_raw=0.6,
    )
    second = NormalizedIOC(
        ioc_value="11.11.11.11",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        first_seen=first_seen,
        last_seen=second_seen,
        raw_tags=["updated"],
        confidence_raw=0.9,
    )

    ioc_id = await upsert_ioc(first, db_session)
    await upsert_ioc(second, db_session)
    await db_session.commit()

    ioc = await crud.get_ioc_by_id(ioc_id, db_session)
    observation = await crud.get_observation(ioc_id, "urlhaus", db_session)

    assert ioc is not None
    assert observation is not None
    assert ioc.observation_count == 1
    assert _ensure_utc(observation.last_seen_by_source) >= second_seen - timedelta(seconds=1)


@pytest.mark.asyncio
async def test_second_observation_different_source_increments_count(
    db_session: AsyncSession,
) -> None:
    """Different source should create a new observation and increment source count."""
    now = datetime.now(UTC)

    first = NormalizedIOC(
        ioc_value="example.bad",
        ioc_type=IOCType.domain,
        source_id="urlhaus",
        first_seen=now,
        last_seen=now,
        raw_tags=["phishing"],
        confidence_raw=0.7,
    )
    second = NormalizedIOC(
        ioc_value="example.bad",
        ioc_type=IOCType.domain,
        source_id="alienvault_otx",
        first_seen=now,
        last_seen=now,
        raw_tags=["malware"],
        confidence_raw=0.6,
    )

    ioc_id = await upsert_ioc(first, db_session)
    await upsert_ioc(second, db_session)
    await db_session.commit()

    ioc = await crud.get_ioc_by_id(ioc_id, db_session)
    observations = await crud.get_ioc_observations(ioc_id, db_session)

    assert ioc is not None
    assert ioc.observation_count == 2
    assert len(observations) == 2


@pytest.mark.asyncio
async def test_confidence_recomputed_on_each_upsert(db_session: AsyncSession) -> None:
    """Confidence should change after adding corroborating source evidence."""
    now = datetime.now(UTC)

    first = NormalizedIOC(
        ioc_value="203.0.113.55",
        ioc_type=IOCType.ip,
        source_id="alienvault_otx",
        first_seen=now,
        last_seen=now,
        raw_tags=["suspicious"],
        confidence_raw=0.5,
    )
    second = NormalizedIOC(
        ioc_value="203.0.113.55",
        ioc_type=IOCType.ip,
        source_id="feodo_tracker",
        first_seen=now,
        last_seen=now,
        raw_tags=["botnet"],
        confidence_raw=0.95,
    )

    ioc_id = await upsert_ioc(first, db_session)
    await db_session.commit()
    after_first = await crud.get_ioc_by_id(ioc_id, db_session)
    assert after_first is not None
    score_after_first = after_first.confidence_score

    await upsert_ioc(second, db_session)
    await db_session.commit()
    after_second = await crud.get_ioc_by_id(ioc_id, db_session)
    assert after_second is not None

    assert after_second.confidence_score > score_after_first

    history_result = await db_session.execute(
        select(IOCScoreHistory)
        .where(IOCScoreHistory.ioc_id == ioc_id)
        .order_by(IOCScoreHistory.computed_at.asc())
    )
    history_rows = list(history_result.scalars().all())
    assert len(history_rows) == 2
    assert all(row.reason == "ingestion_upsert" for row in history_rows)
