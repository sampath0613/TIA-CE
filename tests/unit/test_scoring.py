"""Unit tests for scoring model functions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.models.db import IOC, IOCObservation
from threat_intel.models.ioc import IOCType, Verdict
from threat_intel.scoring.corroboration import corroboration_boost
from threat_intel.scoring.decay import recency_decay
from threat_intel.scoring.engine import compute_confidence, score_to_verdict


def test_recency_decay_today() -> None:
    """Decay should be near 1 for recently seen IOC."""
    score = recency_decay(datetime.now(UTC), IOCType.ip, 0.015)
    assert score == pytest.approx(1.0, rel=1e-3)


def test_recency_decay_old() -> None:
    """Decay should approach zero for very old observations."""
    old = datetime.now(UTC) - timedelta(days=730)
    score = recency_decay(old, IOCType.ip, 0.015)
    assert score < 0.01


def test_corroboration_boost_one() -> None:
    """A single source should not increase corroboration boost."""
    assert corroboration_boost(1) == pytest.approx(1.0)


def test_corroboration_boost_ten() -> None:
    """Ten sources should cap at max corroboration boost."""
    assert corroboration_boost(10) == pytest.approx(1.5)


def test_corroboration_boost_clamped() -> None:
    """Boost remains capped even above max configured source count."""
    assert corroboration_boost(100) == pytest.approx(1.5)


@pytest.mark.asyncio
async def test_compute_confidence_single_source(db_session: AsyncSession) -> None:
    """Confidence should equal weight for one fresh observation when decay~1 and boost=1."""
    now = datetime.now(UTC)
    ioc = IOC(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.ip.value,
        first_seen=now,
        last_seen=now,
        observation_count=1,
        confidence_score=0.0,
        verdict=Verdict.clean.value,
    )
    db_session.add(ioc)
    await db_session.flush()

    db_session.add(
        IOCObservation(
            ioc_id=ioc.id,
            source_id="urlhaus",
            first_seen_by_source=now,
            last_seen_by_source=now,
            raw_tags='["malware"]',
            confidence_raw=0.9,
        )
    )
    await db_session.commit()

    score = await compute_confidence(ioc.id, db_session)
    assert score == pytest.approx(0.8, abs=0.02)


@pytest.mark.asyncio
async def test_compute_confidence_multi_source(db_session: AsyncSession) -> None:
    """Confidence should increase with corroboration across multiple sources."""
    now = datetime.now(UTC)
    ioc = IOC(
        ioc_value="evil.example.com",
        ioc_type=IOCType.domain.value,
        first_seen=now,
        last_seen=now,
        observation_count=3,
        confidence_score=0.0,
        verdict=Verdict.clean.value,
    )
    db_session.add(ioc)
    await db_session.flush()

    db_session.add_all(
        [
            IOCObservation(
                ioc_id=ioc.id,
                source_id="alienvault_otx",
                first_seen_by_source=now - timedelta(days=1),
                last_seen_by_source=now - timedelta(days=1),
                raw_tags='["phishing"]',
                confidence_raw=0.6,
            ),
            IOCObservation(
                ioc_id=ioc.id,
                source_id="urlhaus",
                first_seen_by_source=now - timedelta(days=2),
                last_seen_by_source=now - timedelta(days=2),
                raw_tags='["malware"]',
                confidence_raw=0.8,
            ),
            IOCObservation(
                ioc_id=ioc.id,
                source_id="feodo_tracker",
                first_seen_by_source=now - timedelta(days=1),
                last_seen_by_source=now - timedelta(days=1),
                raw_tags='["botnet"]',
                confidence_raw=0.95,
            ),
        ]
    )
    await db_session.commit()

    score = await compute_confidence(ioc.id, db_session)
    assert 0.75 <= score <= 1.0


def test_score_to_verdict_boundaries() -> None:
    """Verdict thresholds should be applied at exact boundary values."""
    assert score_to_verdict(0.0) == Verdict.clean
    assert score_to_verdict(0.2999) == Verdict.clean
    assert score_to_verdict(0.3) == Verdict.suspicious
    assert score_to_verdict(0.5999) == Verdict.suspicious
    assert score_to_verdict(0.6) == Verdict.malicious
