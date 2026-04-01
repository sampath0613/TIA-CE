"""Integration tests for IOC API endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db.database import get_db_session
from threat_intel.main import app
from threat_intel.models.db import IOC, IOCObservation, SourceConfig
from threat_intel.models.ioc import IOCType

_API_HEADERS = {"X-API-Key": "change-me"}


async def _seed_ioc(
    db_session: AsyncSession,
    *,
    value: str,
    ioc_type: IOCType,
    source_id: str,
    confidence_score: float,
) -> IOC:
    now = datetime.now(UTC)
    ioc = IOC(
        ioc_value=value,
        ioc_type=ioc_type.value,
        first_seen=now,
        last_seen=now,
        observation_count=1,
        confidence_score=confidence_score,
        verdict="malicious" if confidence_score >= 0.6 else "suspicious",
        false_positive_count=0,
    )
    db_session.add(ioc)
    await db_session.flush()

    db_session.add(
        IOCObservation(
            ioc_id=ioc.id,
            source_id=source_id,
            first_seen_by_source=now,
            last_seen_by_source=now,
            raw_tags='["seeded"]',
            confidence_raw=confidence_score,
        )
    )
    await db_session.commit()
    return ioc


@pytest_asyncio.fixture
async def integration_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """HTTP client fixture backed by FastAPI app with test DB override."""

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=_API_HEADERS,
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_ioc_found(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """GET /ioc/{value} should return canonical IOC response payload."""
    await _seed_ioc(
        db_session,
        value="8.8.8.8",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        confidence_score=0.82,
    )

    response = await integration_client.get("/ioc/8.8.8.8")

    assert response.status_code == 200
    payload = response.json()
    assert payload["ioc_value"] == "8.8.8.8"
    assert payload["ioc_type"] == IOCType.ip.value
    assert payload["confidence_score"] > 0
    assert payload["sources"] == ["urlhaus"]
    assert len(payload["source_observations"]) == 1
    observation = payload["source_observations"][0]
    assert observation["source_id"] == "urlhaus"
    assert observation["display_name"] == "URLhaus"


@pytest.mark.asyncio
async def test_get_ioc_bulk_returns_partial_results(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """GET /ioc/bulk should support repeated query params and return found IOCs only."""
    seed_values = [
        ("1.1.1.1", IOCType.ip),
        ("2.2.2.2", IOCType.ip),
        ("bad.example", IOCType.domain),
    ]

    for value, ioc_type in seed_values:
        await _seed_ioc(
            db_session,
            value=value,
            ioc_type=ioc_type,
            source_id="urlhaus",
            confidence_score=0.75,
        )

    response = await integration_client.get(
        "/ioc/bulk",
        params=[
            ("iocs", "1.1.1.1"),
            ("iocs", "2.2.2.2"),
            ("iocs", "bad.example"),
            ("iocs", "not-found.example"),
        ],
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 3
    assert {row["ioc_value"] for row in payload} == {"1.1.1.1", "2.2.2.2", "bad.example"}


@pytest.mark.asyncio
async def test_post_ioc_bulk_returns_partial_results(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """POST /ioc/bulk should return only found IOC matches."""
    seed_values = [
        ("1.1.1.1", IOCType.ip),
        ("2.2.2.2", IOCType.ip),
        ("bad.example", IOCType.domain),
        ("https://evil.example/payload", IOCType.url),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.hash),
    ]

    for value, ioc_type in seed_values:
        await _seed_ioc(
            db_session,
            value=value,
            ioc_type=ioc_type,
            source_id="urlhaus",
            confidence_score=0.75,
        )

    response = await integration_client.post(
        "/ioc/bulk",
        json={
            "iocs": [
                "1.1.1.1",
                "2.2.2.2",
                "bad.example",
                "https://evil.example/payload",
                "d41d8cd98f00b204e9800998ecf8427e",
                "does-not-exist.example",
            ]
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 5


@pytest.mark.asyncio
async def test_post_ioc_verdict_false_positive_decreases_source_weight(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """False-positive feedback should reduce source weight and update IOC response."""
    await _seed_ioc(
        db_session,
        value="9.9.9.9",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        confidence_score=0.8,
    )

    source_config = await db_session.get(SourceConfig, "urlhaus")
    assert source_config is not None
    old_weight = float(source_config.source_weight)

    response = await integration_client.post(
        "/ioc/9.9.9.9/verdict",
        json={"verdict": "false_positive", "notes": "Validated as benign"},
    )

    assert response.status_code == 200
    await db_session.refresh(source_config)

    assert float(source_config.source_weight) < old_weight
    payload = response.json()
    assert payload["false_positive_count"] == 1
