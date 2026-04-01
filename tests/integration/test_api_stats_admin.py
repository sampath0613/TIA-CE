"""Integration tests for stats and admin API endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from anyio import Path as AnyPath
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db.database import get_db_session
from threat_intel.main import app
from threat_intel.models.db import IOC, IOCObservation, SourceConfig
from threat_intel.models.ioc import IOCType

_API_HEADERS = {"X-API-Key": "change-me"}
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


async def _seed_ioc(
    db_session: AsyncSession,
    *,
    value: str,
    ioc_type: IOCType,
    source_id: str,
    confidence_score: float,
) -> None:
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


@pytest_asyncio.fixture
async def integration_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """HTTP client fixture backed by app with test DB dependency override."""

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
async def test_stats_endpoints_return_data(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Stats endpoints should return populated feed health and histogram payloads."""
    await _seed_ioc(
        db_session,
        value="198.51.100.44",
        ioc_type=IOCType.ip,
        source_id="urlhaus",
        confidence_score=0.82,
    )

    feed_health = await integration_client.get("/stats/feed-health")
    confidence_dist = await integration_client.get("/stats/confidence-distribution")
    volume = await integration_client.get("/stats/ioc-volume?days=7")

    assert feed_health.status_code == 200
    assert confidence_dist.status_code == 200
    assert volume.status_code == 200

    health_payload = feed_health.json()
    confidence_payload = confidence_dist.json()
    volume_payload = volume.json()

    assert len(health_payload) >= 4
    assert all("error_rate" in row for row in health_payload)
    assert all("ingestion_run_count" in row for row in health_payload)
    assert all("ingestion_failed_count" in row for row in health_payload)
    assert all(0.0 <= float(row["error_rate"]) <= 1.0 for row in health_payload)
    assert len(confidence_payload) == 10
    assert any(int(bucket["count"]) >= 1 for bucket in confidence_payload)
    assert isinstance(volume_payload, list)


@pytest.mark.asyncio
async def test_admin_patch_source_weight(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """PATCH source weight endpoint should persist value and return accepted status."""
    response = await integration_client.patch(
        "/admin/source-weights/urlhaus",
        json={"source_weight": 0.55},
    )
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "accepted"
    assert payload["source_id"] == "urlhaus"

    source = await db_session.get(SourceConfig, "urlhaus")
    assert source is not None
    assert float(source.source_weight) == pytest.approx(0.55)


@pytest.mark.asyncio
@respx.mock
async def test_admin_ingest_and_generate_report(
    integration_client: AsyncClient,
) -> None:
    """Admin ingest and report generation endpoints should respond successfully."""
    urlhaus_payload = {
        "query_status": "ok",
        "urls": [
            {
                "id": "1",
                "dateadded": "2026-04-01 10:30:00",
                "url": "http://test.bad/payload",
                "url_status": "online",
                "host": "203.0.113.77",
                "threat": "malware_download",
            }
        ],
    }

    respx.get("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(200, json=urlhaus_payload)
    )

    ingest_response = await integration_client.post("/admin/ingest/urlhaus")
    report_response = await integration_client.post("/admin/generate-report")

    assert ingest_response.status_code == 200
    assert report_response.status_code == 200

    ingest_payload = ingest_response.json()
    assert ingest_payload["status"] == "success"
    assert int(ingest_payload["records_fetched"]) >= 1

    report_payload = report_response.json()
    assert report_payload["report_path"] == "docs/feed-quality-report.md"

    report_path = AnyPath(str(_PROJECT_ROOT / "docs" / "feed-quality-report.md"))
    assert await report_path.exists()


@pytest.mark.asyncio
async def test_graph_alert_ingest_and_cluster_query(
    integration_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Graph endpoints should build connected components from alert co-occurrence."""
    for value, ioc_type in [
        ("198.51.100.10", IOCType.ip),
        ("campaign.example", IOCType.domain),
        ("https://campaign.example/dropper", IOCType.url),
    ]:
        await _seed_ioc(
            db_session,
            value=value,
            ioc_type=ioc_type,
            source_id="urlhaus",
            confidence_score=0.78,
        )

    ingest_response = await integration_client.post(
        "/graph/alerts",
        json={
            "alert_id": "alert-1001",
            "iocs": [
                "198.51.100.10",
                "campaign.example",
                "https://campaign.example/dropper",
            ],
        },
    )
    assert ingest_response.status_code == 200
    ingest_payload = ingest_response.json()
    assert ingest_payload["status"] == "created"
    assert ingest_payload["resolved_ioc_count"] == 3
    assert ingest_payload["edges_upserted"] == 3

    cluster_response = await integration_client.get("/graph/clusters?min_size=2")
    assert cluster_response.status_code == 200
    cluster_payload = cluster_response.json()
    assert len(cluster_payload) >= 1
    primary_cluster = cluster_payload[0]
    assert primary_cluster["size"] >= 3

    node_values = {node["ioc_value"] for node in primary_cluster["nodes"]}
    assert "198.51.100.10" in node_values
    assert "campaign.example" in node_values
    assert "https://campaign.example/dropper" in node_values

    duplicate_response = await integration_client.post(
        "/graph/alerts",
        json={
            "alert_id": "alert-1001",
            "iocs": ["198.51.100.10", "campaign.example"],
        },
    )
    assert duplicate_response.status_code == 200
    duplicate_payload = duplicate_response.json()
    assert duplicate_payload["status"] == "duplicate"
