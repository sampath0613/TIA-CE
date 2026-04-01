"""Integration tests for feed ingestion pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import respx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.models.db import IOC, IngestionLog
from threat_intel.pipeline.ingestor import run_all_feeds

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load_fixture_json(filename: str) -> dict[str, Any] | list[dict[str, Any]]:
    with (_FIXTURES / filename).open("r", encoding="utf-8") as file_obj:
        return cast(dict[str, Any] | list[dict[str, Any]], json.load(file_obj))


def _load_fixture_text(filename: str) -> str:
    with (_FIXTURES / filename).open("r", encoding="utf-8") as file_obj:
        return file_obj.read()


@pytest.mark.asyncio
@respx.mock
async def test_ingestion_pipeline_for_registered_feeds(db_session: AsyncSession) -> None:
    """Ingestion should persist IOCs, logs, and confidence scores for mocked feeds."""
    feodo_payload = _load_fixture_json("feodo_response.json")
    urlhaus_payload = _load_fixture_json("urlhaus_response.json")
    otx_page_one = _load_fixture_json("otx_response_page1.json")
    otx_page_two = _load_fixture_json("otx_response_page2.json")
    emerging_payload = _load_fixture_text("emerging_threats_response.txt")

    respx.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").mock(
        return_value=httpx.Response(200, json=feodo_payload)
    )
    respx.get("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(200, json=urlhaus_payload)
    )
    respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        side_effect=[
            httpx.Response(200, json=otx_page_one, headers={"X-RateLimit-Remaining": "5"}),
            httpx.Response(200, json=otx_page_two, headers={"X-RateLimit-Remaining": "5"}),
        ]
    )
    respx.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt").mock(
        return_value=httpx.Response(200, text=emerging_payload)
    )

    await run_all_feeds(db_session)

    ioc_count = await db_session.scalar(select(func.count()).select_from(IOC))
    assert ioc_count is not None
    assert ioc_count >= 8

    result = await db_session.execute(select(IngestionLog).order_by(IngestionLog.started_at.asc()))
    logs = list(result.scalars().all())
    assert len(logs) == 4
    assert all(log.status == "success" for log in logs)
    assert all(log.records_fetched > 0 for log in logs)

    result_iocs = await db_session.execute(select(IOC))
    iocs = list(result_iocs.scalars().all())
    assert all(ioc.confidence_score >= 0.0 for ioc in iocs)
