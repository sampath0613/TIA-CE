"""Unit tests for feed adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import respx

from threat_intel.config import Settings
from threat_intel.feeds.alienvault_otx import AlienVaultOTXFeed
from threat_intel.feeds.base import FeedFetchError
from threat_intel.feeds.emerging_threats import EmergingThreatsFeed
from threat_intel.feeds.feodo_tracker import FeodoTrackerFeed
from threat_intel.feeds.urlhaus import URLHausFeed
from threat_intel.models.ioc import IOCType

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load_fixture_json(filename: str) -> dict[str, Any] | list[dict[str, Any]]:
    with (_FIXTURES / filename).open("r", encoding="utf-8") as file_obj:
        return cast(dict[str, Any] | list[dict[str, Any]], json.load(file_obj))


def _load_fixture_text(filename: str) -> str:
    with (_FIXTURES / filename).open("r", encoding="utf-8") as file_obj:
        return file_obj.read()


@pytest.mark.asyncio
@respx.mock
async def test_feodo_fetch_success() -> None:
    """Feodo adapter should parse valid IPv4 records into NormalizedIOC rows."""
    payload = _load_fixture_json("feodo_response.json")
    respx.get(FeodoTrackerFeed.endpoint).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        adapter = FeodoTrackerFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        records = await adapter.fetch()

    assert len(records) == 2
    assert all(record.source_id == FeodoTrackerFeed.source_id for record in records)
    assert all(record.ioc_type == IOCType.ip for record in records)


@pytest.mark.asyncio
@respx.mock
async def test_feodo_fetch_http_error_retries_then_fails() -> None:
    """Feodo adapter should raise FeedFetchError after retry budget is exhausted."""
    respx.get(FeodoTrackerFeed.endpoint).mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )

    async with httpx.AsyncClient() as client:
        adapter = FeodoTrackerFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        with pytest.raises(FeedFetchError):
            await adapter.fetch()


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_fetch_success() -> None:
    """URLhaus adapter should parse online URL records and IPv4 hosts."""
    payload = _load_fixture_json("urlhaus_response.json")
    respx.get(URLHausFeed.endpoint).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        adapter = URLHausFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        records = await adapter.fetch()

    url_iocs = [record for record in records if record.ioc_type == IOCType.url]
    ip_iocs = [record for record in records if record.ioc_type == IOCType.ip]

    assert len(url_iocs) == 2
    assert len(ip_iocs) == 1
    assert all(record.source_id == URLHausFeed.source_id for record in records)


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_fetch_http_error_retries_then_fails() -> None:
    """URLhaus adapter should raise FeedFetchError after transient failures persist."""
    respx.get(URLHausFeed.endpoint).mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )

    async with httpx.AsyncClient() as client:
        adapter = URLHausFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        with pytest.raises(FeedFetchError):
            await adapter.fetch()


@pytest.mark.asyncio
@respx.mock
async def test_emerging_threats_fetch_success() -> None:
    """Emerging Threats adapter should parse plain-text IP lines."""
    payload = _load_fixture_text("emerging_threats_response.txt")
    respx.get(EmergingThreatsFeed.endpoint).mock(return_value=httpx.Response(200, text=payload))

    async with httpx.AsyncClient() as client:
        adapter = EmergingThreatsFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        records = await adapter.fetch()

    assert len(records) == 3
    assert all(record.ioc_type == IOCType.ip for record in records)
    assert all(record.source_id == EmergingThreatsFeed.source_id for record in records)


@pytest.mark.asyncio
@respx.mock
async def test_emerging_threats_fetch_http_error_retries_then_fails() -> None:
    """Emerging Threats adapter should raise FeedFetchError on repeated server errors."""
    respx.get(EmergingThreatsFeed.endpoint).mock(
        return_value=httpx.Response(500, text="upstream error")
    )

    async with httpx.AsyncClient() as client:
        adapter = EmergingThreatsFeed(Settings(), client)
        adapter.base_backoff_seconds = 0.0
        with pytest.raises(FeedFetchError):
            await adapter.fetch()


@pytest.mark.asyncio
@respx.mock
async def test_otx_fetch_success_with_pagination() -> None:
    """OTX adapter should fetch all pages and map supported indicator types."""
    page_one = _load_fixture_json("otx_response_page1.json")
    page_two = _load_fixture_json("otx_response_page2.json")

    respx.get(AlienVaultOTXFeed.endpoint).mock(
        side_effect=[
            httpx.Response(200, json=page_one, headers={"X-RateLimit-Remaining": "10"}),
            httpx.Response(200, json=page_two, headers={"X-RateLimit-Remaining": "10"}),
        ]
    )

    settings = Settings(otx_api_key="otx-test-key")
    async with httpx.AsyncClient() as client:
        adapter = AlienVaultOTXFeed(settings, client)
        adapter.base_backoff_seconds = 0.0
        records = await adapter.fetch()

    assert len(records) == 5
    assert all(record.source_id == AlienVaultOTXFeed.source_id for record in records)
    assert IOCType.hash in {record.ioc_type for record in records}


@pytest.mark.asyncio
@respx.mock
async def test_otx_fetch_http_error_retries_then_fails() -> None:
    """OTX adapter should raise FeedFetchError after retry budget is exhausted."""
    respx.get(AlienVaultOTXFeed.endpoint).mock(
        return_value=httpx.Response(500, json={"detail": "failure"})
    )

    settings = Settings(otx_api_key="otx-test-key")
    async with httpx.AsyncClient() as client:
        adapter = AlienVaultOTXFeed(settings, client)
        adapter.base_backoff_seconds = 0.0
        with pytest.raises(FeedFetchError):
            await adapter.fetch()


@pytest.mark.asyncio
async def test_otx_fetch_requires_api_key() -> None:
    """OTX adapter should fail fast when API key is not configured."""
    async with httpx.AsyncClient() as client:
        adapter = AlienVaultOTXFeed(Settings(otx_api_key=None), client)
        with pytest.raises(FeedFetchError):
            await adapter.fetch()
