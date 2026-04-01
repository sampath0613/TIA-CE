"""URLhaus feed adapter."""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from threat_intel.feeds.base import BaseFeedAdapter, FeedFetchError
from threat_intel.models.ioc import IOCType, NormalizedIOC


class URLHausFeed(BaseFeedAdapter):
    """Adapter for URLhaus recent URLs feed."""

    source_id = "urlhaus"
    display_name = "URLhaus"
    default_weight = 0.80
    endpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    async def fetch(self) -> list[NormalizedIOC]:
        """Fetch online URL and host indicators from URLhaus."""
        start = time.perf_counter()
        response = await self._get_with_retries(self.endpoint)

        payload = response.json()
        urls = payload.get("urls") if isinstance(payload, dict) else None
        if not isinstance(urls, list):
            raise FeedFetchError("urlhaus payload missing urls list")

        now = datetime.now(UTC)
        records: list[NormalizedIOC] = []

        for row in urls:
            if not isinstance(row, dict):
                continue

            status = str(row.get("url_status", "")).strip().lower()
            if status != "online":
                continue

            observed_at = _parse_datetime(str(row.get("dateadded", "")).strip()) or now
            threat = str(row.get("threat", "")).strip()
            tags = [threat] if threat else []

            url_value = str(row.get("url", "")).strip()
            if url_value:
                records.append(
                    NormalizedIOC(
                        ioc_value=url_value,
                        ioc_type=IOCType.url,
                        source_id=self.source_id,
                        first_seen=observed_at,
                        last_seen=observed_at,
                        raw_tags=tags,
                        confidence_raw=0.80,
                    )
                )

            host_value = str(row.get("host", "")).strip()
            if not host_value:
                continue

            try:
                parsed_host = ipaddress.ip_address(host_value)
                if parsed_host.version != 4:
                    continue
            except ValueError:
                continue

            records.append(
                NormalizedIOC(
                    ioc_value=host_value,
                    ioc_type=IOCType.ip,
                    source_id=self.source_id,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    raw_tags=tags,
                    confidence_raw=0.70,
                )
            )

        duration_ms = (time.perf_counter() - start) * 1000
        self.logger.info(
            "feed_fetch_complete source_id=%s records=%s duration_ms=%.2f",
            self.source_id,
            len(records),
            duration_ms,
        )
        return records


def _parse_datetime(value: str) -> datetime | None:
    """Parse URLhaus datetime values."""
    if not value:
        return None

    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
