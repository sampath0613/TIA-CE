"""Feodo Tracker feed adapter."""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from threat_intel.feeds.base import BaseFeedAdapter, FeedFetchError
from threat_intel.models.ioc import IOCType, NormalizedIOC


class FeodoTrackerFeed(BaseFeedAdapter):
    """Adapter for Feodo Tracker IP blocklist feed."""

    source_id = "feodo_tracker"
    display_name = "Feodo Tracker"
    default_weight = 0.90
    endpoint = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    async def fetch(self) -> list[NormalizedIOC]:
        """Fetch IOC records from Feodo Tracker JSON endpoint."""
        start = time.perf_counter()
        response = await self._get_with_retries(self.endpoint)

        payload = response.json()
        if not isinstance(payload, list):
            raise FeedFetchError("feodo_tracker payload is not a list")

        now = datetime.now(UTC)
        records: list[NormalizedIOC] = []

        for row in payload:
            if not isinstance(row, dict):
                continue
            ip_value = str(row.get("ip_address", "")).strip()
            if not ip_value:
                continue

            try:
                parsed_ip = ipaddress.ip_address(ip_value)
                if parsed_ip.version != 4:
                    continue
            except ValueError:
                continue

            last_online_raw = str(row.get("last_online", "")).strip()
            observed_at = _parse_datetime(last_online_raw) or now
            malware = str(row.get("malware", "")).strip()
            tags = [malware] if malware else []

            records.append(
                NormalizedIOC(
                    ioc_value=ip_value,
                    ioc_type=IOCType.ip,
                    source_id=self.source_id,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    raw_tags=tags,
                    confidence_raw=0.95,
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
    """Parse datetime from heterogeneous feed formats."""
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
