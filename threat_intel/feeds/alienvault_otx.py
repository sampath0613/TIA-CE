"""AlienVault OTX feed adapter."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from datetime import UTC, datetime
from typing import ClassVar

from threat_intel.feeds.base import BaseFeedAdapter, FeedFetchError
from threat_intel.models.ioc import IOCType, NormalizedIOC

_MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


class AlienVaultOTXFeed(BaseFeedAdapter):
    """Adapter for AlienVault OTX subscribed pulses API."""

    source_id = "alienvault_otx"
    display_name = "AlienVault OTX"
    default_weight = 0.65
    endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    _IOC_TYPE_MAP: ClassVar[dict[str, IOCType]] = {
        "ipv4": IOCType.ip,
        "ipv4-addr": IOCType.ip,
        "domain": IOCType.domain,
        "hostname": IOCType.domain,
        "url": IOCType.url,
        "uri": IOCType.url,
        "filehash-md5": IOCType.hash,
        "filehash-sha1": IOCType.hash,
        "filehash-sha256": IOCType.hash,
        "filehash": IOCType.hash,
        "sha1": IOCType.hash,
        "sha256": IOCType.hash,
        "md5": IOCType.hash,
    }

    async def health_check(self) -> bool:
        """Check OTX reachability using authenticated API request."""
        if not self.settings.otx_api_key:
            return False

        try:
            await self._get_with_retries(
                self.endpoint,
                headers={"X-OTX-API-KEY": self.settings.otx_api_key},
                params={"limit": 1},
                request_timeout_seconds=10.0,
            )
            return True
        except FeedFetchError:
            return False

    async def fetch(self) -> list[NormalizedIOC]:
        """Fetch IOC records from AlienVault OTX."""
        if not self.settings.otx_api_key:
            raise FeedFetchError("OTX_API_KEY is required for AlienVault OTX ingestion")

        headers = {"X-OTX-API-KEY": self.settings.otx_api_key}
        start = time.perf_counter()
        now = datetime.now(UTC)
        records: list[NormalizedIOC] = []

        page = 1
        while True:
            response = await self._get_with_retries(
                self.endpoint,
                headers=headers,
                params={"page": page},
            )

            payload = response.json()
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                raise FeedFetchError("alienvault_otx payload missing results list")

            for pulse in results:
                if not isinstance(pulse, dict):
                    continue
                modified_at = _parse_datetime(str(pulse.get("modified", "")).strip()) or now
                indicators = pulse.get("indicators")
                if not isinstance(indicators, list):
                    continue

                for indicator in indicators:
                    if not isinstance(indicator, dict):
                        continue

                    indicator_value = str(indicator.get("indicator", "")).strip()
                    indicator_type_raw = str(indicator.get("type", "")).strip().lower()
                    ioc_type = self._IOC_TYPE_MAP.get(indicator_type_raw)

                    if not indicator_value or ioc_type is None:
                        continue
                    if not _is_valid_ioc_value(indicator_value, ioc_type):
                        continue

                    records.append(
                        NormalizedIOC(
                            ioc_value=indicator_value,
                            ioc_type=ioc_type,
                            source_id=self.source_id,
                            first_seen=modified_at,
                            last_seen=modified_at,
                            raw_tags=["otx_pulse"],
                            confidence_raw=None,
                        )
                    )

            remaining_header = response.headers.get("X-RateLimit-Remaining")
            if remaining_header is not None:
                try:
                    if int(remaining_header) <= 0:
                        await asyncio.sleep(1.0)
                except ValueError:
                    pass

            next_page = payload.get("next") if isinstance(payload, dict) else None
            if not next_page:
                break

            page += 1

        duration_ms = (time.perf_counter() - start) * 1000
        self.logger.info(
            "feed_fetch_complete source_id=%s records=%s duration_ms=%.2f",
            self.source_id,
            len(records),
            duration_ms,
        )

        return records


def _parse_datetime(value: str) -> datetime | None:
    """Parse datetime values from OTX API."""
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


def _is_valid_ioc_value(value: str, ioc_type: IOCType) -> bool:
    """Validate indicator value by IOC type."""
    if ioc_type == IOCType.ip:
        try:
            parsed = ipaddress.ip_address(value)
            return parsed.version == 4
        except ValueError:
            return False

    if ioc_type == IOCType.hash:
        return bool(
            _MD5_PATTERN.match(value)
            or _SHA1_PATTERN.match(value)
            or _SHA256_PATTERN.match(value)
        )

    if ioc_type == IOCType.url:
        lowered = value.lower()
        return lowered.startswith("http://") or lowered.startswith("https://")

    return "." in value
