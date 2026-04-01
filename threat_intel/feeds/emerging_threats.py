"""Emerging Threats feed adapter."""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from threat_intel.feeds.base import BaseFeedAdapter
from threat_intel.models.ioc import IOCType, NormalizedIOC


class EmergingThreatsFeed(BaseFeedAdapter):
    """Adapter for Emerging Threats compromised IP feed."""

    source_id = "emerging_threats"
    display_name = "Emerging Threats"
    default_weight = 0.70
    endpoint = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

    async def fetch(self) -> list[NormalizedIOC]:
        """Fetch IOC records from Emerging Threats feed."""
        start = time.perf_counter()
        response = await self._get_with_retries(self.endpoint)
        now = datetime.now(UTC)

        records: list[NormalizedIOC] = []
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            ip_value = line.split()[0].strip()
            try:
                parsed_ip = ipaddress.ip_address(ip_value)
                if parsed_ip.version != 4:
                    continue
            except ValueError:
                continue

            records.append(
                NormalizedIOC(
                    ioc_value=ip_value,
                    ioc_type=IOCType.ip,
                    source_id=self.source_id,
                    first_seen=now,
                    last_seen=now,
                    raw_tags=["compromised_ip"],
                    confidence_raw=0.75,
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
