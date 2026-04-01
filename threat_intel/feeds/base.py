"""Base classes and shared logic for threat intel feed adapters."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from threat_intel.config import Settings
from threat_intel.models.ioc import NormalizedIOC


class FeedFetchError(Exception):
    """Raised when a feed adapter cannot retrieve data after retries."""


class BaseFeedAdapter(ABC):
    """Abstract base for all feed adapters."""

    source_id: ClassVar[str]
    display_name: ClassVar[str]
    default_weight: ClassVar[float]
    max_retries: int = 3
    base_backoff_seconds: float = 1.0

    def __init__(self, settings: Settings, http_client: httpx.AsyncClient):
        """Initialize adapter with shared settings and async HTTP client."""
        self.settings = settings
        self.client = http_client
        self.logger = logging.getLogger(f"{__name__}.{self.source_id}")

    @abstractmethod
    async def fetch(self) -> list[NormalizedIOC]:
        """Fetch all current IOCs from this feed."""

    async def health_check(self) -> bool:
        """Return True when the feed endpoint responds successfully."""
        endpoint = getattr(self, "endpoint", None)
        if not isinstance(endpoint, str) or not endpoint:
            return False

        try:
            head_response = await self.client.head(endpoint, timeout=10.0)
            if head_response.status_code < 400:
                return True
            if head_response.status_code not in {405, 501}:
                return False
        except (httpx.TimeoutException, httpx.NetworkError):
            pass

        try:
            await self._get_with_retries(endpoint, request_timeout_seconds=10.0)
            return True
        except FeedFetchError:
            return False

    async def _get_with_retries(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | int] | None = None,
        request_timeout_seconds: float = 30.0,
    ) -> httpx.Response:
        """Perform GET with exponential backoff for transient errors."""
        last_exception: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            start = time.perf_counter()
            try:
                response = await self.client.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=request_timeout_seconds,
                )

                if response.status_code in {429, 500, 502, 503, 504}:
                    response.raise_for_status()

                response.raise_for_status()
                duration_ms = (time.perf_counter() - start) * 1000
                self.logger.info(
                    "feed_http_success source_id=%s attempt=%s status_code=%s duration_ms=%.2f",
                    self.source_id,
                    attempt,
                    response.status_code,
                    duration_ms,
                )
                return response
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                duration_ms = (time.perf_counter() - start) * 1000
                last_exception = exc

                retryable = not isinstance(exc, httpx.HTTPStatusError)
                if isinstance(exc, httpx.HTTPStatusError):
                    status_code = exc.response.status_code if exc.response is not None else None
                    retryable = status_code in {429, 500, 502, 503, 504}

                self.logger.warning(
                    (
                        "feed_http_retry source_id=%s attempt=%s "
                        "retryable=%s duration_ms=%.2f error=%s"
                    ),
                    self.source_id,
                    attempt,
                    retryable,
                    duration_ms,
                    str(exc),
                )

                if attempt >= self.max_retries or not retryable:
                    break

                await asyncio.sleep(self.base_backoff_seconds * (2 ** (attempt - 1)))

        raise FeedFetchError(f"{self.source_id} fetch failed after retries") from last_exception
