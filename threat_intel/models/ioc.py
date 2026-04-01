"""Pydantic models and enums for IOC data flow and API contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    """Supported IOC categories."""

    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"


class Verdict(str, Enum):
    """Derived IOC verdict based on confidence thresholds."""

    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"


class NormalizedIOC(BaseModel):
    """Output of every feed adapter and input to deduplication/scoring."""

    ioc_value: str
    ioc_type: IOCType
    source_id: str
    first_seen: datetime
    last_seen: datetime
    raw_tags: list[str] = Field(default_factory=list)
    confidence_raw: float | None = None


class IOCSourceObservation(BaseModel):
    """Per-source observation details for an IOC response."""

    source_id: str
    display_name: str
    first_seen_by_source: datetime
    last_seen_by_source: datetime
    raw_tags: list[str] = Field(default_factory=list)
    confidence_raw: float | None = None


class IOCResponse(BaseModel):
    """API response for an IOC enrichment query."""

    ioc_value: str
    ioc_type: IOCType
    confidence_score: float
    verdict: Verdict
    observation_count: int
    first_seen: datetime
    last_seen: datetime
    sources: list[str]
    source_observations: list[IOCSourceObservation] = Field(default_factory=list)
    false_positive_count: int


class BulkIOCRequest(BaseModel):
    """Bulk IOC lookup request payload."""

    iocs: list[str] = Field(min_length=1, max_length=100)


class VerdictFeedback(BaseModel):
    """Analyst feedback payload for model calibration."""

    verdict: Literal["true_positive", "false_positive"]
    notes: str | None = None


class GraphAlertIngestRequest(BaseModel):
    """Request payload for registering IOC co-occurrence from one alert."""

    alert_id: str = Field(min_length=1, max_length=255)
    iocs: list[str] = Field(min_length=2, max_length=200)
    observed_at: datetime | None = None


class GraphAlertIngestResponse(BaseModel):
    """Response payload after alert co-occurrence ingestion."""

    alert_id: str
    status: Literal["created", "duplicate"]
    resolved_ioc_count: int
    edges_upserted: int


class IOCClusterNode(BaseModel):
    """IOC node returned as part of a connected graph cluster."""

    ioc_value: str
    ioc_type: IOCType
    confidence_score: float
    verdict: Verdict


class IOCClusterResponse(BaseModel):
    """Connected-component view of related IOCs."""

    cluster_id: int
    size: int
    edge_count: int
    nodes: list[IOCClusterNode]
