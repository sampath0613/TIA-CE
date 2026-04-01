"""SQLAlchemy ORM models for threat intelligence storage."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.db.database import Base


def utcnow() -> datetime:
    """Return timezone-aware current UTC timestamp."""
    return datetime.now(UTC)


class IOC(Base):
    """Canonical IOC entity deduplicated by value and type."""

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_value", "ioc_type", name="uq_ioc_value_type"),
        Index("ix_iocs_value_type", "ioc_value", "ioc_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ioc_value: Mapped[str] = mapped_column(String(2048), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), default="clean")
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)

    observations: Mapped[list[IOCObservation]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
    )
    feedback_entries: Mapped[list[VerdictFeedback]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
    )
    score_history_entries: Mapped[list[IOCScoreHistory]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
    )


class IOCObservation(Base):
    """Per-source observation metadata for a canonical IOC."""

    __tablename__ = "ioc_observations"
    __table_args__ = (UniqueConstraint("ioc_id", "source_id", name="uq_ioc_source"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        index=True,
    )
    source_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("source_configs.id", ondelete="CASCADE"),
        index=True,
    )
    first_seen_by_source: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_by_source: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_tags: Mapped[str] = mapped_column(Text, default="[]")
    confidence_raw: Mapped[float | None] = mapped_column(Float, nullable=True)

    ioc: Mapped[IOC] = relationship(back_populates="observations")
    source_config: Mapped[SourceConfig] = relationship(back_populates="observations")


class SourceConfig(Base):
    """Feed source configuration and quality counters."""

    __tablename__ = "source_configs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255))
    source_weight: Mapped[float] = mapped_column(Float)
    lambda_ip: Mapped[float] = mapped_column(Float)
    lambda_domain: Mapped[float] = mapped_column(Float)
    lambda_hash: Mapped[float] = mapped_column(Float)
    lambda_url: Mapped[float] = mapped_column(Float)
    last_ingestion_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_ingestion_count: Mapped[int] = mapped_column(Integer, default=0)
    last_ingestion_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cumulative_fp_count: Mapped[int] = mapped_column(Integer, default=0)
    cumulative_tp_count: Mapped[int] = mapped_column(Integer, default=0)

    observations: Mapped[list[IOCObservation]] = relationship(back_populates="source_config")


class IngestionLog(Base):
    """Audit log for every feed ingestion execution."""

    __tablename__ = "ingestion_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_fetched: Mapped[int] = mapped_column(Integer, default=0)
    records_new: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)


class VerdictFeedback(Base):
    """Analyst feedback about IOC verdict correctness."""

    __tablename__ = "verdict_feedback"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        index=True,
    )
    analyst_verdict: Mapped[str] = mapped_column(String(32), index=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    ioc: Mapped[IOC] = relationship(back_populates="feedback_entries")


class IOCScoreHistory(Base):
    """Historical confidence snapshots for IOC scoring changes."""

    __tablename__ = "ioc_score_history"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        index=True,
    )
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    confidence_score: Mapped[float] = mapped_column(Float)
    verdict: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(64), default="recompute")

    ioc: Mapped[IOC] = relationship(back_populates="score_history_entries")


class AlertEvent(Base):
    """External alert event used to register IOC co-occurrence for graph clustering."""

    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    external_alert_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IOCGraphEdge(Base):
    """Undirected IOC graph edge with co-occurrence count."""

    __tablename__ = "ioc_graph_edges"
    __table_args__ = (
        UniqueConstraint("ioc_left_id", "ioc_right_id", name="uq_ioc_graph_edge_pair"),
        Index("ix_ioc_graph_edges_left", "ioc_left_id"),
        Index("ix_ioc_graph_edges_right", "ioc_right_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ioc_left_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    ioc_right_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    cooccurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
