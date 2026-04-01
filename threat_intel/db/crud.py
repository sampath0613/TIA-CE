"""Centralized async CRUD operations for all database reads and writes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.models.db import (
    IOC,
    AlertEvent,
    IngestionLog,
    IOCGraphEdge,
    IOCObservation,
    IOCScoreHistory,
    SourceConfig,
    VerdictFeedback,
)


def _ensure_utc(value: datetime) -> datetime:
    """Coerce naive/aware datetimes to UTC-aware values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def get_ioc_by_value_type(
    ioc_value: str,
    ioc_type: str,
    db: AsyncSession,
    *,
    for_update: bool = False,
) -> IOC | None:
    """Get an IOC by deduplication key.

    Args:
        ioc_value: IOC value.
        ioc_type: IOC type.
        db: Async session.
        for_update: Lock row for update when True.

    Returns:
        The IOC entity if found.
    """
    stmt: Select[tuple[IOC]] = select(IOC).where(
        and_(IOC.ioc_value == ioc_value, IOC.ioc_type == ioc_type)
    )
    if for_update:
        stmt = stmt.with_for_update()
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_ioc_by_id(ioc_id: uuid.UUID, db: AsyncSession) -> IOC | None:
    """Get an IOC by primary key.

    Args:
        ioc_id: IOC identifier.
        db: Async database session.

    Returns:
        IOC row if present.
    """
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    return result.scalar_one_or_none()


async def create_ioc(
    ioc_value: str,
    ioc_type: str,
    first_seen: datetime,
    last_seen: datetime,
    db: AsyncSession,
) -> IOC:
    """Create a canonical IOC row."""
    ioc = IOC(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        first_seen=_ensure_utc(first_seen),
        last_seen=_ensure_utc(last_seen),
        observation_count=1,
        confidence_score=0.0,
        verdict="clean",
    )
    db.add(ioc)
    await db.flush()
    return ioc


async def update_ioc_seen_window(
    ioc: IOC,
    first_seen: datetime,
    last_seen: datetime,
    db: AsyncSession,
) -> IOC:
    """Update IOC first/last seen bounds using min/max semantics."""
    current_first_seen = _ensure_utc(ioc.first_seen)
    current_last_seen = _ensure_utc(ioc.last_seen)
    incoming_first_seen = _ensure_utc(first_seen)
    incoming_last_seen = _ensure_utc(last_seen)

    ioc.first_seen = min(current_first_seen, incoming_first_seen)
    ioc.last_seen = max(current_last_seen, incoming_last_seen)
    await db.flush()
    return ioc


async def get_observation(
    ioc_id: uuid.UUID,
    source_id: str,
    db: AsyncSession,
    *,
    for_update: bool = False,
) -> IOCObservation | None:
    """Get observation for IOC-source pair."""
    stmt: Select[tuple[IOCObservation]] = select(IOCObservation).where(
        and_(IOCObservation.ioc_id == ioc_id, IOCObservation.source_id == source_id)
    )
    if for_update:
        stmt = stmt.with_for_update()
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def create_observation(
    ioc_id: uuid.UUID,
    source_id: str,
    first_seen_by_source: datetime,
    last_seen_by_source: datetime,
    raw_tags: str,
    confidence_raw: float | None,
    db: AsyncSession,
) -> IOCObservation:
    """Create IOC observation row for a specific source."""
    observation = IOCObservation(
        ioc_id=ioc_id,
        source_id=source_id,
        first_seen_by_source=_ensure_utc(first_seen_by_source),
        last_seen_by_source=_ensure_utc(last_seen_by_source),
        raw_tags=raw_tags,
        confidence_raw=confidence_raw,
    )
    db.add(observation)
    await db.flush()
    return observation


async def update_observation(
    observation: IOCObservation,
    first_seen_by_source: datetime,
    last_seen_by_source: datetime,
    raw_tags: str,
    confidence_raw: float | None,
    db: AsyncSession,
) -> IOCObservation:
    """Update IOC observation row while preserving earliest first-seen timestamp."""
    current_first_seen = _ensure_utc(observation.first_seen_by_source)
    current_last_seen = _ensure_utc(observation.last_seen_by_source)
    incoming_first_seen = _ensure_utc(first_seen_by_source)
    incoming_last_seen = _ensure_utc(last_seen_by_source)

    observation.first_seen_by_source = min(current_first_seen, incoming_first_seen)
    observation.last_seen_by_source = max(current_last_seen, incoming_last_seen)
    observation.raw_tags = raw_tags
    observation.confidence_raw = confidence_raw
    await db.flush()
    return observation


async def increment_ioc_observation_count(ioc: IOC, db: AsyncSession) -> IOC:
    """Increment IOC observation_count when a new source is added."""
    ioc.observation_count += 1
    await db.flush()
    return ioc


async def update_ioc_confidence_and_verdict(
    ioc: IOC,
    confidence_score: float,
    verdict: str,
    db: AsyncSession,
) -> IOC:
    """Persist recomputed confidence and derived verdict."""
    ioc.confidence_score = confidence_score
    ioc.verdict = verdict
    await db.flush()
    return ioc


async def create_ioc_score_history(
    ioc_id: uuid.UUID,
    confidence_score: float,
    verdict: str,
    reason: str,
    db: AsyncSession,
) -> IOCScoreHistory:
    """Persist a single confidence snapshot in IOC score history."""
    score_history = IOCScoreHistory(
        ioc_id=ioc_id,
        confidence_score=confidence_score,
        verdict=verdict,
        reason=reason,
    )
    db.add(score_history)
    await db.flush()
    return score_history


async def increment_ioc_false_positive_count(ioc: IOC, db: AsyncSession) -> IOC:
    """Increment IOC false positive count after analyst feedback."""
    ioc.false_positive_count += 1
    await db.flush()
    return ioc


async def get_ioc_observations(ioc_id: uuid.UUID, db: AsyncSession) -> list[IOCObservation]:
    """Return all source observations for an IOC."""
    result = await db.execute(select(IOCObservation).where(IOCObservation.ioc_id == ioc_id))
    return list(result.scalars().all())


async def get_source_config(source_id: str, db: AsyncSession) -> SourceConfig | None:
    """Get source configuration by source ID."""
    result = await db.execute(select(SourceConfig).where(SourceConfig.id == source_id))
    return result.scalar_one_or_none()


async def get_all_source_configs(db: AsyncSession) -> list[SourceConfig]:
    """Get all source configuration rows."""
    result = await db.execute(select(SourceConfig).order_by(SourceConfig.id.asc()))
    return list(result.scalars().all())


async def upsert_source_config(
    source_id: str,
    display_name: str,
    source_weight: float,
    lambda_ip: float,
    lambda_domain: float,
    lambda_hash: float,
    lambda_url: float,
    db: AsyncSession,
) -> SourceConfig:
    """Insert or update source configuration defaults."""
    source_config = await get_source_config(source_id, db)
    if source_config is None:
        source_config = SourceConfig(
            id=source_id,
            display_name=display_name,
            source_weight=source_weight,
            lambda_ip=lambda_ip,
            lambda_domain=lambda_domain,
            lambda_hash=lambda_hash,
            lambda_url=lambda_url,
        )
        db.add(source_config)
    else:
        source_config.display_name = display_name
        source_config.source_weight = source_weight
        source_config.lambda_ip = lambda_ip
        source_config.lambda_domain = lambda_domain
        source_config.lambda_hash = lambda_hash
        source_config.lambda_url = lambda_url
    await db.flush()
    return source_config


async def update_source_weight(
    source_id: str,
    source_weight: float,
    db: AsyncSession,
) -> SourceConfig | None:
    """Update a source weight value."""
    source_config = await get_source_config(source_id, db)
    if source_config is None:
        return None
    source_config.source_weight = source_weight
    await db.flush()
    return source_config


async def update_source_ingestion_status(
    source_id: str,
    *,
    last_ingestion_at: datetime | None,
    last_ingestion_count: int,
    last_ingestion_error: str | None,
    db: AsyncSession,
) -> None:
    """Update latest ingestion metadata for a source."""
    source_config = await get_source_config(source_id, db)
    if source_config is None:
        return
    source_config.last_ingestion_at = last_ingestion_at
    source_config.last_ingestion_count = last_ingestion_count
    source_config.last_ingestion_error = last_ingestion_error
    await db.flush()


async def update_source_feedback_counters(
    source_id: str,
    *,
    false_positive_delta: int,
    true_positive_delta: int,
    db: AsyncSession,
) -> None:
    """Increment cumulative feedback counters for a source."""
    source_config = await get_source_config(source_id, db)
    if source_config is None:
        return
    source_config.cumulative_fp_count += false_positive_delta
    source_config.cumulative_tp_count += true_positive_delta
    await db.flush()


async def create_ingestion_log(
    source_id: str,
    started_at: datetime,
    db: AsyncSession,
) -> IngestionLog:
    """Create an ingestion log entry with running status."""
    log_entry = IngestionLog(
        source_id=source_id,
        started_at=started_at,
        status="running",
        records_fetched=0,
        records_new=0,
        records_updated=0,
    )
    db.add(log_entry)
    await db.flush()
    return log_entry


async def finalize_ingestion_log(
    ingestion_log: IngestionLog,
    *,
    completed_at: datetime,
    records_fetched: int,
    records_new: int,
    records_updated: int,
    status: str,
    error_message: str | None,
    db: AsyncSession,
) -> IngestionLog:
    """Finalize an ingestion log entry."""
    ingestion_log.completed_at = completed_at
    ingestion_log.records_fetched = records_fetched
    ingestion_log.records_new = records_new
    ingestion_log.records_updated = records_updated
    ingestion_log.status = status
    ingestion_log.error_message = error_message
    await db.flush()
    return ingestion_log


async def create_verdict_feedback(
    ioc_id: uuid.UUID,
    analyst_verdict: str,
    submitted_at: datetime,
    notes: str | None,
    db: AsyncSession,
) -> VerdictFeedback:
    """Persist analyst verdict feedback for an IOC."""
    feedback = VerdictFeedback(
        ioc_id=ioc_id,
        analyst_verdict=analyst_verdict,
        submitted_at=submitted_at,
        notes=notes,
    )
    db.add(feedback)
    await db.flush()
    return feedback


async def get_alert_event_by_external_id(
    external_alert_id: str,
    db: AsyncSession,
) -> AlertEvent | None:
    """Return one alert-event row by external alert identifier."""
    result = await db.execute(
        select(AlertEvent).where(AlertEvent.external_alert_id == external_alert_id)
    )
    return result.scalar_one_or_none()


async def create_alert_event(
    external_alert_id: str,
    observed_at: datetime,
    db: AsyncSession,
) -> AlertEvent:
    """Create a new alert event used for IOC co-occurrence graphing."""
    alert_event = AlertEvent(
        external_alert_id=external_alert_id,
        observed_at=_ensure_utc(observed_at),
    )
    db.add(alert_event)
    await db.flush()
    return alert_event


def _canonical_edge_pair(
    ioc_a_id: uuid.UUID,
    ioc_b_id: uuid.UUID,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Return a stable undirected edge ordering for IOC pair keys."""
    if ioc_a_id.hex <= ioc_b_id.hex:
        return ioc_a_id, ioc_b_id
    return ioc_b_id, ioc_a_id


async def upsert_ioc_graph_edge(
    ioc_a_id: uuid.UUID,
    ioc_b_id: uuid.UUID,
    observed_at: datetime,
    db: AsyncSession,
) -> IOCGraphEdge | None:
    """Create or increment an undirected IOC co-occurrence edge."""
    if ioc_a_id == ioc_b_id:
        return None

    left_id, right_id = _canonical_edge_pair(ioc_a_id, ioc_b_id)
    stmt = select(IOCGraphEdge).where(
        and_(IOCGraphEdge.ioc_left_id == left_id, IOCGraphEdge.ioc_right_id == right_id)
    )
    result = await db.execute(stmt)
    edge = result.scalar_one_or_none()

    observed_utc = _ensure_utc(observed_at)
    if edge is None:
        edge = IOCGraphEdge(
            ioc_left_id=left_id,
            ioc_right_id=right_id,
            cooccurrence_count=1,
            first_seen=observed_utc,
            last_seen=observed_utc,
        )
        db.add(edge)
        await db.flush()
        return edge

    edge.cooccurrence_count += 1
    edge.first_seen = min(_ensure_utc(edge.first_seen), observed_utc)
    edge.last_seen = max(_ensure_utc(edge.last_seen), observed_utc)
    await db.flush()
    return edge


async def get_iocs_by_ids(ioc_ids: list[uuid.UUID], db: AsyncSession) -> list[IOC]:
    """Return IOC rows for a list of IOC identifiers."""
    if not ioc_ids:
        return []

    result = await db.execute(select(IOC).where(IOC.id.in_(ioc_ids)))
    return list(result.scalars().all())


async def get_graph_edges(
    min_cooccurrence: int,
    db: AsyncSession,
) -> list[tuple[uuid.UUID, uuid.UUID, int]]:
    """Return graph edges above a minimum co-occurrence threshold."""
    threshold = max(min_cooccurrence, 1)
    result = await db.execute(
        select(
            IOCGraphEdge.ioc_left_id,
            IOCGraphEdge.ioc_right_id,
            IOCGraphEdge.cooccurrence_count,
        ).where(IOCGraphEdge.cooccurrence_count >= threshold)
    )
    return [(left, right, int(weight)) for left, right, weight in result.all()]


async def get_source_ids_for_ioc(ioc_id: uuid.UUID, db: AsyncSession) -> list[str]:
    """Return source IDs that have reported an IOC."""
    result = await db.execute(
        select(IOCObservation.source_id).where(IOCObservation.ioc_id == ioc_id).distinct()
    )
    return [row[0] for row in result.all()]


async def get_ioc_count_by_source(db: AsyncSession) -> list[tuple[str, int]]:
    """Get IOC counts per source from observation table."""
    result = await db.execute(
        select(IOCObservation.source_id, func.count(IOCObservation.ioc_id))
        .group_by(IOCObservation.source_id)
        .order_by(func.count(IOCObservation.ioc_id).desc())
    )
    return [(source_id, count) for source_id, count in result.all()]


async def get_feed_health_rows(db: AsyncSession) -> list[dict[str, object]]:
    """Return aggregate feed health metrics for statistics endpoints."""
    avg_confidence_expr = func.avg(
        case(
            (IOCObservation.ioc_id.is_not(None), IOC.confidence_score),
            else_=None,
        )
    )

    ingestion_stats = (
        select(
            IngestionLog.source_id.label("source_id"),
            func.count(IngestionLog.id).label("run_count"),
            func.sum(case((IngestionLog.status == "failed", 1), else_=0)).label("failed_count"),
        )
        .group_by(IngestionLog.source_id)
        .subquery()
    )

    stmt = (
        select(
            SourceConfig.id,
            SourceConfig.display_name,
            SourceConfig.source_weight,
            SourceConfig.last_ingestion_at,
            SourceConfig.last_ingestion_count,
            SourceConfig.last_ingestion_error,
            SourceConfig.cumulative_fp_count,
            SourceConfig.cumulative_tp_count,
            func.count(IOCObservation.ioc_id).label("ioc_count"),
            avg_confidence_expr.label("avg_confidence"),
            func.coalesce(ingestion_stats.c.run_count, 0).label("ingestion_run_count"),
            func.coalesce(ingestion_stats.c.failed_count, 0).label("ingestion_failed_count"),
        )
        .outerjoin(IOCObservation, IOCObservation.source_id == SourceConfig.id)
        .outerjoin(IOC, IOC.id == IOCObservation.ioc_id)
        .outerjoin(ingestion_stats, ingestion_stats.c.source_id == SourceConfig.id)
        .group_by(
            SourceConfig.id,
            ingestion_stats.c.run_count,
            ingestion_stats.c.failed_count,
        )
    )

    result = await db.execute(stmt)
    rows: list[dict[str, object]] = []
    for row in result.mappings().all():
        total_feedback = int(row["cumulative_fp_count"] or 0) + int(row["cumulative_tp_count"] or 0)
        fp_rate = (float(row["cumulative_fp_count"]) / total_feedback) if total_feedback else 0.0
        run_count = int(row["ingestion_run_count"] or 0)
        failed_count = int(row["ingestion_failed_count"] or 0)
        error_rate = (failed_count / run_count) if run_count else 0.0
        rows.append(
            {
                "source_id": row["id"],
                "display_name": row["display_name"],
                "source_weight": float(row["source_weight"]),
                "last_ingestion_at": row["last_ingestion_at"],
                "last_ingestion_count": int(row["last_ingestion_count"] or 0),
                "last_error": row["last_ingestion_error"],
                "avg_confidence": float(row["avg_confidence"] or 0.0),
                "ioc_count": int(row["ioc_count"] or 0),
                "cumulative_fp_rate": fp_rate,
                "ingestion_run_count": run_count,
                "ingestion_failed_count": failed_count,
                "error_rate": error_rate,
            }
        )
    return rows


async def get_ioc_ids_by_source(source_id: str, db: AsyncSession) -> list[uuid.UUID]:
    """Return distinct IOC IDs observed by a source."""
    result = await db.execute(
        select(IOCObservation.ioc_id)
        .where(IOCObservation.source_id == source_id)
        .distinct()
    )
    return [row[0] for row in result.all()]


async def get_ioc_volume_rows(
    days: int,
    source_id: str | None,
    db: AsyncSession,
) -> list[dict[str, str | int]]:
    """Return IOC observation volume grouped by day and source."""
    lookback_days = max(days, 1)
    cutoff = datetime.now(UTC) - timedelta(days=lookback_days)

    stmt = select(IOCObservation.source_id, IOCObservation.last_seen_by_source).where(
        IOCObservation.last_seen_by_source >= cutoff
    )
    if source_id:
        stmt = stmt.where(IOCObservation.source_id == source_id)

    result = await db.execute(stmt)
    grouped: dict[tuple[str, str], int] = {}
    for src, seen_at in result.all():
        seen_utc = _ensure_utc(seen_at)
        key = (seen_utc.date().isoformat(), str(src))
        grouped[key] = grouped.get(key, 0) + 1

    rows: list[dict[str, str | int]] = []
    for (date, src), count in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        rows.append(
            {
                "date": str(date),
                "source_id": str(src),
                "ioc_count": int(count),
            }
        )
    return rows


async def get_confidence_distribution_rows(db: AsyncSession) -> list[dict[str, str | int]]:
    """Return histogram counts for confidence score buckets."""
    result = await db.execute(select(IOC.confidence_score))
    scores = [float(row[0]) for row in result.all()]

    counts = [0] * 10
    for score in scores:
        clamped = min(max(score, 0.0), 1.0)
        bucket_index = min(int(clamped * 10), 9)
        counts[bucket_index] += 1

    rows: list[dict[str, str | int]] = []
    for bucket_index, count in enumerate(counts):
        lower = bucket_index / 10
        upper = lower + 0.1
        rows.append(
            {
                "bucket": f"{lower:.1f}-{upper:.1f}",
                "count": count,
            }
        )
    return rows


async def get_top_iocs(
    limit: int,
    verdict: str | None,
    db: AsyncSession,
) -> list[IOC]:
    """Return top IOCs by confidence score, optionally filtered by verdict."""
    safe_limit = max(min(limit, 100), 1)
    stmt = select(IOC)
    if verdict:
        stmt = stmt.where(IOC.verdict == verdict)
    stmt = stmt.order_by(IOC.confidence_score.desc(), IOC.last_seen.desc()).limit(safe_limit)

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_observations_with_sources(
    ioc_id: uuid.UUID,
    db: AsyncSession,
) -> list[tuple[IOCObservation, SourceConfig]]:
    """Return observation rows joined with source config for one IOC."""
    stmt = (
        select(IOCObservation, SourceConfig)
        .join(SourceConfig, SourceConfig.id == IOCObservation.source_id)
        .where(IOCObservation.ioc_id == ioc_id)
    )
    result = await db.execute(stmt)
    return [(row[0], row[1]) for row in result.all()]


async def get_feed_corroboration_rows(db: AsyncSession) -> list[dict[str, float | int | str]]:
    """Return per-feed corroboration counts and rates."""
    corroborated_case = case((IOC.observation_count > 1, 1), else_=0)
    stmt = (
        select(
            IOCObservation.source_id,
            func.count(IOCObservation.ioc_id).label("total_ioc_count"),
            func.sum(corroborated_case).label("corroborated_ioc_count"),
        )
        .join(IOC, IOC.id == IOCObservation.ioc_id)
        .group_by(IOCObservation.source_id)
    )
    result = await db.execute(stmt)

    rows: list[dict[str, float | int | str]] = []
    for source, total_count, corroborated_count in result.all():
        total = int(total_count or 0)
        corroborated = int(corroborated_count or 0)
        rate = (corroborated / total) if total else 0.0
        rows.append(
            {
                "source_id": str(source),
                "total_ioc_count": total,
                "corroborated_ioc_count": corroborated,
                "corroboration_rate": rate,
            }
        )
    return rows


async def get_ioc_type_coverage_rows(db: AsyncSession) -> list[dict[str, float | int | str]]:
    """Return per-source IOC type coverage counts and average confidence."""
    stmt = (
        select(
            IOCObservation.source_id,
            IOC.ioc_type,
            func.count(IOC.id).label("ioc_count"),
            func.avg(IOC.confidence_score).label("avg_confidence"),
        )
        .join(IOC, IOC.id == IOCObservation.ioc_id)
        .group_by(IOCObservation.source_id, IOC.ioc_type)
        .order_by(IOCObservation.source_id.asc(), IOC.ioc_type.asc())
    )
    result = await db.execute(stmt)
    rows: list[dict[str, float | int | str]] = []
    for source, ioc_type, count, avg_confidence in result.all():
        rows.append(
            {
                "source_id": str(source),
                "ioc_type": str(ioc_type),
                "ioc_count": int(count or 0),
                "avg_confidence": float(avg_confidence or 0.0),
            }
        )
    return rows
