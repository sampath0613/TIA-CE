"""IOC query and feedback API routes."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud
from threat_intel.db.database import get_db_session
from threat_intel.models.db import IOC
from threat_intel.models.ioc import (
    BulkIOCRequest,
    IOCResponse,
    IOCSourceObservation,
    IOCType,
    Verdict,
    VerdictFeedback,
)
from threat_intel.scoring.corroboration import corroboration_boost
from threat_intel.scoring.decay import recency_decay
from threat_intel.scoring.engine import compute_confidence, score_to_verdict
from threat_intel.scoring.weights import auto_adjust_weight

router = APIRouter(tags=["ioc"])

_MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> IOCType:
    """Auto-detect IOC type from raw IOC value."""
    try:
        ipaddress.ip_address(value)
        return IOCType.ip
    except ValueError:
        pass

    if _MD5_PATTERN.match(value) or _SHA1_PATTERN.match(value) or _SHA256_PATTERN.match(value):
        return IOCType.hash

    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return IOCType.url

    return IOCType.domain


def _parse_raw_tags(raw_tags: str) -> list[str]:
    """Parse source raw_tags JSON payload into a normalized string list."""
    try:
        parsed = json.loads(raw_tags)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []

    return [str(tag) for tag in parsed]


async def _build_ioc_response(ioc: IOC, db: AsyncSession) -> IOCResponse:
    """Build IOCResponse from ORM entity."""
    observations_with_sources = await crud.get_observations_with_sources(ioc.id, db)
    source_ids = sorted({source.id for _, source in observations_with_sources})
    source_observations = [
        IOCSourceObservation(
            source_id=source.id,
            display_name=source.display_name,
            first_seen_by_source=observation.first_seen_by_source,
            last_seen_by_source=observation.last_seen_by_source,
            raw_tags=_parse_raw_tags(observation.raw_tags),
            confidence_raw=(
                float(observation.confidence_raw)
                if observation.confidence_raw is not None
                else None
            ),
        )
        for observation, source in observations_with_sources
    ]

    try:
        verdict = Verdict(ioc.verdict)
    except ValueError:
        verdict = score_to_verdict(float(ioc.confidence_score))

    return IOCResponse(
        ioc_value=ioc.ioc_value,
        ioc_type=IOCType(ioc.ioc_type),
        confidence_score=float(ioc.confidence_score),
        verdict=verdict,
        observation_count=int(ioc.observation_count),
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        sources=source_ids,
        source_observations=source_observations,
        false_positive_count=int(ioc.false_positive_count),
    )


def _source_lambda_for_ioc_type(ioc_type: IOCType, source_config: dict[str, float]) -> float:
    """Resolve source lambda field by IOC type."""
    if ioc_type == IOCType.ip:
        return source_config["lambda_ip"]
    if ioc_type == IOCType.domain:
        return source_config["lambda_domain"]
    if ioc_type == IOCType.hash:
        return source_config["lambda_hash"]
    return source_config["lambda_url"]


@router.post("/ioc/bulk", response_model=list[IOCResponse])
async def post_ioc_bulk(
    payload: BulkIOCRequest,
    db: AsyncSession = Depends(get_db_session),
) -> list[IOCResponse]:
    """Bulk IOC lookup endpoint for SOAR enrichment."""
    return await _lookup_iocs_bulk(payload.iocs, db)


@router.get("/ioc/bulk", response_model=list[IOCResponse])
async def get_ioc_bulk(
    iocs: list[str] | None = Query(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> list[IOCResponse]:
    """Bulk IOC lookup endpoint using repeated query parameters."""
    return await _lookup_iocs_bulk(iocs or [], db)


async def _lookup_iocs_bulk(ioc_values: list[str], db: AsyncSession) -> list[IOCResponse]:
    """Resolve a batch of IOC values to canonical IOC response rows."""
    if not ioc_values:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one IOC value is required",
        )
    if len(ioc_values) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Maximum batch size is 100 IOC values",
        )

    responses: list[IOCResponse] = []

    for ioc_value in ioc_values:
        ioc_type = detect_ioc_type(ioc_value)
        ioc = await crud.get_ioc_by_value_type(ioc_value, ioc_type.value, db)
        if ioc is None:
            continue
        responses.append(await _build_ioc_response(ioc, db))

    return responses


@router.get("/ioc/top", response_model=list[IOCResponse])
async def get_top_ioc_entries(
    limit: int = Query(default=20, ge=1, le=100),
    verdict: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db_session),
) -> list[IOCResponse]:
    """Return top-confidence IOCs with optional verdict filter."""
    validated_verdict: str | None = None
    if verdict is not None:
        allowed_values = {item.value for item in Verdict}
        if verdict not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid verdict. Allowed values: {sorted(allowed_values)}",
            )
        validated_verdict = verdict

    iocs = await crud.get_top_iocs(limit=limit, verdict=validated_verdict, db=db)
    return [await _build_ioc_response(ioc, db) for ioc in iocs]


@router.get("/ioc/breakdown/{value:path}")
async def get_ioc_breakdown(
    value: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, object]:
    """Return per-source scoring breakdown for a single IOC value."""
    ioc_type = detect_ioc_type(value)
    ioc = await crud.get_ioc_by_value_type(value, ioc_type.value, db)
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    observations = await crud.get_observations_with_sources(ioc.id, db)
    rows: list[dict[str, object]] = []
    base_weighted_sum = 0.0

    for observation, source_config in observations:
        lambda_values = {
            "lambda_ip": float(source_config.lambda_ip),
            "lambda_domain": float(source_config.lambda_domain),
            "lambda_hash": float(source_config.lambda_hash),
            "lambda_url": float(source_config.lambda_url),
        }
        lambda_value = _source_lambda_for_ioc_type(ioc_type, lambda_values)
        decay = recency_decay(
            last_seen=observation.last_seen_by_source,
            ioc_type=ioc_type,
            lambda_val=lambda_value,
        )
        weight = float(source_config.source_weight)
        contribution = weight * decay
        base_weighted_sum += contribution

        try:
            tags = json.loads(observation.raw_tags)
            parsed_tags = tags if isinstance(tags, list) else []
        except json.JSONDecodeError:
            parsed_tags = []

        rows.append(
            {
                "source_id": source_config.id,
                "display_name": source_config.display_name,
                "last_seen_by_source": observation.last_seen_by_source,
                "weight": weight,
                "lambda": lambda_value,
                "decay": decay,
                "contribution": contribution,
                "raw_tags": parsed_tags,
                "confidence_raw": observation.confidence_raw,
            }
        )

    corroboration_multiplier = corroboration_boost(len(rows))
    recomputed_score = min(max(base_weighted_sum * corroboration_multiplier, 0.0), 1.0)

    return {
        "ioc_value": ioc.ioc_value,
        "ioc_type": ioc.ioc_type,
        "observation_count": len(rows),
        "base_weighted_sum": base_weighted_sum,
        "corroboration_multiplier": corroboration_multiplier,
        "recomputed_score": recomputed_score,
        "stored_score": float(ioc.confidence_score),
        "rows": rows,
    }


@router.get("/ioc/{value:path}", response_model=IOCResponse)
async def get_ioc(
    value: str,
    db: AsyncSession = Depends(get_db_session),
) -> IOCResponse:
    """Get IOC enrichment details by value with auto-detected IOC type."""
    ioc_type = detect_ioc_type(value)
    ioc = await crud.get_ioc_by_value_type(value, ioc_type.value, db)
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return await _build_ioc_response(ioc, db)


@router.post("/ioc/{value:path}/verdict", response_model=IOCResponse)
async def post_ioc_verdict(
    value: str,
    payload: VerdictFeedback,
    db: AsyncSession = Depends(get_db_session),
) -> IOCResponse:
    """Submit analyst verdict feedback and re-calibrate source confidence."""
    ioc_type = detect_ioc_type(value)
    ioc = await crud.get_ioc_by_value_type(value, ioc_type.value, db, for_update=True)
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    await crud.create_verdict_feedback(
        ioc_id=ioc.id,
        analyst_verdict=payload.verdict,
        submitted_at=datetime.now(UTC),
        notes=payload.notes,
        db=db,
    )

    source_ids = await crud.get_source_ids_for_ioc(ioc.id, db)

    if payload.verdict == "false_positive":
        await crud.increment_ioc_false_positive_count(ioc=ioc, db=db)

    for source_id in source_ids:
        fp_delta = 1 if payload.verdict == "false_positive" else 0
        tp_delta = 1 if payload.verdict == "true_positive" else 0
        await crud.update_source_feedback_counters(
            source_id,
            false_positive_delta=fp_delta,
            true_positive_delta=tp_delta,
            db=db,
        )
        if payload.verdict == "false_positive":
            await auto_adjust_weight(source_id, db)

    updated_score = await compute_confidence(ioc.id, db)
    updated_verdict = score_to_verdict(updated_score).value
    await crud.update_ioc_confidence_and_verdict(
        ioc=ioc,
        confidence_score=updated_score,
        verdict=updated_verdict,
        db=db,
    )
    await crud.create_ioc_score_history(
        ioc_id=ioc.id,
        confidence_score=updated_score,
        verdict=updated_verdict,
        reason="analyst_feedback",
        db=db,
    )
    await db.commit()

    refreshed_ioc = await crud.get_ioc_by_id(ioc.id, db)
    if refreshed_ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    return await _build_ioc_response(refreshed_ioc, db)
