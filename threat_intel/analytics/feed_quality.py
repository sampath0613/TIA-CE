"""Feed quality report generation from ingested data."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.db import crud


def _as_float(value: object) -> float:
    """Convert mixed numeric-like values to float safely."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _as_int(value: object) -> int:
    """Convert mixed numeric-like values to int safely."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return 0
    return 0


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a markdown table from headers and rows."""
    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join(["---"] * len(headers)) + " |"
    body = "\n".join(["| " + " | ".join(row) + " |" for row in rows])
    if body:
        return "\n".join([header_row, separator_row, body])
    return "\n".join([header_row, separator_row])


async def generate_feed_quality_report(db: AsyncSession) -> str:
    """Generate a markdown-formatted feed quality report string."""
    feed_health = await crud.get_feed_health_rows(db)
    corroboration_rows = await crud.get_feed_corroboration_rows(db)
    coverage_rows = await crud.get_ioc_type_coverage_rows(db)

    corroboration_by_source = {
        str(row["source_id"]): float(row["corroboration_rate"])
        for row in corroboration_rows
    }

    highest_source = "N/A"
    if feed_health:
        highest = max(feed_health, key=lambda row: _as_float(row.get("avg_confidence", 0.0)))
        highest_source = str(highest.get("display_name") or highest.get("source_id") or "N/A")

    analysis_rows: list[list[str]] = []
    for row in feed_health:
        source_id = str(row["source_id"])
        analysis_rows.append(
            [
                source_id,
                f"{_as_float(row['source_weight']):.2f}",
                f"{_as_float(row['avg_confidence']):.3f}",
                f"{_as_float(row['cumulative_fp_rate']):.3%}",
                f"{corroboration_by_source.get(source_id, 0.0):.3%}",
            ]
        )

    low_corroboration_sources = [
        str(row["source_id"])
        for row in corroboration_rows
        if _as_float(row["corroboration_rate"]) <= 0.05 and _as_int(row["total_ioc_count"]) > 0
    ]

    coverage_table_rows = [
        [
            str(row["source_id"]),
            str(row["ioc_type"]),
            str(_as_int(row["ioc_count"])),
            f"{_as_float(row['avg_confidence']):.3f}",
        ]
        for row in coverage_rows
    ]

    generated_at = datetime.now(UTC).isoformat()

    report = f"""# Feed Quality Report

Generated at: {generated_at}

## Executive Summary

- Highest average confidence contributor: **{highest_source}**
- Total feeds evaluated: **{len(feed_health)}**
- Total feed/type coverage rows: **{len(coverage_rows)}**

## Per-Feed Analysis

{_markdown_table(
    ["Feed", "Weight", "Avg IOC Confidence", "FP Rate", "Corroboration Rate"],
    analysis_rows,
)}

## Recommendations

"""

    if low_corroboration_sources:
        recommendation_lines = [
            f"- Candidate for lower weight due to weak corroboration: `{source}`"
            for source in low_corroboration_sources
        ]
        recommendations = "\n".join(
            recommendation_lines
        )
    else:
        recommendations = (
            "- No immediate down-weight recommendations based on "
            "corroboration threshold."
        )

    report += recommendations
    report += f"""

## IOC Type Coverage

{_markdown_table(
    ["Feed", "IOC Type", "IOC Count", "Avg Confidence"],
    coverage_table_rows,
)}

## Methodology Notes

- Confidence formula:
  - `confidence = clamp(sum(source_weight * recency_decay) * corroboration_boost, 0, 1)`
- Corroboration rate definition:
  - `corroboration_rate = feed_iocs_seen_by_2plus_sources / total_feed_iocs`
- FP rate definition:
  - `cumulative_fp_count / (cumulative_fp_count + cumulative_tp_count)`
- Decay lambdas are source-configured per IOC type and applied at scoring time.

> Methodology Box
>
> Corroboration is calculated per feed by counting IOC observations where the canonical IOC
> has `observation_count > 1`, then dividing by total IOC observations for that feed.
> This estimates how often a source is independently confirmed by at least one other source.
"""

    return report
