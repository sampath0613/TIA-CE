# Design Decisions

## Why PostgreSQL over SQLite

- Parallel ingestion and concurrent API writes require robust transactional concurrency.
- PostgreSQL handles row locking (`SELECT FOR UPDATE`) and write contention more safely at scale.
- Better production parity for async SQLAlchemy + `asyncpg`.
- Stronger aggregate/query capabilities for analytics and feed-quality reporting.

SQLite remains useful for fast local unit tests.

## Why Recompute Confidence on Write

- Enrichment queries must be low-latency and deterministic.
- Shifting compute to write time keeps read path fast for SOAR usage.
- Avoids stale in-memory cache concerns and keeps DB as source of truth.

Tradeoff:

- Higher write cost during ingestion and bulk recalculation, accepted for this portfolio design.

## Why Source Weights Live in DB

- Analysts can tune weights without redeploying application code.
- Feedback loop can automatically update `source_weight` and quality counters.
- Admin API enables runtime governance and transparency.

## Why APScheduler over Celery

- No separate message broker required.
- Simpler operations model for a solo portfolio project.
- Sufficient for periodic pull-based ingestion jobs.

## Why Per-Source, Per-Type Lambda Values

- Different sources have different freshness characteristics.
- Different IOC types decay at different practical rates.
- Enables nuanced arbitration instead of one global decay assumption.

## Why `/ioc/bulk` for SOAR Enrichment

- Playbooks often enrich many observables in one execution context.
- Batch endpoint reduces connector overhead and network round trips.
- Supports partial matches gracefully when some IOCs are unknown.
- Supports both `GET /ioc/bulk` (query-based) and `POST /ioc/bulk` (JSON body) for integration flexibility.

## SOAR Integration Pattern

1. Playbook collects observables from SIEM alert.
2. Connector sends `GET /ioc/bulk` (repeated query params) or `POST /ioc/bulk` (JSON body) with up to 100 values.
3. API returns verdict and confidence per resolved IOC.
4. Playbook gates automation steps based on score/verdict threshold.

This keeps decision logic deterministic and centrally governed.
