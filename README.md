# Threat Intel Aggregator & Correlation Engine

A production-grade threat intelligence pipeline that ingests from four open feeds, deduplicates and scores every indicator using a confidence arbitration model, and exposes a SOAR-compatible REST API for real-time alert enrichment. Built to solve the problem that matters in production SOCs — not the shortage of threat data, but the inability to trust it.

## The Problem It Solves

Every threat intel tutorial teaches you to fetch feeds and store IOCs. The part nobody builds is the arbitration layer: when the same IP appears across six feeds with conflicting verdicts, which one do you trust? This project answers that question mathematically. It turns a data collection problem into a data quality problem — and that framing is what actually matters to analysts drowning in indicators.

## What It Does

The pipeline runs on a configurable schedule and does five things automatically:

- Ingests from AlienVault OTX, Abuse.ch URLhaus, Feodo Tracker, and Emerging Threats via independent async feed adapters, each handling its own authentication, pagination, and rate limiting
- Normalizes all indicators to a unified schema and deduplicates by indicator value and type, preserving per-source observation records
- Scores every indicator using a confidence arbitration model that weighs source credibility, recency, and cross-source corroboration
- Exposes a REST API for SOAR playbook enrichment, returning verdict, confidence score, and full source breakdown per indicator
- Learns from analyst feedback — false positive markings automatically downgrade the contributing source's weight for future scoring

## Confidence Arbitration Model

The centrepiece of the project. When sources disagree, the formula produces a single defensible score:

```
confidence = clamp( Σ(source_weight × recency_decay) × corroboration_boost, 0, 1 )
```

source_weight   — per-source credibility score tuned by historical false positive rate
recency_decay   — exp(-λ × days_since_seen), with different λ per IOC type
                  IP addresses decay faster than file hashes
corroboration   — log(1 + observation_count) normalized to [1.0, 1.5]

Every parameter is independently tunable via the admin API without a code redeploy. A score of 0.87 with a malicious verdict from this model is more actionable than five conflicting raw alerts from individual feeds.

## API Integration

Four feed adapters built on a common base class — adding a new source means writing one adapter class with no changes to the pipeline or scoring engine. Each adapter handles its source's authentication scheme, pagination, and rate limits independently.

### REST API Surface

REST API surface for SOAR integration:

- **GET /ioc/{value}** — full enriched record: confidence score, all source observations, verdict, first and last seen timestamps
- **POST /ioc/bulk** — batch enrichment endpoint returning verdicts in under 100ms, designed for direct call from SOAR playbook enrichment steps
- **GET /stats/feed-health** — per-feed ingestion time, record count, error rate, and average IOC confidence
- **POST /ioc/{value}/verdict** — analyst feedback endpoint; marks IOC as true or false positive, triggers source weight recalibration
- **Admin API** — adjust source weights and decay parameters live; system recomputes affected IOC scores in the background

## Alert Enrichment

The /ioc/bulk endpoint is built specifically for SOAR playbook integration. A playbook enrichment step calls it with a list of IOCs extracted from an alert and receives back, for each one: a three-tier verdict (clean / suspicious / malicious), a confidence score, the contributing sources, and first and last seen dates. The analyst sees a pre-enriched picture of every indicator in the alert rather than raw feed data.

## Campaign Clustering

IOCs that co-appear in the same alert are registered as edges in an undirected graph. Connected components analysis runs over this graph to identify clusters of indicators belonging to the same threat campaign. This enables campaign-level triage — an analyst can see that three IPs in different alerts are part of the same infrastructure — rather than treating every indicator in isolation.

## Workflow Testing and Documentation

- 30 unit and integration tests covering ingestion, scoring, deduplication, feedback loops, and graph clustering; feed response mocks replicate real OTX pagination and URLhaus formats
- Type-checked with MyPy, linted with Ruff, zero violations
- Documentation in docs/: architecture, scoring model with worked example, design decisions, feed adapter extension guide, and an auto-generated feed quality report that ranks sources by confidence contribution and false positive rate

## Technology Stack

Python 3.11, FastAPI, SQLAlchemy 2.0 async, PostgreSQL, Alembic, APScheduler, httpx, Pydantic, pytest, respx, Jinja2, Chart.js