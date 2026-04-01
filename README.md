# Threat Intel Aggregator & Correlation Engine

---

## The Problem It Solves

Security analysts drown in IOC alerts. Without automated enrichment, they manually:
- Cross-reference the same IP across multiple threat feeds
- Downgrade alerts from low-credibility sources
- Correlate suspicious indicators across different data sources

This system **automates the entire process**: aggregate, deduplicate, score, and enrich—turning raw data into actionable threat verdicts in real time.

---

## What This Project Does

A **production-grade automated threat intelligence pipeline** that:

1. **Ingests** from 4 open threat intel feeds (OTX, URLhaus, Feodo Tracker, Emerging Threats) on configurable schedules
2. **Normalizes** indicators to a unified schema (IOC value, type, source metadata)
3. **Deduplicates** by indicator value + type while preserving per-source observations
4. **Scores** each indicator using a **confidence arbitration model**:
   - Source credibility weighting (some sources are more trustworthy than others)
   - Recency decay (old indicators matter less than fresh ones)
   - Cross-source corroboration (multiple sources increase confidence)
5. **Exposes REST APIs** for SOAR playbook enrichment, admin controls, and analytics
6. **Learns from feedback**: analysts mark false positives → system auto-downgrades source weights
7. **Clusters related IOCs** from alert contexts to identify campaigns

### Core Innovation: Confidence Arbitration

When an IP appears in 6 feeds with conflicting verdicts, which one do you trust?

**Formula:**
```
confidence = clamp(Σ(source_weight × recency_decay) × corroboration_boost, 0, 1)

Where:
- source_weight ∈ [0,1] per source (tuned by historical accuracy)
- recency_decay = exp(-λ × days_since_seen) per IOC type
- corroboration_boost = log(1 + observation_count) normalized to [1.0, 1.5]
```

**Result:** Score of 0.87 with "malicious" verdict is orders of magnitude more valuable than 5 conflicting raw alerts.

---

## How It's Built

### Architecture

```
Feed Adapters (OTX, URLhaus, Feodo, Emerging)
    ↓ Async HTTP
Ingestion Pipeline (scheduled or manual)
    ↓ Normalization
Deduplicator (upsert by value+type, preserve per-source rows)
    ↓ Row lock for consistency
Scoring Engine (compute confidence from weights + decay + corroboration)
    ↓ Write history
PostgreSQL Database
    ↓ Async SQLAlchemy ORM
FastAPI REST API (enrichment, admin, stats, analytics)
    ↓ JSON responses
SOAR Playbooks & Dashboard UI
```

### Stack & Design

- **Language:** Python 3.11+ (async-first)
- **API:** FastAPI with async SQLAlchemy ORM
- **Database:** PostgreSQL + Alembic migrations
- **Scheduling:** APScheduler for periodic feed ingestion
- **Testing:** 30 unit + integration tests (pytest + respx mocks)
- **Quality:** Type-checked (MyPy), linted (Ruff), documented
- **Frontend:** Jinja2 templates + Chart.js for dashboard

### Key Features

| Capability | Purpose | How |
|---|---|---|
| **Playbook Logic** | Automate security decisions | Confidence scores + 3-tier verdicts (clean/suspicious/malicious) power branching logic |
| **API Integration** | Multi-feed source aggregation | 4 independent adapters; each handles auth, pagination, rate limits |
| **Alert Enrichment** | Instant IOC context for analysts | `/ioc/bulk` endpoint returns verdict + confidence + source list in <100ms |
| **Workflow Testing** | Ensure automation works safely | 30 tests covering ingestion, scoring, feedback, duplicate handling |
| **Process Docs** | Train analysts on automation | Scoring formula, architecture, SOP docs, feed quality reports |
| **Admin Controls** | Tune system without code redeploy | Adjust source weights + decay lambdas via admin API; recompute affected IOCs in background |
| **Feedback Loop** | Learn from analyst corrections | Mark IOC as false positive → system increments source FP counter and auto-downgrades weight |
| **Campaign Clustering** | Link related IOCs across alerts | Register IOCs from same alert as graph edge; compute connected components |

---

## What I Built

### Source Code (44 Python Files)

- **`threat_intel/feeds/`** — 4 feed adapters (base class + implementations)
- **`threat_intel/scoring/`** — Confidence formula: decay, corroboration, weights, arbitration engine
- **`threat_intel/pipeline/`** — Deduplicator, ingestor, scheduler (APScheduler)
- **`threat_intel/api/`** — IOC enrichment, stats, admin, graph clustering endpoints
- **`threat_intel/db/`** — SQLAlchemy ORM + async CRUD operations
- **`threat_intel/models/`** — Pydantic contracts + SQLAlchemy models

### Database

- **Alembic migrations** — 2 revisions: initial schema + score history + graph tables
- **Tables:** IOCs, observations, source configs, ingestion logs, feedback, score history, graph edges, alert events
- Production-ready schema with proper indexes and constraints

### Tests (30 Total)

- **Unit tests:** Scoring functions, feed adapters, deduplication logic
- **Integration tests:** End-to-end ingestion, API contracts, feedback loops, graph clustering
- **Fixtures:** Real threat feed response mocks (OTX pagination, URLhaus, Feodo)

### Dashboard & UI

- **Overview page:** IOC volume chart, confidence distribution histogram, feed scorecard, top-20 IOCs
- **IOC detail page:** Scoring breakdown (per-source contributions), feedback buttons, timeline
- **Responsive design:** Jinja2 templates + vanilla JS + Chart.js

### Documentation

- **`docs/architecture.md`** — System design, data flow, component responsibilities
- **`docs/scoring-model.md`** — Confidence formula, tuning guide, worked example
- **`docs/design-decisions.md`** — Why PostgreSQL, why async, why source weights in DB
- **`docs/adding-a-feed.md`** — Extending with new threat sources (adapter pattern)
- **`docs/feed-quality-report.md`** — Auto-generated quality analysis (highest-confidence sources, corroboration rates, FP analysis)

---

## Next Steps for Production

1. Connect to real SOAR platform (Palo Alto Cortex XSOAR, Google SecOps, Splunk)
2. Add more threat feeds (abuse.ch URLhaus variants, custom internal feeds)
3. Implement false-positive feedback from analyst actions (auto-rate-limit sources with high FP %)
4. Deploy with WAF + API key rotation
5. Add Prometheus metrics for SOC dashboard visibility
