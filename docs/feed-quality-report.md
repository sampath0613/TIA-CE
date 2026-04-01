# Feed Quality Report

Generated at: 2026-04-01T14:48:13.239060+00:00

## Executive Summary

- Highest average confidence contributor: **URLhaus**
- Total feeds evaluated: **4**
- Total feed/type coverage rows: **2**

## Per-Feed Analysis

| Feed | Weight | Avg IOC Confidence | FP Rate | Corroboration Rate |
| --- | --- | --- | --- | --- |
| alienvault_otx | 0.65 | 0.000 | 0.000% | 0.000% |
| emerging_threats | 0.70 | 0.000 | 0.000% | 0.000% |
| feodo_tracker | 0.90 | 0.000 | 0.000% | 0.000% |
| urlhaus | 0.80 | 0.797 | 0.000% | 0.000% |

## Recommendations

- Candidate for lower weight due to weak corroboration: `urlhaus`

## IOC Type Coverage

| Feed | IOC Type | IOC Count | Avg Confidence |
| --- | --- | --- | --- |
| urlhaus | ip | 1 | 0.798 |
| urlhaus | url | 1 | 0.797 |

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
