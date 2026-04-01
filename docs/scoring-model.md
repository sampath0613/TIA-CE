# Scoring Model

## Confidence Formula

The engine computes IOC confidence using source credibility, recency, and corroboration:

$$
\text{confidence}(i) = \text{clamp}\Bigg(
\Big[\sum_{s \in S_i} w_s \cdot e^{-\lambda_{s,t(i)} \cdot d_{s,i}}\Big]
\cdot B(|S_i|),\;0,\;1\Bigg)
$$

Where:

- $i$ is one canonical IOC.
- $S_i$ is the set of sources that reported IOC $i$.
- $w_s$ is current source weight from `source_configs.source_weight`.
- $d_{s,i}$ is days since IOC $i$ was last seen by source $s$.
- $\lambda_{s,t(i)}$ is source/type decay rate for IOC type $t(i)$.
- $B(n)$ is corroboration multiplier from observation count $n$.
- `clamp` bounds final value in $[0,1]$.

## Why This Formulation

- Exponential decay ($e^{-\lambda d}$):
  - Natural model for signal freshness decay.
  - Smoothly de-emphasizes stale observations without hard cutoffs.
- Log corroboration:
  - Additional sources should help confidence, but with diminishing returns.
  - Prevents linear over-amplification from high-source fan-in.
- Source weights in DB:
  - Allows runtime governance and analyst-driven recalibration.

## Recency Decay Defaults

Default lambdas by IOC type:

- `ip`: 0.015
- `domain`: 0.008
- `url`: 0.020
- `hash`: 0.002

Half-life is:

$$
T_{1/2} = \frac{\ln(2)}{\lambda}
$$

Computed half-lives:

- IP: $\ln(2)/0.015 \approx 46.2$ days
- Domain: $\ln(2)/0.008 \approx 86.6$ days
- URL: $\ln(2)/0.020 \approx 34.7$ days
- Hash: $\ln(2)/0.002 \approx 346.6$ days

Rationale:

- IP and URL infrastructure churns quickly.
- Domains decay slower but still rotate.
- Hash intelligence is comparatively stable over long windows.

## Corroboration Multiplier

Implemented as normalized log scale in range $[1.0, 1.5]$:

$$
B(n)=1+0.5\cdot\frac{\ln(1+n)-\ln(2)}{\ln(11)-\ln(2)}
$$

with clamping to $[1.0,1.5]$ and `MAX_SOURCES = 10`.

Properties:

- $B(1)=1.0$
- $B(10)=1.5$
- $B(n>10)=1.5$ (clamped)

## Default Source Weights

Initial defaults in `.env.example` and seeded into DB:

- `feodo_tracker`: 0.90
- `urlhaus`: 0.80
- `emerging_threats`: 0.70
- `alienvault_otx`: 0.65

Justification (initial baseline):

- Feodo and URLhaus are focused abuse feeds with high operational signal for IP/URL abuse.
- Emerging Threats and OTX remain strong but broader/heterogeneous, so they start slightly lower.
- Feedback loop adjusts these values using analyst TP/FP rates.

## Verdict Thresholds

- `clean`: score < 0.3
- `suspicious`: 0.3 <= score < 0.6
- `malicious`: score >= 0.6

Reasoning:

- Keep a broad middle band for uncertain or weakly corroborated indicators.
- Reserve malicious for stronger multi-factor evidence.

## Worked Example

IOC: `203.0.113.50` observed by 3 sources.

Assume:

- Source A (`w=0.90`), last seen 2 days ago, $\lambda=0.015$:
  - decay $\approx e^{-0.015\cdot2}=0.9704$
  - contribution $\approx 0.90\cdot0.9704=0.8734$
- Source B (`w=0.80`), last seen 5 days ago:
  - decay $\approx e^{-0.015\cdot5}=0.9277$
  - contribution $\approx 0.7422$
- Source C (`w=0.65`), last seen 1 day ago:
  - decay $\approx e^{-0.015\cdot1}=0.9851$
  - contribution $\approx 0.6403$

Base sum: $2.2559$.

For 3 observations:

$$
B(3) \approx 1.203
$$

Raw confidence: $2.2559\cdot1.203\approx2.714$.
After clamp: $1.0$ -> verdict `malicious`.

## Sensitivity Over 90 Days

Decay after 90 days for default lambdas:

- IP ($\lambda=0.015$): $e^{-1.35} \approx 0.259$
- Domain ($\lambda=0.008$): $e^{-0.72} \approx 0.487$
- URL ($\lambda=0.020$): $e^{-1.8} \approx 0.165$
- Hash ($\lambda=0.002$): $e^{-0.18} \approx 0.835$

Interpretation:

- URL and IP signals weaken rapidly over a quarter.
- Domain signals retain moderate value.
- Hash indicators preserve most recency contribution over the same horizon.
