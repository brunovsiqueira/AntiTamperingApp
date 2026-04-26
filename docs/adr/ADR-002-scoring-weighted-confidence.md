# ADR-002: Weighted Confidence Scoring

**Status:** Accepted
**Date:** 2026-04-26

## Context

No single detection check is definitive. Build properties can be spoofed, file paths can be hooked, and package lists become stale. Academic research confirms that all purely client-side checks can be individually bypassed (Merlo et al., "You Shall not Repackage!", 2021). The state-of-the-art approach is combining multiple weak signals into a strong composite verdict.

## Decision

Use a **weighted confidence scoring system** with three verdict levels:

### Scoring model

Each detector produces:
- `detected: Boolean` — whether anomalies were found
- `confidence: Float` (0.0–1.0) — how certain the detector is
- `weight: Float` (0.0–1.0) — configured importance of this detector

The engine computes:
```
overallScore = sum(weight_i * confidence_i) / sum(weight_i)
```

### Verdict thresholds

| Score Range | Status | Meaning |
|-------------|--------|---------|
| < 0.25 | SECURE | No significant anomalies |
| 0.25 – 0.59 | WARNING | Some suspicious signals |
| >= 0.60 | TAMPERED | Strong evidence of tampering |

### Evidence transparency

Every check produces an `Evidence` item with `checkName`, `description`, `rawValue`, and `suspicious` flag. This directly satisfies the challenge requirement to display "what evidence was used to reach this conclusion."

## Alternatives Considered

- **Binary detection (tampered/not):** Too brittle. A single false positive blocks legitimate users. A single bypass defeats the whole system.
- **Vote-based (majority of detectors):** Doesn't account for signal quality differences. A spoofed Build.FINGERPRINT is weaker evidence than a mismatched signing certificate.
- **ML-based scoring:** Over-engineered for the challenge scope and requires training data we don't have.

## Trade-offs

- (+) Resilient: an attacker must defeat enough detectors to stay below the threshold.
- (+) Tunable: weights and thresholds can be adjusted without code changes.
- (+) Transparent: the evidence trail explains every verdict.
- (-) Thresholds are somewhat arbitrary and would need tuning with real-world data.
- (-) Weights are hardcoded client-side (in production, these should be server-configurable).
