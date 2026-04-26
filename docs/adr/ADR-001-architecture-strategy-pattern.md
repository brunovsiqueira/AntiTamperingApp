# ADR-001: Strategy Pattern with Pluggable Detectors

**Status:** Accepted
**Date:** 2026-04-26

## Context

We need a modular detection architecture that can grow with new threat categories without modifying existing code. The Incognia challenge explicitly requires the component to be "modular and scalable, considering future evolution for new types of detection."

## Decision

Use the **Strategy pattern** where each detector implements a `TamperDetector` interface. A `DetectionEngine` orchestrates all registered detectors and aggregates results.

### Key design choices:

- **Interface-based:** `TamperDetector` defines `detect(context): DetectionResult`. Any new detection category is added by implementing this interface.
- **Builder pattern for engine:** `DetectionEngine.Builder()` allows the consumer (app module) to choose which detectors to register. This makes the SDK flexible — an app owner can opt in/out of specific checks.
- **Separate Gradle module (`:detection`):** The detection logic lives in an Android library module, separate from the app. This enforces a clean API boundary, prevents UI concerns from leaking into detection logic, and mirrors real SDK architecture.
- **Concurrent execution:** Detectors run in parallel via `async`/`awaitAll` on `Dispatchers.Default`. They are independent by design — no detector depends on another's result.

## Alternatives Considered

- **Chain of Responsibility:** Would impose ordering and sequential execution. Detectors are independent, so parallelism is a better fit.
- **Single monolithic class:** Simpler, but violates the challenge's modularity requirement and makes testing harder.
- **Annotation-based auto-discovery:** Over-engineered for this scope. Builder is explicit and debuggable.

## Trade-offs

- (+) Adding a new detector = one new class, one `addDetector()` call. Zero changes to existing code.
- (+) Each detector is independently testable.
- (+) Concurrent execution gives better performance.
- (-) Slightly more boilerplate than a monolithic approach.
- (-) Builder requires the consumer to know which detectors exist.
