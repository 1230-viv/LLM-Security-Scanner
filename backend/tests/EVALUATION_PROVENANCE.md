# Expanded Evaluation Fixture Provenance

The expanded fixture is `evaluation_dataset.py` and contains 100 deterministic
cases with stable IDs. It was authored from the scanner evaluation
specification, not generated from detector outputs. Every case stores its
category, expected vulnerability label, expected verdict, severity, rationale,
and protected context where applicable.

The fixture is separate from the original 20-case benchmark in
`test_detector_benchmark.py`. The original benchmark is not edited or replaced.
The expanded fixture is intended for measurement and regression reporting, not
for detector tuning. Any future detector change must be evaluated against it
without changing labels or cases first.

This is a synthetic fixture. It contains no real model traffic and does not
establish broad real-world generalization. Its labels are specification-based
and should be reviewed by an independent evaluator before being described as
independent validation.

## Metric semantics

The expanded runner reports two separate binary views:

1. **Finding-presence metrics** compare `bool(aggregated_findings)` with
   `expected_finding`. This measures whether the detector produced the labeled
   finding, including an `INCONCLUSIVE` finding when the test explicitly
   expects insufficient evidence. It does not mean the case is a confirmed
   vulnerability.
2. **Confirmed-vulnerability metrics** are calculated only over security cases
   (instruction override, canary disclosure, system-prompt disclosure, role
   claims, and controls). They compare whether any aggregated finding has
   verdict `CONFIRMED` with `expected_vulnerable`. `SUSPECTED`,
   `NOT_REPRODUCED`, and `INCONCLUSIVE` never count as confirmed. Base64
   integrity and truncation cases are excluded from this security matrix and
   remain finding cases rather than evidence of data leakage.

Verdict counts are derived from the same case-level table as the matrices.
Each case has exactly one actual verdict: the aggregated finding verdict, or
`NOT_REPRODUCED` when no finding was emitted. Exact verdict agreement means
`actual_verdict == expected_verdict` for that case; it is not a set-membership
or "represented by any finding" rule. The runner prints every case-level row,
then derives overall counts, per-category metrics, verdict counts, and exact
agreement from those rows. No dataset labels are changed by the runner.
