# Detector and Evaluation Audit

## Scope

Audited the detector plugins, response processing, canary verification, executor,
attack repository, aggregation, persistence path, existing regression tests, and
the original 20-case benchmark.

## Findings

1. The original benchmark is embedded in `test_detector_benchmark.py`. Several
   prompts and responses reuse the same phrases and scenarios as the detector
   rules and curated prompt suite. Its held-out status is asserted by a comment,
   but no independent authoring or freeze record is stored.
2. Response-integrity detection uses response-wide keyword presence and plaintext
   substring matching. It does not establish that the relevant decoding claim
   was complete before assigning a result when completion metadata is absent.
3. Data leakage contains a second permissive Base64 decoder. It strips punctuation
   and uses non-validating decoding, which can create detector overlap and
   attribution drift.
4. Jailbreak and prompt-injection detectors intentionally classify mode claims as
   `SUSPECTED`, but their criterion confirmation is heuristic and covers only a
   small set of observable behaviors.
5. Canary verification correctly requires protected-context presence and exact
   disclosure. Credential-shaped output without verified protected provenance is
   still treated as a suspected hallucinated secret in some paths.
6. Aggregation groups only by attack prompt and merges evidence with
   `dict.update()`. Detector disagreement and same-key evidence can therefore be
   hidden.
7. Confidence values are fixed heuristic scores, not calibrated probabilities.
   Reports must not present them as measured probabilities.
8. Raw response text is retained, but execution metadata such as expected
   plaintext and completion evidence is not persisted in the attack-response
   database record.

## Evaluation limitation

The original 20-case fixture remains unchanged for historical comparison. The
expanded fixture is separately authored and versioned, but it is a deterministic
synthetic fixture rather than a study of real model traffic. It must not be
described as independent validation until its authoring freeze and tuning split
are maintained separately from detector development.
