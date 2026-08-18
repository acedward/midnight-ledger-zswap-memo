# SHAKEDOWN samples — not acceptance data

Everything in this directory was produced by the `shakedown` profile. Every run
record here carries `"acceptance_data": false`, and the collector printed a
warning on each one.

**These numbers may not be used to derive a coefficient, fit a model, or set a
schedule.** They exist for two purposes only:

1. to validate that the harness measures what it claims to measure, and that its
   failure paths fail; and
2. to quantify the variance of the reference environment, so that the
   reproducibility tolerance and safety margin can be proposed against observed
   numbers instead of guesses.

Acceptance samples belong one directory up, as `zswap-memo-raw.csv` and
`zswap-memo-calibration.md`, and may only be gathered after the protocol owner
has approved the tolerance and the margin rule. See the plan.

## The runs

Shared host, 2026-08-18, load average 3.7–8.5 out of 16 cores from other work on
the machine. Each `*-run.json` records its own start conditions, environment and
self-check results.

| Run | Harness commit | Integrated group | Verdict under the proposed 3% within-class-dispersion gate |
| --- | --- | --- | --- |
| `c` | `9a0fa1b8` | yes | not screened — taken before the `transient_hash` anchor existed; retained for its integrated measurements |
| `f` | `9d871af1` | no | **rejected**, one class at 34.8% dispersion |
| `g` | `9d871af1` | no | admissible, worst class 2.61% |
| `h` | `9d871af1` | no | admissible, worst class 1.37% |

`g` and `h` are consecutive and agree on the per-class statistic to within 1.34%.
That pair is the evidence behind the proposed ±5% tolerance; `f` is the evidence
that the gate rejects what it should.

Two further runs were refused outright by the collector and produced no files:
they had inherited benchmark cases from an earlier run with a different profile.
That is what prompted `9d871af1`, which clears the criterion directory before
measuring.

## The open discrepancy in run `c`

`c` measured the integrated `Input::<Proof, _>::well_formed` path at 2.57 ms with
no memo and 3.41 ms with a 512-byte memo — a delta about five times the isolated
`memo_to_field` workload for the same length. `c` was also the most contended run
of the set. Phase 3 must decompose that delta under admissible conditions before
fitting anything; if it does not collapse, the isolated benchmark is not the
whole workload. See the plan's Questions section.
