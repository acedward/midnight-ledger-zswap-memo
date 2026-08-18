# Zswap memo-work calibration record

**Status: NOT AN ACCEPTED CALIBRATION. No schedule is derived here, and no cost
coefficient in this file may be shipped.**

Three acceptance runs were gathered on 2026-08-18 under the owner-approved Phase 3
gate. All three were **rejected** by that gate's admissibility criterion. This file
is the record of the attempt: what was measured, why each run was rejected, what
the data does and does not establish, and what decision is now required. It exists
because the protocol requires rejected runs to be recorded rather than discarded.

The authority on what these numbers are allowed to mean is the plan:

    plans/00001-sub-02-memo-cost-calibration.md   (in the project organizer tree)

## What is pinned

| What | Value |
| --- | --- |
| Commit calibrated | `fc70658df5da758e6101383acb3b4c064a933e31`, tree `37b0f15426f1512d0043245713c198c9c84a9650` |
| Branch | `integration/zswap-input-memo` |
| Harness | `zswap/benches/memo_cost.rs` SHA-256 `6d922e8cf9022f9ff9352736123161225bf7f5bcd77e204de86c735c4d0dabe9` |
| Collector | `collect-memo-samples.py` SHA-256 `a334ff7f85a609b865702389cfb5e88fb73ea14414e333d3c455ba3099c92ee2` |
| Entry point | `run-memo-bench-docker.sh` SHA-256 `1f30288e5d010c0346fc3f58688fe08f7eade95b2518b249e2957ce223a4737e` |
| `Cargo.lock` | SHA-256 `20b39e383c0bf328c89e08ba481471c04182ecfc210b2869130ce62b9b7c0172`, unchanged |
| Toolchain | `rustc 1.91.1 (ed61e7d7e 2025-11-07)`, `cargo 1.91.1` |
| Container base | `rust@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33` |
| Runner image | `memo-cost-runner:20260818accept`, ID `sha256:cb7442fb8b9a0fd4f14eed205fa1c11ca457936932d986ceae00f689dcebbfc5` |
| Host | Apple M4 Max, 16 physical cores, 48 GiB, macOS 15.7.3; 12 vCPU exposed to the container |
| Profile | `acceptance` — every length 1..512, `sample_size = 100`, warm-up 1000 ms, measurement 2000 ms |
| Corpus digest | `c26fc19990382ae9` (FNV-1a 64, re-derived independently by the collector on every run) |
| Isolation | measurement stages `--network none`; source a `--depth 1` clone verified by SHA, tree and `git status` inside the container |

The source SHA-256s above are byte-identical to those frozen in the plan's Phase 1
record, so the harness that produced these samples is the harness that was pinned
before any coefficient was seen.

## The acceptance inputs (owner-approved, not adjustable)

| Input | Value | Source |
| --- | --- | --- |
| Admissibility gate (A1) | within-class dispersion of per-length means ≤ **3%** for every class; timer-floor control within **±10%** of the accepted-run median | Q-A → A1 |
| Reproducibility (B2) | **±5%** on the per-class statistic across **three admissible runs**, and byte-identical integer schedules | Q-B → B2 |
| Safety margin (C-b) | **+25%** on the per-class base, then `ceil`; anchored to `runtime_cost_model.transient_hash`; running maximum over classes; margin never admits a failing run | Q-C → C-b |
| Fit thresholds | parametric candidate considered only if `R² ≥ 0.95` and `max |relative residual| ≤ 5%` | frozen protocol |
| Start precondition | total Docker CPU < 100%, re-verified immediately before every run | owner, 2026-08-18 |

"Within-class dispersion" is `(max − min) / min` over the per-length means inside
one Poseidon-permutation class, worst class in the run. That definition reproduces
the Phase 2 shakedown verdicts exactly (`f` 34.82%, `g` 2.61%, `h` 1.37%), so the
gate applied here is arithmetically the gate that was approved.

## The runs

All three collected cleanly: 524 rows each, every collector self-check green,
`acceptance_data: true`, completion marker present, corpus digest re-derived and
matching, all workload-class labels independently recomputed and matching.
Collection succeeding is not admissibility; the gate is a separate question.

| Run | Started (UTC) | Pre-run Docker CPU | In-container load start → end | Dispersion (gate ≤3%) | Verdict |
| --- | --- | --- | --- | --- | --- |
| `acceptance-1` | 20:16 | krun 3.9%, containers 0.86% | 5.70 → 1.90 | **26.68%** (class 10) | REJECTED |
| `acceptance-2` | 21:02 | krun 5.0%, containers 8.65% | 0.90 → 6.09 | **34.85%** (class 4) | REJECTED |
| `acceptance-3` | 22:00 | krun 11.7%, containers 9.86% | 3.44 → 14.50 | **261.96%** (class 4) | REJECTED |

Raw samples for all three, including the rejected ones, are in
`zswap-memo-raw.csv` with leading `run_id` and `admissible` columns. Per-run
environment and self-check records are in `zswap-memo-run-acceptance-{1,2,3}.json`.

## Why they were rejected

**The acceptance profile's own sampling precision is ample.** With 100 samples per
length, a per-length mean is determined to a median of **0.227%** (`acceptance-1`)
and **0.218%** (`acceptance-2`). If sampling error were the only scatter, the
dispersion statistic over 62 lengths would land near **0.9%** and clear the 3% gate
with room to spare. The gate is not unreachable by construction.

**What defeats it is contention.** The observed between-length scatter inside a
class is **2.64%** and **2.65%** in those two runs — **11.6× and 12.2× the sampling
error**. That excess is other agents' work landing in whichever 3-second window a
given length happened to occupy.

| Median over the run | `acceptance-1` | `acceptance-2` |
| --- | --- | --- |
| sampling error of one per-length mean | 0.227% | 0.218% |
| observed within-class scatter (robust, MAD→σ) | 2.642% | 2.653% |
| excess over sampling error | 11.6× | 12.2× |
| predicted dispersion if sampling error were the only scatter | 0.91% (would pass) | 0.87% (would pass) |
| actual worst-class dispersion | 26.68% | 34.85% |

**The comparison that needs no distributional assumption**: restricted to the 25
lengths the shakedown measured, `acceptance-1`'s own samples score **26.68%**,
against **2.61%** for `shakedown-g` and **1.37%** for `shakedown-h` on exactly
those lengths. The acceptance runs were an order of magnitude noisier than the runs
the ±5% tolerance was proposed against, at identical sampling.

**The mechanism is exposure time.** A shakedown sweep is ~2 minutes and can be
threaded between other agents' bursts. The acceptance sweep is ~35–40 minutes and
essentially cannot avoid overlapping them. Each length is measured exactly once, so
a burst anywhere in the run permanently inflates whichever lengths it hits, and
`(max − min)/min` reports the worst one. `acceptance-2` shows this directly: it
started quieter than `acceptance-1` (load 0.90 vs 5.70) and scored worse, because
load had risen to 6.09 by the time it finished.

A secondary effect is real but is not what sank these runs: the gate statistic is
extreme-value and grows with class size, and the acceptance profile puts 62 lengths
in a class where the shakedown put at most 8. Resampling `acceptance-1`'s class 2
gives a median `(max − min)/min` of 2.84% at n=2, 9.35% at n=8 and 16.64% at n=62.

**No gate value was changed**, and none may be. A tolerance loose enough to admit
these runs is quantified below.

## The gate is measuring the right thing

Physical coherence degrades in step with the dispersion statistic, which is the
strongest available evidence that A1 detects what it was designed to detect.

| Run | Dispersion | integrated delta ÷ isolated (512 B) | delta ÷ isolated (1 B) | two-input additivity ratio |
| --- | --- | --- | --- | --- |
| `acceptance-1` | 26.68% | **1.10** | **0.94** | **0.988** |
| `acceptance-2` | 34.85% | 0.25 | 3.28 | 6.753 |
| `acceptance-3` | 261.96% | 0.77 | 1.12 | **−0.332** |

`acceptance-3`'s two-input additivity ratio is **negative**: the transaction
carrying two 512-byte memos measured *faster* than the otherwise-identical
memo-less one. That is physically impossible. `acceptance-2` implies a 1-byte memo
costs 3.28× its own isolated workload while a 512-byte memo costs 0.25× of its.
Only `acceptance-1` produces mutually consistent, physically sensible figures.

A tolerance wide enough to admit these runs would be a tolerance that admits a
negative memo cost. That is the concrete reason the escalation is to a quieter
machine and not to a looser threshold.

## Q-D: the integrated delta — provisionally answered, not discharged

Q-D asked whether the integrated verifier path contains memo-attributable work the
isolated `memo_to_field` benchmark omits. The shakedown measured an ~841 µs delta
for a 512-byte memo against ~164–168 µs isolated — about **5×** — under load 8.5.

On `acceptance-1`, the least contended run and the only coherent one:

| Integrated `Input::<Proof, _>::well_formed` | Measured |
| --- | --- |
| 1 input, no memo | 2159.78 µs (se 3.28) |
| 1 input, 1-byte memo | 2233.53 µs (se 4.24) |
| 1 input, 512-byte memo | 2332.61 µs (se 9.64) |
| 2 inputs, no memo | 4344.62 µs |
| 2 inputs, 512-byte memos | 4656.27 µs |
| isolated `memo_to_field(1)` | 78.67 µs |
| isolated `memo_to_field(512)` | 157.76 µs |

| Estimator | Measured | Expected from isolated | Ratio |
| --- | --- | --- | --- |
| delta(512-byte vs no memo) | 172.83 µs | 157.76 µs | **1.10** |
| delta(1-byte vs no memo) | 73.75 µs | 78.67 µs | **0.94** |
| length-only, `V(512) − V(1)` | 99.08 µs | 79.09 µs | 1.25 |
| two-input, `V2(512) − V2(none)` | 311.65 µs | 315.51 µs | **0.99** |

**Provisional verdict: the delta appears to collapse.** The shakedown's 5× looks
like contention. There is no sign of a hidden fixed cost for a memo merely being
present (1-byte delta is 0.94× its isolated workload), and the two-input case
reproduces twice the single-input memo cost to within 1.2%.

**This does not discharge Q-D.** The plan requires the decomposition *under
admissible conditions*, and no run was admissible. The length-only estimator reads
1.25× expectation (99.08 µs vs 79.09 µs); with a combined standard error of
≈10.5 µs that 20 µs excess is ≈1.9σ — marginal, in the safe direction, and
precisely the estimator that would reveal omitted memo work. It must be re-checked
on every admissible run.

## Structural observations — INDICATIVE ONLY, NOT A FIT

Everything in this section comes from a **rejected** run and is recorded for the
reviewer's orientation. **No candidate is selected, no coefficient is adopted, and
no number here may be shipped.** The derivation tool enforces this: given these
three runs it exits non-zero with `INSUFFICIENT: 0 admissible run(s), 3 required.
No schedule derived.`

Class medians from `acceptance-1` form a clean staircase, one step per Poseidon
permutation:

| Class `p` | Lengths | Median |
| --- | --- | --- |
| 2 | 1–62 | 78.45 µs |
| 3 | 63–124 | 89.41 µs |
| 4 | 125–186 | 99.80 µs |
| 5 | 187–248 | 111.32 µs |
| 6 | 249–310 | 122.33 µs |
| 7 | 311–372 | 132.63 µs |
| 8 | 373–434 | 143.76 µs |
| 9 | 435–496 | 154.72 µs |
| 10 | 497–512 | 165.72 µs |

Successive steps are 10.96, 10.39, 11.52, 11.01, 10.30, 11.13, 10.96 and 11.00 µs —
consistent to about ±5%, i.e. the workload is close to linear in the permutation
count `p(L) = ceil((ceil(L/31) + 2) / 2)`, with measured-work boundaries at
63, 125, 187, 249, 311, 373, 435 and 497. This confirms the Phase 2 finding that
the boundaries fall on the **62/63 permutation family**, not on the 31-byte packing
family the spec's edge-case list names, and that candidate **C1 (byte-linear, which
the `TODO(zswap-memo)` comment in `ledger/src/structure.rs` assumes) is the wrong
shape**.

Candidate evaluation on this rejected run, for orientation only:

| Id | Shape | R² | max abs rel residual | meets fit thresholds |
| --- | --- | --- | --- | --- |
| C0 | `a` | 0.0000 | 58.63% | FAIL |
| C1 | `a + b·L` | 0.9633 | 18.51% | FAIL |
| C2 | `a + b·k(L)` | 0.9671 | 18.42% | FAIL |
| C3 | `a + b·p(L)` | 0.9774 | 16.99% | FAIL |
| C4 | per-permutation-class maximum | 0.7035 | 26.68% | n/a (nonparametric) |
| C5 | per-chunk-class maximum | 0.7690 | 26.68% | n/a (nonparametric) |
| C6 | `m(class) × transient_hash` | 0.7035 | 26.68% | n/a (nonparametric) |

**This table is itself an argument against using contaminated runs.** Every
parametric candidate fails the 5% residual threshold — not because the workload is
irregular, but because individual lengths are contaminated. Under the protocol's
selection rule that would force the nonparametric fallback C4, i.e. **the noise
would change which model shape ships**, not merely widen its error bars. The class
medians above show the underlying workload is in fact close to `a + b·p(L)`, which
on a quiet run should fit far inside the thresholds.

## The anchor

Every other coefficient in `CostModel` was measured on the project's dedicated
benchmarking host. The harness therefore measures the model's own `transient_hash`
benchmark alongside the memo workload, so the schedule can be expressed as a
scale-free ratio rather than as absolute time measured here.

| Run | `transient_hash` anchor |
| --- | --- |
| `acceptance-1` | 36 330 ns |
| `acceptance-2` | 31 229 ns |
| `acceptance-3` | 32 563 ns |

The shipped coefficient is
`INITIAL_COST_MODEL.transient_hash = CostDuration::from_picoseconds(52_808_019)`
(52.808 µs), in `onchain-vm/gen/const_declaration.rs` of the pinned dependency.
This host measures the same operation at 31–36 µs, i.e. it is roughly **1.5–1.7×
faster** than the machine the rest of the model was calibrated on. An absolute
picosecond figure measured here would therefore have shipped roughly **35–40% too
cheap** relative to every coefficient around it — more than the entire +25% margin,
in the direction that underprices. This is why rider (1) requires anchoring.

Note the anchor itself spans 31 229–36 330 ns across the three runs, a **16%**
spread. On admissible runs it is expected to be far tighter (the two consecutive
admissible shakedown runs agreed to 1.2%); the spread here is another symptom of
the same contention.

## What is blocked

Phase 3 cannot complete. Specifically, the following remain **open**:

- Q-D decomposition under admissible conditions.
- Candidate evaluation, coefficients, residual distributions and selection.
- The per-class base, the +25% margin, and the final integer schedule.
- The machine check over lengths 1..512.
- B2 reproducibility across three admissible runs.

The decision required is recorded as **Q-E** in the plan's Questions section:
escalate to a dedicated host (A2), or accept one of the alternatives set out there.
This file must be regenerated once admissible runs exist; nothing in it should be
carried forward as settled except the pinned identities at the top.

## Reproducing this

Any operator with Docker, read access to a clone containing `fc70658d`, and
`generate-cost-model/memo/README.md` can repeat the runs; no privileged access and
no shared state with the executing agent is required. The harness refuses to emit
anything that could be mistaken for acceptance data without an explicit profile.

The two analysis tools are deterministic and consume only the retained CSVs:

```sh
# admissibility, Q-D, candidates, schedule, machine check, B2 -- refuses to emit a
# schedule unless three admissible runs are supplied
generate-cost-model/memo/derive-memo-schedule.py \
    acceptance-1=<raw.csv>[,<run.json>] acceptance-2=... acceptance-3=...

# merge per-run CSVs into the retained artifact, recomputing each verdict
generate-cost-model/memo/merge-memo-runs.py <out.csv> acceptance-1=<raw.csv> ...
```
