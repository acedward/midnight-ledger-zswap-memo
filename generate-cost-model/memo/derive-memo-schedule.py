#!/usr/bin/env python3
# This file is part of midnight-ledger.
# Copyright (C) Midnight Foundation
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Derives the memo verifier-work schedule from acceptance runs, and checks it.

This is the *derivation* half of the calibration. It consumes only the raw CSVs the
collector wrote, applies the protocol frozen in the plan before any coefficient was seen,
and re-derives every number in the calibration record. Nothing here is a knob: the gate
values, the margin and the rounding rule are the owner-approved acceptance inputs
(Q-A -> A1, Q-B -> B2, Q-C -> C-b), and they are stated as constants below so that a
reviewer can diff them against the plan.

    plans/00001-sub-02-memo-cost-calibration.md   (in the project organizer tree)

What it does, in the order the plan requires:

  1. Admissibility (A1). A run is usable only if its own samples prove it was quiet:
     within-class dispersion of per-length means <= 3% for every workload class, and the
     timer-floor control within +/-10% of the median across the runs that passed the
     dispersion gate. Rejected runs are reported, not dropped.
  2. Q-D. Decomposes the integrated `well_formed` delta against the isolated workload,
     *before* any model is fitted. The plan forbids fitting until this is discharged.
  3. Candidates. Evaluates the six predeclared shapes C0..C6, records coefficients,
     R^2, residual distribution, and why each rejected candidate was rejected.
  4. Schedule. Per-class statistic -> anchor ratio -> +25% margin -> ceil to an integer
     multiple of `runtime_cost_model.transient_hash` -> running maximum over classes.
  5. Checks. B2 reproducibility (+/-5% on the per-class statistic and byte-identical
     integer schedules), and a machine check of every length 1..512 proving no class is
     priced below measured-work-plus-margin in any admissible run.

Usage:
    derive-memo-schedule.py <raw.csv> ...                       # merged CSV, all runs
    derive-memo-schedule.py <run-id>=<raw.csv>[,<run.json>] ...  # explicit per-run

Starting cold from the repository, the whole record is one command:

    generate-cost-model/memo/derive-memo-schedule.py \
        generate-cost-model/results/zswap-memo-raw.csv
"""

import csv
import json
import math
import sys
from pathlib import Path

# --------------------------------------------------------------------------------------
# Acceptance inputs. Owner-approved 2026-08-18; see the plan's Questions section.
# These are NOT tunable. A reviewer should be able to diff them against the plan by eye.
# --------------------------------------------------------------------------------------

DISPERSION_GATE = 0.03          # A1: within-class dispersion of per-length means
FLOOR_TOLERANCE = 0.10          # A1: timer-floor control vs the accepted-run median
REPRO_TOLERANCE = 0.05          # B2: per-class statistic across admissible runs
SAFETY_MARGIN = 1.25            # C-b: +25% on the per-class base
MIN_R2 = 0.95                   # protocol: parametric fit threshold
MAX_REL_RESIDUAL = 0.05         # protocol: parametric fit threshold
REQUIRED_ADMISSIBLE_RUNS = 3    # B2

# Workload-class arithmetic. Restated rather than imported, exactly as the collector does.
MEMO_BYTES_PER_FIELD = 31
HASH_PREFIX_FIELDS = 2
POSEIDON_RATE = 2
MAX_MEMO_BYTES = 512


def memo_chunks(length):
    return -(-length // MEMO_BYTES_PER_FIELD)


def hash_inputs(length):
    return memo_chunks(length) + HASH_PREFIX_FIELDS


def poseidon_permutations(length):
    return -(-hash_inputs(length) // POSEIDON_RATE)


class DerivationFailed(Exception):
    """A fatal derivation failure. No schedule is emitted when one is raised."""


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def load_runs(spec):
    """Loads one or more runs from a `<run-id>=<csv>[,<json>]` spec, or a merged CSV.

    The retained artifact `results/zswap-memo-raw.csv` holds every run in one file,
    keyed by a `run_id` column, so a reviewer starting cold from the repository can
    pass that single path and get exactly the runs it contains. Per-run CSVs, as the
    collector writes them, still work.
    """
    run_id, sep, paths = spec.partition("=")
    if not sep:
        run_id, paths = None, spec
    parts = paths.split(",")
    csv_path, json_path = parts[0], (parts[1] if len(parts) > 1 else None)

    with open(csv_path, newline="", encoding="utf-8") as handle:
        header = csv.DictReader(handle).fieldnames or []
    if "run_id" not in header:
        return [Run(run_id or Path(csv_path).stem, csv_path, json_path)]

    with open(csv_path, newline="", encoding="utf-8") as handle:
        ids = sorted({row["run_id"] for row in csv.DictReader(handle)})
    if run_id:
        ids = [i for i in ids if i == run_id] or [run_id]
    return [Run(i, csv_path, json_path, merged_run_id=i) for i in ids]


class Run:
    def __init__(self, run_id, csv_path, json_path=None, merged_run_id=None):
        self.run_id = run_id
        self.csv_path = Path(csv_path)
        self.json_path = Path(json_path) if json_path else None
        self.merged_run_id = merged_run_id
        self.statement = {}      # memo_len -> mean_ns
        self.statement_rsd = {}  # memo_len -> relative std dev
        self.controls = {}       # control name -> mean_ns
        self.validation = {}     # (memo_inputs, plain_inputs, memo_len) -> row
        self.aggregate = {}      # memo_inputs -> row
        self.profile = None
        self.record = json.loads(self.json_path.read_text()) if self.json_path else None

        with open(self.csv_path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if self.merged_run_id is not None and row.get("run_id") != self.merged_run_id:
                    continue
                self.profile = row["profile"]
                group = row["group"]
                mean = float(row["mean_ns"]) if row["mean_ns"] else None
                if group == "zswap_memo_control":
                    self.controls[row["control"]] = mean
                elif group == "zswap_memo_statement":
                    length = int(row["memo_len"])
                    self.statement[length] = mean
                    self.statement_rsd[length] = (
                        float(row["rel_std_dev"]) if row["rel_std_dev"] else None
                    )
                elif group == "zswap_memo_validation":
                    key = (int(row["memo_inputs"]), int(row["plain_inputs"]), int(row["memo_len"]))
                    self.validation[key] = row
                elif group == "zswap_memo_aggregate":
                    self.aggregate[int(row["memo_inputs"])] = row

        if self.profile != "acceptance":
            raise DerivationFailed(
                f"{self.run_id}: profile is {self.profile!r}, not 'acceptance'. "
                "Shakedown samples may never be used to derive a coefficient."
            )
        missing = set(range(1, MAX_MEMO_BYTES + 1)) - set(self.statement)
        if missing:
            raise DerivationFailed(
                f"{self.run_id}: the acceptance sweep is incomplete; "
                f"{len(missing)} lengths missing (first: {sorted(missing)[:5]})"
            )
        for control in ("timer_floor", "transient_hash_anchor"):
            if not self.controls.get(control):
                raise DerivationFailed(f"{self.run_id}: control {control!r} missing or zero")

    @property
    def anchor_ns(self):
        return self.controls["transient_hash_anchor"]

    @property
    def floor_ns(self):
        return self.controls["timer_floor"]

    def classes(self):
        """poseidon-permutation class -> sorted list of lengths."""
        out = {}
        for length in sorted(self.statement):
            out.setdefault(poseidon_permutations(length), []).append(length)
        return out

    def dispersion(self):
        """A1's contention detector: (max-min)/min of per-length means, worst class."""
        worst, worst_class = 0.0, None
        per_class = {}
        for klass, lengths in self.classes().items():
            means = [self.statement[length] for length in lengths]
            if len(means) < 2:
                continue
            value = (max(means) - min(means)) / min(means)
            per_class[klass] = value
            if value > worst:
                worst, worst_class = value, klass
        return worst, worst_class, per_class

    def per_class_statistic(self):
        """The quantity the schedule is built from: max of the class's per-length means."""
        return {
            klass: max(self.statement[length] for length in lengths)
            for klass, lengths in self.classes().items()
        }

    def per_class_ratio(self):
        """The same statistic in anchor units. Scale-free; this is what ships."""
        return {k: v / self.anchor_ns for k, v in self.per_class_statistic().items()}


# --------------------------------------------------------------------------------------
# 1. Admissibility (A1)
# --------------------------------------------------------------------------------------


def screen(runs):
    """Applies A1. Returns (admissible, verdicts). Rejected runs are kept in verdicts."""
    verdicts = {}
    passed_dispersion = []
    for run in runs:
        worst, worst_class, _ = run.dispersion()
        ok = worst <= DISPERSION_GATE
        verdicts[run.run_id] = {
            "dispersion": worst,
            "dispersion_worst_class": worst_class,
            "dispersion_ok": ok,
            "floor_ns": run.floor_ns,
            "anchor_ns": run.anchor_ns,
        }
        if ok:
            passed_dispersion.append(run)

    if not passed_dispersion:
        for verdict in verdicts.values():
            verdict["floor_ok"] = None
            verdict["admissible"] = False
        return [], verdicts

    floors = sorted(run.floor_ns for run in passed_dispersion)
    n = len(floors)
    median = floors[n // 2] if n % 2 else (floors[n // 2 - 1] + floors[n // 2]) / 2

    admissible = []
    for run in runs:
        verdict = verdicts[run.run_id]
        verdict["floor_median_ns"] = median
        verdict["floor_deviation"] = (run.floor_ns - median) / median
        verdict["floor_ok"] = abs(verdict["floor_deviation"]) <= FLOOR_TOLERANCE
        verdict["admissible"] = bool(verdict["dispersion_ok"] and verdict["floor_ok"])
        if verdict["admissible"]:
            admissible.append(run)
    return admissible, verdicts


# --------------------------------------------------------------------------------------
# 2. Q-D: decompose the integrated delta before fitting anything
# --------------------------------------------------------------------------------------


def decompose_integrated(run):
    """Separates 'a memo is present' from 'a memo is long' in the integrated path."""

    def mean(key):
        row = run.validation.get(key)
        return float(row["mean_ns"]) if row else None

    def se(key):
        row = run.validation.get(key)
        return float(row["mean_se_ns"]) if row and row["mean_se_ns"] else None

    base1 = mean((0, 1, 0))
    memo1 = mean((1, 0, 1))
    memo512 = mean((1, 0, 512))
    base2 = mean((0, 2, 0))
    memo512x2 = mean((2, 0, 512))

    iso1 = run.statement[1]
    iso512 = run.statement[512]

    out = {
        "baseline_1_input_ns": base1,
        "memo_1_byte_ns": memo1,
        "memo_512_byte_ns": memo512,
        "baseline_2_input_ns": base2,
        "memo_512_two_inputs_ns": memo512x2,
        "isolated_1_ns": iso1,
        "isolated_512_ns": iso512,
        "se": {
            "baseline_1": se((0, 1, 0)),
            "memo_1": se((1, 0, 1)),
            "memo_512": se((1, 0, 512)),
            "baseline_2": se((0, 2, 0)),
            "memo_512_x2": se((2, 0, 512)),
        },
    }

    if None not in (base1, memo512):
        out["delta_512_vs_none_ns"] = memo512 - base1
    if None not in (base1, memo1):
        out["delta_1_vs_none_ns"] = memo1 - base1
    # The cleanest estimator: differencing two memo-bearing cases cancels the fixed
    # verification cost entirely, so it does not rely on the memo-less baseline at all.
    if None not in (memo1, memo512):
        out["length_only_delta_ns"] = memo512 - memo1
        out["length_only_expected_ns"] = iso512 - iso1
        expected = iso512 - iso1
        if expected:
            out["length_only_ratio"] = (memo512 - memo1) / expected
    if None not in (base2, memo512x2):
        out["two_input_delta_ns"] = memo512x2 - base2
        out["two_input_expected_ns"] = 2 * iso512
        out["two_input_ratio"] = (memo512x2 - base2) / (2 * iso512)
    if "delta_512_vs_none_ns" in out and iso512:
        out["delta_512_ratio_to_isolated"] = out["delta_512_vs_none_ns"] / iso512
    if "delta_1_vs_none_ns" in out and iso1:
        out["delta_1_ratio_to_isolated"] = out["delta_1_vs_none_ns"] / iso1
    return out


# --------------------------------------------------------------------------------------
# 3. Candidates
# --------------------------------------------------------------------------------------


def ols(xs, ys):
    """Ordinary least squares for y = a + b*x. Returns (a, b)."""
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx == 0:
        return mean_y, 0.0
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    b = sxy / sxx
    return mean_y - b * mean_x, b


def fit_quality(observed, predicted):
    n = len(observed)
    mean_y = sum(observed) / n
    ss_tot = sum((y - mean_y) ** 2 for y in observed)
    ss_res = sum((y - p) ** 2 for y, p in zip(observed, predicted))
    r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
    rel = [(p - y) / y for y, p in zip(observed, predicted)]
    return {
        "r2": r2,
        "max_abs_rel_residual": max(abs(r) for r in rel),
        "mean_rel_residual": sum(rel) / n,
        "min_rel_residual": min(rel),
        "max_rel_residual": max(rel),
        "underprediction_count": sum(1 for r in rel if r < 0),
    }


def evaluate_candidates(run):
    """Evaluates the six predeclared shapes against one run's per-length means."""
    lengths = sorted(run.statement)
    ys = [run.statement[length] for length in lengths]
    results = {}

    # --- parametric ------------------------------------------------------------------
    a0 = sum(ys) / len(ys)
    results["C0"] = {
        "shape": "a",
        "parametric": True,
        "coefficients": {"a_ns": a0},
        "predict": lambda L, a=a0: a,
    }
    for cid, shape, feature in (
        ("C1", "a + b*L", lambda L: L),
        ("C2", "a + b*k(L)", memo_chunks),
        ("C3", "a + b*p(L)", poseidon_permutations),
    ):
        a, b = ols([feature(L) for L in lengths], ys)
        results[cid] = {
            "shape": shape,
            "parametric": True,
            "coefficients": {"a_ns": a, "b_ns": b},
            "predict": (lambda L, a=a, b=b, f=feature: a + b * f(L)),
        }

    # --- nonparametric ---------------------------------------------------------------
    perm_max = {}
    chunk_max = {}
    for length in lengths:
        perm_max[poseidon_permutations(length)] = max(
            perm_max.get(poseidon_permutations(length), 0), run.statement[length]
        )
        chunk_max[memo_chunks(length)] = max(
            chunk_max.get(memo_chunks(length), 0), run.statement[length]
        )
    results["C4"] = {
        "shape": "per-permutation-class maximum",
        "parametric": False,
        "coefficients": {f"class_{k}_ns": v for k, v in sorted(perm_max.items())},
        "predict": (lambda L, m=perm_max: m[poseidon_permutations(L)]),
    }
    results["C5"] = {
        "shape": "per-chunk-class maximum",
        "parametric": False,
        "coefficients": {f"chunk_{k}_ns": v for k, v in sorted(chunk_max.items())},
        "predict": (lambda L, m=chunk_max: m[memo_chunks(L)]),
    }
    ratios = {k: v / run.anchor_ns for k, v in perm_max.items()}
    results["C6"] = {
        "shape": "m(class) * runtime_cost_model.transient_hash",
        "parametric": False,
        "coefficients": {f"class_{k}_anchor_ratio": v for k, v in sorted(ratios.items())},
        "predict": (lambda L, m=ratios, a=run.anchor_ns: m[poseidon_permutations(L)] * a),
    }

    for cid, candidate in results.items():
        predicted = [candidate["predict"](L) for L in lengths]
        candidate["fit"] = fit_quality(ys, predicted)
        # The no-underpricing property is enforced absolutely, not by the fit statistic:
        # how far below a class's worst observation does this candidate ever fall?
        worst_shortfall = 0.0
        for klass, class_lengths in run.classes().items():
            class_max = max(run.statement[L] for L in class_lengths)
            for L in class_lengths:
                shortfall = (class_max - candidate["predict"](L)) / class_max
                worst_shortfall = max(worst_shortfall, shortfall)
        candidate["worst_class_shortfall_before_margin"] = worst_shortfall
        candidate["covers_class_max_after_margin"] = all(
            candidate["predict"](L) * SAFETY_MARGIN
            >= max(run.statement[x] for x in run.classes()[poseidon_permutations(L)])
            for L in lengths
        )
        candidate["overcharge_at_512"] = (
            candidate["predict"](512) - run.statement[512]
        ) / run.statement[512]
        if candidate["parametric"]:
            candidate["meets_fit_thresholds"] = (
                candidate["fit"]["r2"] >= MIN_R2
                and candidate["fit"]["max_abs_rel_residual"] <= MAX_REL_RESIDUAL
            )
        else:
            candidate["meets_fit_thresholds"] = None
    return results


def select_candidate(candidates):
    """The protocol's selection rule, applied verbatim."""
    eligible = [
        cid
        for cid, c in candidates.items()
        if c["covers_class_max_after_margin"]
        and (c["meets_fit_thresholds"] is not False)
    ]
    if not eligible:
        return "C4", "no candidate met both conditions; the protocol falls back to C4"
    best = min(eligible, key=lambda cid: candidates[cid]["overcharge_at_512"])
    return best, (
        "meets the fit thresholds, is never below a class maximum after the margin, "
        "and overcharges least at L=512 among the candidates that do"
    )


# --------------------------------------------------------------------------------------
# 4. Schedule
# --------------------------------------------------------------------------------------


def derive_schedule(runs):
    """C-b with all three riders: anchor, +25%, ceil, then running maximum over classes.

    The shipped quantity is an INTEGER multiple of `runtime_cost_model.transient_hash`,
    which is what rider (1) means by 'a multiple of' and what the ledger already does for
    merkle rehashing (`transient_hash * log_size`). Being an exact multiple of a
    coefficient the model already carries is what makes the schedule scale-free, and it
    is also what makes B2's byte-identical requirement achievable: three runs that agree
    to a few percent land on the same integer.
    """
    classes = sorted({poseidon_permutations(L) for L in range(1, MAX_MEMO_BYTES + 1)})
    base_ratio = {}
    for klass in classes:
        base_ratio[klass] = max(run.per_class_ratio()[klass] for run in runs)

    schedule, running = {}, 0
    detail = {}
    for klass in classes:
        margined = base_ratio[klass] * SAFETY_MARGIN
        multiple = math.ceil(margined)
        monotone = max(multiple, running)
        running = monotone
        schedule[klass] = monotone
        detail[klass] = {
            "base_anchor_ratio": base_ratio[klass],
            "after_margin": margined,
            "ceil": multiple,
            "after_running_max": monotone,
            "raised_by_monotonicity": monotone > multiple,
            "effective_margin": monotone / base_ratio[klass],
        }
    return schedule, detail


def check_schedule(schedule, runs):
    """Machine check: every length 1..512, every admissible run, no underpricing."""
    failures = []
    checked = 0
    for length in range(1, MAX_MEMO_BYTES + 1):
        klass = poseidon_permutations(length)
        if klass not in schedule:
            failures.append(f"length {length} maps to class {klass}, which has no price")
            continue
        for run in runs:
            required = run.statement[length] * SAFETY_MARGIN
            priced = schedule[klass] * run.anchor_ns
            checked += 1
            if priced < required:
                failures.append(
                    f"length {length} (class {klass}) priced at {priced:.1f} ns in "
                    f"{run.run_id}, below measured {run.statement[length]:.1f} ns "
                    f"x {SAFETY_MARGIN} = {required:.1f} ns"
                )
    ordered = [schedule[k] for k in sorted(schedule)]
    if ordered != sorted(ordered):
        failures.append(f"schedule is not monotone in the class index: {ordered}")
    return failures, checked


def check_reproducibility(runs):
    """B2: +/-5% on the per-class statistic, and byte-identical integer schedules."""
    stats = {run.run_id: run.per_class_statistic() for run in runs}
    ratios = {run.run_id: run.per_class_ratio() for run in runs}
    classes = sorted(next(iter(stats.values())))

    spread_raw, spread_anchor = {}, {}
    for klass in classes:
        raw = [stats[r][klass] for r in stats]
        anc = [ratios[r][klass] for r in ratios]
        spread_raw[klass] = (max(raw) - min(raw)) / min(raw)
        spread_anchor[klass] = (max(anc) - min(anc)) / min(anc)

    per_run_schedule = {}
    for run in runs:
        sched, _ = derive_schedule([run])
        per_run_schedule[run.run_id] = sched

    schedules = list(per_run_schedule.values())
    identical = all(s == schedules[0] for s in schedules)
    worst_raw = max(spread_raw.values())
    worst_anchor = max(spread_anchor.values())
    return {
        "per_class_statistic_ns": stats,
        "per_class_anchor_ratio": ratios,
        "spread_raw": spread_raw,
        "spread_anchor": spread_anchor,
        "worst_spread_raw": worst_raw,
        "worst_spread_anchor": worst_anchor,
        "tolerance": REPRO_TOLERANCE,
        "raw_within_tolerance": worst_raw <= REPRO_TOLERANCE,
        "anchor_within_tolerance": worst_anchor <= REPRO_TOLERANCE,
        "per_run_schedule": per_run_schedule,
        "schedules_identical": identical,
    }


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    runs = []
    for spec in argv[1:]:
        runs.extend(load_runs(spec))

    admissible, verdicts = screen(runs)
    report = {
        "runs": [r.run_id for r in runs],
        "admissibility": verdicts,
        "admissible_runs": [r.run_id for r in admissible],
        "gate": {
            "dispersion_gate": DISPERSION_GATE,
            "floor_tolerance": FLOOR_TOLERANCE,
            "required_admissible_runs": REQUIRED_ADMISSIBLE_RUNS,
        },
    }

    # Q-D is discharged per run, on whatever admissible runs exist, before any fitting.
    report["qd_decomposition"] = {
        run.run_id: decompose_integrated(run) for run in (admissible or runs)
    }

    if len(admissible) < REQUIRED_ADMISSIBLE_RUNS:
        report["status"] = (
            f"INSUFFICIENT: {len(admissible)} admissible run(s), "
            f"{REQUIRED_ADMISSIBLE_RUNS} required. No schedule derived."
        )
        print(json.dumps(report, indent=2, default=str))
        return 1

    candidates = {run.run_id: evaluate_candidates(run) for run in admissible}
    # The selection rule is applied independently to every admissible run. If the runs
    # disagreed about which shape wins, the choice would be an artefact of one run's
    # noise rather than a property of the workload, and that has to be visible.
    per_run_selection = {
        run_id: select_candidate(cands) for run_id, cands in candidates.items()
    }
    chosen = {sel for sel, _ in per_run_selection.values()}
    selected, why = per_run_selection[admissible[0].run_id]
    report["candidates"] = {
        run_id: {
            cid: {k: v for k, v in c.items() if k != "predict"}
            for cid, c in cands.items()
        }
        for run_id, cands in candidates.items()
    }
    report["selected_candidate"] = {
        "id": selected,
        "why": why,
        "per_run": {rid: sel for rid, (sel, _) in per_run_selection.items()},
        "unanimous": len(chosen) == 1,
    }

    schedule, detail = derive_schedule(admissible)
    failures, checked = check_schedule(schedule, admissible)
    report["schedule"] = {str(k): v for k, v in schedule.items()}
    report["schedule_derivation"] = {str(k): v for k, v in detail.items()}
    report["machine_check"] = {
        "lengths_checked": MAX_MEMO_BYTES,
        "length_run_assertions": checked,
        "failures": failures,
        "passed": not failures,
    }
    report["reproducibility"] = check_reproducibility(admissible)

    ok = (
        not failures
        and report["reproducibility"]["raw_within_tolerance"]
        and report["reproducibility"]["schedules_identical"]
        and report["selected_candidate"]["unanimous"]
    )
    report["status"] = "PASS" if ok else "FAIL"
    print(json.dumps(report, indent=2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except DerivationFailed as failure:
        print(f"FATAL: {failure}", file=sys.stderr)
        sys.exit(1)
