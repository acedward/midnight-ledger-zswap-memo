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

"""Collects the memo calibration harness's criterion output into one reviewable CSV.

This is the validating half of the harness. It re-derives, from scratch, everything the
benchmark asserted about itself -- the memo corpus, its digest, and every workload-class label --
and refuses to emit anything at all if a single check fails. A partial CSV is worse than no CSV,
because a partial CSV looks like data.

Checks performed, all fatal:

  1. The run completed. `manifest.json` is written before the first sample and `completed.json`
     after the last, so a crashed or killed run is detectable rather than silently short.
  2. The corpus is the corpus. SplitMix64 and FNV-1a are re-implemented here and the resulting
     digest is compared with the one the harness reported.
  3. Every workload-class label is recomputed from `memo_len` alone and compared with the label
     the benchmark emitted. The two implementations are independent; agreement is the check.
  4. Every group has exactly the number of cases the manifest declared, with no duplicates and
     no strays.
  5. Every benchmark took exactly the declared number of samples.
  6. The measured work is real: the shortest and the longest memo must both cost at least
     `MIN_FLOOR_RATIO` times the timer floor, which no dead-code-eliminated call could.

Usage:
    collect-memo-samples.py <criterion-dir> <bench-out-dir> <results-dir>
"""

import csv
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

# Mirrors of the harness's constants. Deliberately re-stated rather than read from the manifest:
# reading them back would make this script agree with the harness by construction.
MEMO_BYTES_PER_FIELD = 31
HASH_PREFIX_FIELDS = 2
POSEIDON_RATE = 2
CORPUS_SEED = 0x6D656D6F5F62656E
MASK64 = (1 << 64) - 1

# How much slower than an empty timed loop the real workload must be before we believe it ran.
MIN_FLOOR_RATIO = 100.0

GROUPS = [
    "zswap_memo_control",
    "zswap_memo_statement",
    "zswap_memo_aggregate",
    "zswap_memo_validation",
]


class CheckFailed(Exception):
    """A fatal validation failure. Nothing is written when one is raised."""


def splitmix64(state):
    """Yields the SplitMix64 stream for `state`, matching the harness exactly."""
    while True:
        state = (state + 0x9E3779B97F4A7C15) & MASK64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        yield z ^ (z >> 31)


def memo_bytes(length):
    stream = splitmix64(CORPUS_SEED ^ length)
    out = bytearray()
    while len(out) < length:
        out += next(stream).to_bytes(8, "little")
    return bytes(out[:length])


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & MASK64
    return h


def corpus_digest(lengths):
    acc = 0xCBF29CE484222325
    for length in sorted(lengths):
        acc ^= fnv1a64(length.to_bytes(8, "little"))
        acc = (acc * 0x100000001B3) & MASK64
        acc ^= fnv1a64(memo_bytes(length))
        acc = (acc * 0x100000001B3) & MASK64
    return acc


def memo_chunks(length):
    return -(-length // MEMO_BYTES_PER_FIELD)


def hash_inputs(length):
    return memo_chunks(length) + HASH_PREFIX_FIELDS


def poseidon_permutations(length):
    return -(-hash_inputs(length) // POSEIDON_RATE)


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def collect_benchmarks(criterion_dir):
    """Every completed criterion benchmark under `criterion_dir`, keyed by group."""
    found = {}
    for benchmark_file in sorted(Path(criterion_dir).rglob("new/benchmark.json")):
        new_dir = benchmark_file.parent
        meta = read_json(benchmark_file)
        group = meta.get("group_id")
        if group not in GROUPS:
            continue
        for required in ("estimates.json", "sample.json"):
            if not (new_dir / required).exists():
                raise CheckFailed(
                    f"{new_dir} has a benchmark.json but no {required}: "
                    "the run was interrupted while writing this case"
                )
        params = json.loads(meta["function_id"])
        found.setdefault(group, []).append(
            {
                "params": params,
                "estimates": read_json(new_dir / "estimates.json"),
                "sample": read_json(new_dir / "sample.json"),
                "dir": str(new_dir),
            }
        )
    return found


def point(estimates, key):
    node = estimates.get(key)
    if node is None:
        return None
    return node.get("point_estimate")


def check_labels(group, params):
    """Re-derives every workload-class label from `memo_len` and compares."""
    if group != "zswap_memo_statement":
        return
    length = params["memo_len"]
    expected = {
        "memo_chunks": memo_chunks(length),
        "hash_inputs": hash_inputs(length),
        "poseidon_permutations": poseidon_permutations(length),
    }
    for key, value in expected.items():
        if params.get(key) != value:
            raise CheckFailed(
                f"work-class label mismatch at memo_len={length}: "
                f"harness said {key}={params.get(key)}, collector derived {value}"
            )


def per_iteration_times(sample):
    iters = sample["iters"]
    times = sample["times"]
    if len(iters) != len(times):
        raise CheckFailed("criterion sample has mismatched iters/times arrays")
    return [t / i for t, i in zip(times, iters) if i]


def environment_record(bench_out):
    """Everything about this machine that a reproducer needs, and nothing it cannot check."""

    def run(cmd):
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=20, check=False
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    load = ""
    try:
        load = ", ".join(f"{value:.2f}" for value in os.getloadavg())
    except OSError:
        pass
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "load_average_1_5_15": load,
        "rustc": run(["rustc", "--version"]),
        "cargo": run(["cargo", "--version"]),
        "container_hostname": platform.node(),
        "bench_out": str(bench_out),
        "env": {
            key: os.environ.get(key, "")
            for key in (
                "MEMO_BENCH_PROFILE",
                "MEMO_BENCH_INTEGRATED",
                "MEMO_BENCH_MAX_INPUTS",
                "MEMO_RUN_ID",
                "MEMO_LOAD_NOTE",
                "CARGO_BUILD_JOBS",
                "RUSTFLAGS",
            )
        },
    }


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    criterion_dir, bench_out, results_dir = (Path(a) for a in argv[1:])

    manifest_path = bench_out / "manifest.json"
    if not manifest_path.exists():
        raise CheckFailed(f"no manifest at {manifest_path}: the harness never started")
    manifest = read_json(manifest_path)
    if not (bench_out / "completed.json").exists():
        raise CheckFailed(
            "the harness wrote a manifest but no completion marker: the run was "
            "interrupted, and its samples must not be used"
        )

    profile = manifest["profile"]
    sample_size = manifest["criterion"]["sample_size"]
    expected_cases = manifest["expected_cases"]

    # (2) the corpus is the corpus.
    lengths = sorted(
        {
            case["params"]["memo_len"]
            for case in collect_benchmarks(criterion_dir).get("zswap_memo_statement", [])
        }
    )
    if not lengths:
        raise CheckFailed("no zswap_memo_statement samples found")
    digest = f"{corpus_digest(lengths):016x}"
    if digest != manifest["corpus"]["corpus_digest_fnv1a64"]:
        raise CheckFailed(
            "corpus digest mismatch: harness reported "
            f"{manifest['corpus']['corpus_digest_fnv1a64']}, collector derived {digest}. "
            "The measured bytes are not the bytes the manifest claims."
        )

    benchmarks = collect_benchmarks(criterion_dir)
    rows = []
    floor_ns = None
    anchor_ns = None
    statement_means = {}

    for group in GROUPS:
        cases = benchmarks.get(group, [])
        declared = expected_cases.get(group, 0)
        if len(cases) != declared:
            raise CheckFailed(
                f"group {group} has {len(cases)} cases but the manifest declared {declared}"
            )
        seen = set()
        for case in cases:
            params = case["params"]
            key = json.dumps(params, sort_keys=True)
            if key in seen:
                raise CheckFailed(f"duplicate case in {group}: {key}")
            seen.add(key)
            check_labels(group, params)

            sample = case["sample"]
            if len(sample["iters"]) != sample_size:
                raise CheckFailed(
                    f"{group} case {key} took {len(sample['iters'])} samples, "
                    f"the manifest declared {sample_size}"
                )
            times = per_iteration_times(sample)
            estimates = case["estimates"]
            mean = point(estimates, "mean")
            row = {
                "profile": profile,
                "group": group,
                "memo_len": params.get("memo_len", ""),
                "memo_chunks": params.get("memo_chunks", ""),
                "hash_inputs": params.get("hash_inputs", ""),
                "poseidon_permutations": params.get("poseidon_permutations", ""),
                "memo_inputs": params.get("memo_inputs", ""),
                "plain_inputs": params.get("plain_inputs", ""),
                "total_memo_bytes": params.get("total_memo_bytes", ""),
                "total_poseidon_permutations": params.get("total_poseidon_permutations", ""),
                "control": params.get("control", ""),
                "sample_count": len(sample["iters"]),
                "total_iters": sum(sample["iters"]),
                "mean_ns": mean,
                "mean_se_ns": (estimates.get("mean") or {}).get("standard_error"),
                "mean_ci_lo_ns": ((estimates.get("mean") or {}).get("confidence_interval") or {}).get("lower_bound"),
                "mean_ci_hi_ns": ((estimates.get("mean") or {}).get("confidence_interval") or {}).get("upper_bound"),
                "median_ns": point(estimates, "median"),
                "median_abs_dev_ns": point(estimates, "median_abs_dev"),
                "std_dev_ns": point(estimates, "std_dev"),
                "slope_ns": point(estimates, "slope"),
                "min_iter_ns": min(times) if times else "",
                "max_iter_ns": max(times) if times else "",
                "rel_std_dev": (
                    point(estimates, "std_dev") / mean
                    if mean and point(estimates, "std_dev") is not None
                    else ""
                ),
            }
            rows.append(row)
            if params.get("control") == "timer_floor":
                floor_ns = mean
            if params.get("control") == "transient_hash_anchor":
                anchor_ns = mean
            if group == "zswap_memo_statement":
                statement_means[params["memo_len"]] = mean

    # (6) the measured work is real.
    if floor_ns is None:
        raise CheckFailed("the timer-floor control is missing; the floor check cannot run")
    if floor_ns <= 0:
        raise CheckFailed(f"timer floor is {floor_ns} ns, which cannot be right")
    for length in (min(statement_means), max(statement_means)):
        ratio = statement_means[length] / floor_ns
        if ratio < MIN_FLOOR_RATIO:
            raise CheckFailed(
                f"memo_len={length} measured {ratio:.1f}x the timer floor, below the "
                f"{MIN_FLOOR_RATIO}x threshold: the call may have been optimised away"
            )

    # The anchor is load-bearing: without it the schedule can only be expressed in absolute time
    # measured on a host that is not the one the rest of the cost model was calibrated on.
    if anchor_ns is None:
        raise CheckFailed(
            "the transient_hash anchor control is missing; the schedule could then only be "
            "expressed in absolute time on this host, which is not the machine the rest of the "
            "cost model was measured on"
        )
    if anchor_ns / floor_ns < MIN_FLOOR_RATIO:
        raise CheckFailed(
            f"the transient_hash anchor measured {anchor_ns / floor_ns:.1f}x the timer floor, "
            f"below the {MIN_FLOOR_RATIO}x threshold"
        )

    results_dir.mkdir(parents=True, exist_ok=True)
    stem = f"zswap-memo-{profile}"
    csv_path = results_dir / f"{stem}-raw.csv"
    run_path = results_dir / f"{stem}-run.json"
    fields = list(rows[0].keys())

    tmp_csv = csv_path.with_suffix(".csv.partial")
    with open(tmp_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            sorted(rows, key=lambda r: (r["group"], r["memo_len"] or 0, r["memo_inputs"] or 0))
        )
    os.replace(tmp_csv, csv_path)

    record = {
        "manifest": manifest,
        "environment": environment_record(bench_out),
        "checks": {
            "completion_marker": True,
            "corpus_digest": digest,
            "labels_recomputed": True,
            "case_counts": {group: len(benchmarks.get(group, [])) for group in GROUPS},
            "sample_size": sample_size,
            "timer_floor_ns": floor_ns,
            "transient_hash_anchor_ns": anchor_ns,
            "floor_ratio_min_length": statement_means[min(statement_means)] / floor_ns,
            "floor_ratio_max_length": statement_means[max(statement_means)] / floor_ns,
            "anchor_ratio_min_length": statement_means[min(statement_means)] / anchor_ns,
            "anchor_ratio_max_length": statement_means[max(statement_means)] / anchor_ns,
        },
        "rows": len(rows),
        "acceptance_data": manifest.get("acceptance_data", False),
    }
    tmp_run = run_path.with_suffix(".json.partial")
    with open(tmp_run, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_run, run_path)

    print(f"wrote {csv_path} ({len(rows)} rows) and {run_path}")
    if not manifest.get("acceptance_data", False):
        print("PROFILE IS NOT ACCEPTANCE: these samples must not be used to derive a schedule.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except CheckFailed as failure:
        print(f"FATAL: {failure}", file=sys.stderr)
        print("no output written", file=sys.stderr)
        sys.exit(1)
