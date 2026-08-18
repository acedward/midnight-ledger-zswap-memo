#!/bin/sh

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

# In-container entry point for the memo-work calibration harness.
#
# Two stages, deliberately separated:
#
#   build    -- resolves dependencies and compiles the benchmark. Needs network.
#   measure  -- runs the benchmark and collects the samples. Runs with `--network none`, so
#               nothing can be fetched, and so no download can land in the middle of a timing.
#
# Every failure is fatal. There is no mode in which this script produces some samples and a
# non-zero exit; either the whole run is usable or nothing is written.

set -eu

cd "${MEMO_SRC:-/src}"

: "${MEMO_STAGE:?MEMO_STAGE must be 'build' or 'measure'}"

echo "=== toolchain ==="
rustc --version
cargo --version
python3 --version

echo "=== source identity ==="
git config --global --add safe.directory '*' >/dev/null 2>&1 || true
git rev-parse HEAD || echo "(not a git checkout)"
git rev-parse 'HEAD^{tree}' || true
git status --porcelain || true

echo "=== environment ==="
env | LC_ALL=C sort | sed 's/^/env: /'

case "$MEMO_STAGE" in
  build)
    # `--locked` is the point of this stage: if the manifest change that added the bench target
    # had disturbed the lockfile, the calibration would be running against a different dependency
    # graph than the ledger the schedule is for.
    cargo fetch --locked
    cargo bench --locked -p midnight-zswap --bench memo_cost --no-run
    ;;

  measure)
    : "${MEMO_BENCH_PROFILE:?}"
    : "${MEMO_BENCH_OUT:?}"
    : "${MEMO_BENCH_INTEGRATED:?}"
    : "${MEMO_RESULTS:?}"

    # criterion accumulates: a directory from a previous run survives into this one, and a
    # previous run with a different profile leaves cases this run never measured. The collector
    # catches that -- it counts cases against the manifest and refuses the run -- but catching it
    # after twenty minutes of benchmarking is a poor trade for deleting a directory now. What is
    # collected is then exactly what this run measured, with no dependence on what ran before.
    # criterion's own run-to-run change detection is lost, and is not part of this protocol:
    # reproducibility here is measured between whole runs, not by criterion's baseline diff.
    rm -rf "${CARGO_TARGET_DIR:-target}/criterion"

    echo "=== load at start ==="
    cat /proc/loadavg || true
    nproc || true

    cargo bench --locked --offline -p midnight-zswap --bench memo_cost

    echo "=== load at end ==="
    cat /proc/loadavg || true

    python3 generate-cost-model/memo/collect-memo-samples.py \
        "${CARGO_TARGET_DIR:-target}/criterion" \
        "$MEMO_BENCH_OUT" \
        "$MEMO_RESULTS"
    ;;

  *)
    echo "MEMO_STAGE must be 'build' or 'measure', got '$MEMO_STAGE'" >&2
    exit 2
    ;;
esac
