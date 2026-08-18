# Zswap memo-work calibration

Prices one thing: the verifier-side work a Zswap input causes by carrying a memo. That work is
`midnight_zswap::memo_to_field`, which `Input::<Proof, _>::well_formed` calls through
`memo_statement_element` to build the first element of the spend statement. The remaining 67
public inputs and the pairing check do not depend on the memo, because the statement's length is
fixed whether or not a memo is present.

The frozen protocol — environment pins, sample plan, model candidates, tolerance, safety margin,
and the rule that the schedule may not be derived from an unapproved tolerance — lives in the
plan, not here:

    plans/00001-sub-02-memo-cost-calibration.md   (in the project organizer tree)

Read the "Phase 1 record" section there before running anything. This file is the operating
manual for the machinery; the plan is the authority on what the numbers are allowed to mean.

## What is here

| File | Role |
| --- | --- |
| `../../zswap/benches/memo_cost.rs` | the benchmark: workload, corpus, work-class labels, self-checks |
| `collect-memo-samples.py` | independently re-derives the corpus and every label, then writes the raw CSV — or writes nothing |
| `Dockerfile` | runner, base pinned by digest |
| `run-memo-bench-docker.sh` | in-container entry point, `build` and `measure` stages |

The benchmark follows the conventions of the existing cost-model machinery in the parent
directory: criterion groups named after the operation, a benchmark id that is a JSON object with
`container_type` and the model parameters, and `mean.point_estimate` as the summary statistic.
`../src/vm-cost-model.rs` carries matching `BENCHMARK_SCHEMAS` entries, so the existing regression
tool reads this output unchanged.

### Why this does not run through `run-cost-model-docker.sh`

The parent script runs `cargo bench --features bench` over the whole workspace and then
`generate-cost-model`. Neither half works on this branch:

* `integration/zswap-input-memo` is the release-isolated ref. Its workspace is trimmed to `zswap`
  and `ledger`, so `generate-cost-model` is no longer a workspace member and cannot be built in
  place, and the VM and crypto benchmarks it analyses live in crates the trimmed workspace no
  longer contains.
* Neither `zswap` nor `ledger` has a `bench` feature, so `--features bench` fails outright.

Adding `generate-cost-model` back to `members` would fix the build and break the measurement: its
dependency tree overlaps `zswap`'s and `ledger`'s, so cargo's feature unification could change
what the crates under calibration are compiled with. Calibrating a build that no consumer
produces is worse than a separate entry point. So the benchmark lives inside the workspace as an
ordinary `zswap` bench target — no manifest churn beyond a dev-only `[[bench]]` stanza, no
dependency change — and only the analysis is separate. The schema entries in
`../src/vm-cost-model.rs` are still added, so a full-workspace checkout can run the regression
tool over this output without any further change.

## Running it

Two stages. `build` needs the network; `measure` never gets it, so nothing can be fetched in the
middle of a timing.

```sh
# ------------------------------------------------------------------ identities
TASK=memo-cost-$(date +%Y%m%d)
RUNNER=memo-cost-runner:$(date +%Y%m%d)
BRANCH=integration/zswap-input-memo
COMMIT=<the commit being calibrated>
HOST_REPO=<any clone containing $COMMIT>

# --------------------------------------------------------------------- runner
docker build --platform linux/arm64 -t "$RUNNER" -f generate-cost-model/memo/Dockerfile \
    generate-cost-model/memo

# ------------------------------------------------------------- frozen source
# The source volume *is* the checkout: cloning into its root is what lets the image's fixed
# entry point find the script, and what makes "the thing that was measured" a single verified
# object rather than a directory someone chose.
for v in src cargo-registry cargo-git target out results; do docker volume create "$TASK-$v"; done
docker run --rm --entrypoint bash -v "$TASK-src":/dst -v "$HOST_REPO":/repo:ro "$RUNNER" -euo pipefail -c '
    git config --global --add safe.directory "*"
    git clone --depth 1 --branch '"$BRANCH"' file:///repo /dst
    cd /dst
    test "$(git rev-parse HEAD)" = '"$COMMIT"'
    test -z "$(git status --porcelain)"'

# --------------------------------------------------------------------- stages
CARGO_ENV="-e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0
 -e CARGO_NET_GIT_FETCH_WITH_CLI=true -e MIDNIGHT_PP=/params"
MOUNTS="-v $TASK-src:/src -v $TASK-target:/target -v $TASK-cargo-registry:/cargo/registry
 -v $TASK-cargo-git:/cargo/git -v $TASK-out:/out -v $TASK-results:/results"

# build (network on)
docker run --rm $MOUNTS $CARGO_ENV -e MEMO_STAGE=build "$RUNNER"

# measure (network off)
docker run --rm --network none $MOUNTS $CARGO_ENV \
    --mount "type=bind,src=$HOME/.cache/midnight/zk-params,dst=/params,readonly" \
    -e MEMO_STAGE=measure \
    -e MEMO_BENCH_PROFILE=acceptance -e MEMO_BENCH_INTEGRATED=1 \
    -e MEMO_BENCH_OUT=/out -e MEMO_RESULTS=/results \
    -e MEMO_RUN_ID=run-1 -e MEMO_LOAD_NOTE="describe what else the host was doing" "$RUNNER"

# ------------------------------------------------------------------- teardown
docker volume rm "$TASK-src" "$TASK-cargo-registry" "$TASK-cargo-git" "$TASK-target" \
                 "$TASK-out" "$TASK-results"
docker image rm "$RUNNER"
```

Copy the CSV and run record out of `$TASK-results` before removing the volume.

`MEMO_BENCH_INTEGRATED=1` needs the Zswap proving and verifying material, which is why `measure`
bind-mounts a populated `zk-params` cache; with it mounted, the stage runs with `--network none`.
Set `MEMO_BENCH_INTEGRATED=0` to skip that group, which is the only part that needs it.

## Profiles

`MEMO_BENCH_PROFILE` is required and has no default, because an unlabelled run cannot be told
apart from acceptance data afterwards.

* `shakedown` — 25 lengths, small sample sizes. For validating the harness and measuring variance.
  **Never** an input to a coefficient, a model fit, or a schedule. The collector prints a warning
  on every shakedown run and stamps `acceptance_data: false` into the run record.
* `acceptance` — every valid length 1 through 512, plus the aggregation and integrated groups.
  Only legitimate once the protocol owner has approved the reproducibility tolerance and the
  safety-margin rule recorded in the plan.

## What fails the run

The harness aborts, and the collector writes nothing, if any of these is false. They are checks on
the measurement, not on the code under measurement, and a run that violated one would produce
output that looks usable and is not.

* `MEMO_BENCH_PROFILE`, `MEMO_BENCH_OUT` or `MEMO_BENCH_INTEGRATED` is unset or unrecognised.
* A measured length is outside `1..=512`, or the corpus generator is not reproducible.
* The corpus digest the collector re-derives disagrees with the one the harness reported.
* Any workload-class label disagrees with the collector's independent recomputation.
* A group has a different number of cases than the manifest declared, or a duplicate case.
* Any benchmark took a different number of samples than the profile declared.
* The run has no completion marker, so it was interrupted.
* The shortest or longest memo measured under 100x the timer floor, which would suggest the call
  was optimised away.
* The `transient_hash` anchor control is missing or degenerate. Without it the schedule could only
  be expressed as absolute time measured on this host, and every other coefficient in `CostModel`
  was measured on a different one.
