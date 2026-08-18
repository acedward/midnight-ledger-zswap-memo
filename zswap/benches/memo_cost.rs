// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(warnings)]

//! Calibration harness for the verifier-side memo workload.
//!
//! This benchmark exists to price one thing: the work a *verifier* does because a Zswap input
//! carries a memo. That work is exactly [`midnight_zswap::memo_to_field`], which
//! `Input::<Proof, _>::well_formed` calls (through `memo_statement_element`) to produce the first
//! element of the spend statement. Everything else in `well_formed` — the transcript program, the
//! field-repr of the remaining 67 public inputs, and the pairing check itself — is independent of
//! the memo, because the statement has a fixed length whether or not a memo is present.
//!
//! What is deliberately *not* timed here, because an existing cost-model coefficient already
//! covers it: memo construction, memo serialization/deserialization (paid through the
//! transaction's serialized size, which flows into `block_usage`), and proof verification (paid
//! through `proof_verify`). The benchmark bodies therefore take an already-constructed [`Memo`]
//! and call nothing but the statement derivation.
//!
//! It follows the conventions of the repository's existing cost-model machinery
//! (`generate-cost-model`): criterion benchmark groups named after the "operation", a benchmark
//! id that is a JSON object carrying `container_type` plus the model parameters, and
//! `mean.point_estimate` as the summary statistic. `generate-cost-model/src/vm-cost-model.rs`
//! carries matching `BENCHMARK_SCHEMAS` entries, so the existing regression tool consumes this
//! output unchanged.
//!
//! ## Groups
//!
//! * `zswap_memo_statement` — the priced workload, one benchmark per memo length.
//! * `zswap_memo_aggregate` — the same workload repeated for 0, 1, 2 and the maximum number of
//!   memo-bearing inputs with mixed lengths, to test the additive-aggregation assumption.
//! * `zswap_memo_validation` — the integrated `Input::<Proof, _>::well_formed` path with real
//!   proofs and real verification, memo-bearing and memo-less, to detect verifier work this
//!   harness would otherwise omit. Off unless `MEMO_BENCH_INTEGRATED=1`, because it needs the
//!   Zswap proving/verifying material.
//! * `zswap_memo_control` — a timer floor, the absent-memo statement value, and a
//!   `transient_hash` anchor that lets the schedule be expressed as a ratio to a coefficient the
//!   shipped cost model already carries, rather than as an absolute time measured on a machine
//!   that is not the one the rest of the model was calibrated on.
//!
//! ## Environment (all required; the harness panics rather than emitting a partial run)
//!
//! * `MEMO_BENCH_PROFILE` — `shakedown` or `acceptance`. `shakedown` output is **not** acceptance
//!   data and must never be used to derive a coefficient; it exists to validate this harness and
//!   to quantify variance.
//! * `MEMO_BENCH_OUT` — directory for `manifest.json` and `completed.json`.
//! * `MEMO_BENCH_INTEGRATED` — `0` or `1`.
//! * `MEMO_BENCH_MAX_INPUTS` — optional override of the aggregate sweep's maximum.

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::rng::SplittableRng;
use coin_structure::coin::Info as CoinInfo;
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, black_box, criterion_group, criterion_main};
use midnight_zswap::keys::SecretKeys;
use midnight_zswap::local::State as ZswapLocalState;
use midnight_zswap::prove::ZswapResolver;
use midnight_zswap::{
    Input, MAX_MEMO_BYTES, Memo, Offer, Output as ZswapOutput, ZSWAP_EXPECTED_FILES, memo_to_field,
};
use rand::{Rng, SeedableRng, rngs::OsRng, rngs::StdRng};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{Proof, ProofPreimage};
use zkir_v2::LocalProvingProvider;

type DB = InMemoryDB;

// -------------------------------------------------------------------------------------------
// Workload classification
//
// These three constants are the harness's model of where the verifier's memo work comes from.
// They are mirrored from the implementation rather than imported, because two of the three are
// not public. `zswap`'s `harness_memo_work_class_constants_are_pinned` test asserts that the
// mirrored values still match the implementation, so a change to the packing width or the memo
// cap breaks the build rather than silently mislabelling every sample.
// -------------------------------------------------------------------------------------------

/// Bytes packed into one field element by `memo_to_field`; mirrors `zswap`'s private
/// `MEMO_BYTES_PER_FIELD`.
const MEMO_BYTES_PER_FIELD: usize = 31;

/// Field elements `memo_to_field` hashes on top of the packed chunks: the length prefix it pushes
/// itself, plus the commitment opening `transient_commit` prepends.
const HASH_PREFIX_FIELDS: usize = 2;

/// Sponge rate of the Poseidon instance behind `transient_hash`; mirrors `midnight-circuits`'
/// `hash::poseidon::constants::RATE`. `PoseidonChip::hash` initialises a fixed-length sponge, so
/// it performs `ceil(inputs / RATE)` permutations with no padding block.
const POSEIDON_RATE: usize = 2;

/// Field elements packed from the memo body.
fn memo_chunks(len: usize) -> usize {
    len.div_ceil(MEMO_BYTES_PER_FIELD)
}

/// Field elements absorbed by the commitment hash.
fn hash_inputs(len: usize) -> usize {
    memo_chunks(len) + HASH_PREFIX_FIELDS
}

/// Poseidon permutations performed by the commitment hash.
///
/// This is the harness's *candidate* work class. Whether the measured cost actually steps here,
/// at the 31-byte packing boundary, or nowhere at all is an output of calibration, not an
/// assumption of it — the label is recorded on every sample so the analysis can test all three.
fn poseidon_permutations(len: usize) -> usize {
    hash_inputs(len).div_ceil(POSEIDON_RATE)
}

// -------------------------------------------------------------------------------------------
// Deterministic corpus
// -------------------------------------------------------------------------------------------

/// SplitMix64. Chosen because it is short enough to re-implement exactly in the collector, which
/// independently regenerates the corpus and checks the digest this harness reports.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Seed base for the memo corpus. Ties the bytes to this harness so an unrelated fixture cannot
/// be mistaken for calibration input.
const CORPUS_SEED: u64 = 0x6D65_6D6F_5F62_656E; // "memo_ben"

/// The memo of a given length. Deterministic: the same length always yields the same bytes, on
/// every machine and every run.
fn memo_bytes(len: usize) -> Vec<u8> {
    let mut rng = SplitMix64(CORPUS_SEED ^ len as u64);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(len);
    out
}

/// FNV-1a 64. Used instead of a cryptographic digest so the collector can recompute it without
/// adding a dependency to `zswap`; it is an integrity check on the corpus, not a security claim.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Digest of the whole corpus, in ascending length order, with each memo's length mixed in.
fn corpus_digest(lengths: &[usize]) -> u64 {
    let mut sorted = lengths.to_vec();
    sorted.sort_unstable();
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for len in sorted {
        acc ^= fnv1a64(&(len as u64).to_le_bytes());
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
        acc ^= fnv1a64(&memo_bytes(len));
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
    }
    acc
}

// -------------------------------------------------------------------------------------------
// Profile
// -------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Profile {
    /// Harness validation and variance reconnaissance. Never acceptance data.
    Shakedown,
    /// The Phase 3 acceptance sweep: every valid length.
    Acceptance,
}

impl Profile {
    fn from_env() -> Profile {
        match std::env::var("MEMO_BENCH_PROFILE").as_deref() {
            Ok("shakedown") => Profile::Shakedown,
            Ok("acceptance") => Profile::Acceptance,
            other => panic!(
                "MEMO_BENCH_PROFILE must be `shakedown` or `acceptance`, got {other:?}. \
                 The harness refuses to guess: an unlabelled run cannot be told apart from \
                 acceptance data afterwards."
            ),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Profile::Shakedown => "shakedown",
            Profile::Acceptance => "acceptance",
        }
    }

    fn sample_size(self) -> usize {
        match self {
            Profile::Shakedown => 50,
            Profile::Acceptance => 100,
        }
    }

    fn warm_up(self) -> Duration {
        match self {
            Profile::Shakedown => Duration::from_millis(500),
            Profile::Acceptance => Duration::from_millis(1000),
        }
    }

    fn measurement(self) -> Duration {
        match self {
            Profile::Shakedown => Duration::from_millis(1000),
            Profile::Acceptance => Duration::from_millis(2000),
        }
    }

    /// Memo lengths to measure.
    ///
    /// Acceptance measures every valid length, so no length in the shipped schedule rests on
    /// interpolation. The shakedown set is the boundary skeleton: both sides of the first and
    /// last packing boundary, both sides of a mid-range packing boundary, both sides of the
    /// first, second and last permutation boundary, and the range ends.
    fn lengths(self) -> Vec<usize> {
        match self {
            Profile::Acceptance => (1..=MAX_MEMO_BYTES).collect(),
            Profile::Shakedown => vec![
                1, 2, 30, 31, 32, 33, 61, 62, 63, 64, 92, 93, 94, 124, 125, 186, 187, 255, 256,
                310, 311, 496, 497, 511, 512,
            ],
        }
    }

    /// Memo-bearing input counts for the aggregation check.
    fn aggregate_counts(self, max_inputs: usize) -> Vec<usize> {
        match self {
            Profile::Acceptance => vec![0, 1, 2, max_inputs],
            Profile::Shakedown => vec![0, 1, 2, 16],
        }
    }

    /// `(memo-bearing inputs, memo-less inputs, memo length)` for the integrated group.
    fn validation_cases(self) -> Vec<(usize, usize, Option<usize>)> {
        match self {
            Profile::Acceptance => vec![
                (0, 1, None),
                (1, 0, Some(1)),
                (1, 0, Some(512)),
                (0, 2, None),
                (2, 0, Some(512)),
            ],
            Profile::Shakedown => vec![(0, 1, None), (1, 0, Some(512))],
        }
    }
}

/// Upper bound on memo-bearing inputs in one transaction, used for the aggregation sweep.
///
/// A ledger-9 transaction is capped at 1 MiB (`INITIAL_LIMITS.transaction_byte_limit`) and every
/// Zswap input carries a `INPUT_PROOF_SIZE` = 4832-byte proof plus its own fields, so no valid
/// transaction reaches 256 memo-bearing inputs. Measuring 256 therefore brackets the real maximum
/// from above, which is the safe direction for an additivity check. Phase 5 replaces this with
/// the exact ledger-derived bound when it enforces the limit.
const MAX_MEMO_BEARING_INPUTS: usize = 256;

fn max_inputs() -> usize {
    match std::env::var("MEMO_BENCH_MAX_INPUTS") {
        Ok(raw) => raw
            .parse()
            .expect("MEMO_BENCH_MAX_INPUTS must be a positive integer"),
        Err(_) => MAX_MEMO_BEARING_INPUTS,
    }
}

fn integrated_enabled() -> bool {
    match std::env::var("MEMO_BENCH_INTEGRATED").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        other => panic!("MEMO_BENCH_INTEGRATED must be `0` or `1`, got {other:?}"),
    }
}

fn out_dir() -> PathBuf {
    let raw = std::env::var("MEMO_BENCH_OUT")
        .expect("MEMO_BENCH_OUT must name a directory for the run manifest");
    let path = PathBuf::from(raw);
    std::fs::create_dir_all(&path).expect("MEMO_BENCH_OUT must be creatable");
    path
}

/// The mixed-length pattern used by the aggregation group: one length per packing/permutation
/// regime, so an aggregate is never a multiple of a single class.
const MIXED_LENGTHS: [usize; 8] = [1, 31, 32, 62, 63, 93, 256, 512];

// -------------------------------------------------------------------------------------------
// Self-checks
// -------------------------------------------------------------------------------------------

/// Everything that must hold before a single sample is worth taking.
///
/// Any failure aborts the process. A calibration run that produced *some* output while one of
/// these was false would be worse than no run at all, because the output would look usable.
fn self_check(profile: Profile, lengths: &[usize]) -> serde_json::Value {
    assert_eq!(
        MAX_MEMO_BYTES, 512,
        "the harness's length domain is written against a 512-byte cap"
    );

    // Class arithmetic, checked against hand-computed anchors rather than against itself.
    assert_eq!(memo_chunks(1), 1);
    assert_eq!(memo_chunks(31), 1);
    assert_eq!(memo_chunks(32), 2);
    assert_eq!(memo_chunks(62), 2);
    assert_eq!(memo_chunks(63), 3);
    assert_eq!(memo_chunks(512), 17);
    assert_eq!(hash_inputs(1), 3);
    assert_eq!(hash_inputs(512), 19);
    assert_eq!(poseidon_permutations(1), 2);
    assert_eq!(poseidon_permutations(62), 2);
    assert_eq!(poseidon_permutations(63), 3);
    assert_eq!(poseidon_permutations(512), 10);

    // Every measured length is a valid memo, is the length it claims to be, and is reproducible.
    let mut checksum = Fr::from(0u64);
    for &len in lengths {
        assert!(
            (1..=MAX_MEMO_BYTES).contains(&len),
            "length {len} is outside the valid memo range"
        );
        let bytes = memo_bytes(len);
        assert_eq!(bytes.len(), len, "corpus generator produced the wrong length");
        assert_eq!(
            bytes,
            memo_bytes(len),
            "corpus generator is not deterministic for length {len}"
        );
        let memo = Memo::new(bytes).expect("every measured length must be a valid memo");
        // Also proves the benchmarked call really computes something for every length: a
        // dead-code-eliminated `memo_to_field` could not produce distinct nonzero values.
        let field = memo_to_field(&memo);
        assert_ne!(
            field,
            Fr::from(0u64),
            "memo commitment collided with the absent-memo sentinel at length {len}"
        );
        checksum = checksum + field;
    }

    let digest = corpus_digest(lengths);
    if let Ok(expected) = std::env::var("MEMO_BENCH_EXPECT_CORPUS") {
        let expected = expected.trim_start_matches("0x");
        assert_eq!(
            format!("{digest:016x}"),
            expected,
            "corpus digest changed; the measured bytes are not the bytes that were pinned"
        );
    }

    json!({
        "corpus_digest_fnv1a64": format!("{digest:016x}"),
        "corpus_commitment_sum": format!("{checksum:?}"),
        "lengths": lengths.len(),
        "profile": profile.name(),
    })
}

// -------------------------------------------------------------------------------------------
// Groups
// -------------------------------------------------------------------------------------------

/// Deterministic shuffle, so that thermal or load drift over a long run does not correlate with
/// memo length. The order is reproducible from the recorded seed.
const ORDER_SEED: u64 = 0x0C0F_FEE0_0000_0001;

fn shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    let mut rng = SplitMix64(seed);
    for i in (1..out.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    out
}

fn configure() -> Criterion {
    let profile = Profile::from_env();
    Criterion::default()
        .sample_size(profile.sample_size())
        .warm_up_time(profile.warm_up())
        .measurement_time(profile.measurement())
        .without_plots()
        .configure_from_args()
}

/// The priced workload: one benchmark per memo length.
pub fn memo_statement(c: &mut Criterion) {
    // Match the isolation the repository's other crypto benchmarks use, so a rayon pool sized to
    // the host cannot make the measurement depend on how busy the host is.
    let _ = rayon::ThreadPoolBuilder::new()
        .use_current_thread()
        .num_threads(1)
        .build_global();

    let profile = Profile::from_env();
    let lengths = profile.lengths();
    let checks = self_check(profile, &lengths);

    let manifest = json!({
        "harness": "zswap/benches/memo_cost.rs",
        "plan": "plans/00001-sub-02-memo-cost-calibration.md",
        "profile": profile.name(),
        "acceptance_data": profile == Profile::Acceptance,
        "criterion": {
            "sample_size": profile.sample_size(),
            "warm_up_ms": profile.warm_up().as_millis() as u64,
            "measurement_ms": profile.measurement().as_millis() as u64,
            "summary_statistic": "mean.point_estimate",
        },
        "workload_classes": {
            "memo_bytes_per_field": MEMO_BYTES_PER_FIELD,
            "hash_prefix_fields": HASH_PREFIX_FIELDS,
            "poseidon_rate": POSEIDON_RATE,
        },
        "corpus": checks,
        "order_seed": format!("{ORDER_SEED:016x}"),
        "corpus_seed": format!("{CORPUS_SEED:016x}"),
        "max_memo_bearing_inputs": max_inputs(),
        "integrated": integrated_enabled(),
        "groups": [
            "zswap_memo_control",
            "zswap_memo_statement",
            "zswap_memo_aggregate",
            "zswap_memo_validation",
        ],
        "expected_cases": {
            "zswap_memo_control": 3,
            "zswap_memo_statement": lengths.len(),
            "zswap_memo_aggregate": profile.aggregate_counts(max_inputs()).len(),
            "zswap_memo_validation": if integrated_enabled() { profile.validation_cases().len() } else { 0 },
        },
    });
    let out = out_dir();
    // Written before the first sample: a run that dies mid-way leaves a manifest and no
    // completion marker, which is exactly how the collector detects a partial run.
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest must serialise"),
    )
    .expect("manifest must be writable");
    let _ = std::fs::remove_file(out.join("completed.json"));

    // Controls first, so the timer floor is measured under the same conditions as the workload.
    let mut group = c.benchmark_group("zswap_memo_control");
    let id = json!({"container_type": "none", "control": "timer_floor", "memo_len": 0});
    group.bench_function(id.to_string(), |b| b.iter(|| black_box(0u64)));
    // The value `memo_statement_element` produces for an absent memo is the constant zero field
    // element: no packing, no hashing, no allocation. This benchmark measures that construction,
    // which is the whole of the absent-memo workload; FR-002's "exactly zero memo cost" claim is
    // pinned separately, by `zswap`'s in-crate assertion that the absent statement element *is*
    // `Fr::from(0)`, because that is a claim about the code path and not about a duration.
    let id = json!({"container_type": "none", "control": "absent_statement_value", "memo_len": 0});
    group.bench_function(id.to_string(), |b| b.iter(|| black_box(Fr::from(0u64))));
    // Anchor to a coefficient the shipped cost model already carries.
    //
    // Every other coefficient in `CostModel` was measured on the project's dedicated benchmarking
    // machine, not on whatever host runs this harness. An absolute picosecond figure measured here
    // would therefore be on a different scale from the model it joins, and would be silently too
    // cheap on a host faster than the reference one. Measuring the model's own `transient_hash`
    // benchmark alongside the memo workload gives a *ratio* on one machine, which is scale-free.
    //
    // The body must stay byte-for-byte equivalent to `transient-crypto/benches/benchmarking.rs`'s
    // `transient_hash` case, random draws included: the shipped coefficient was measured with them
    // inside the timed region, so an "improved" body here would anchor to a different quantity.
    let id = json!({"container_type": "none", "control": "transient_hash_anchor", "memo_len": 0});
    group.bench_function(id.to_string(), |b| {
        b.iter(|| {
            black_box(transient_crypto::hash::transient_hash(black_box(&[
                Fr::from(OsRng.r#gen::<u64>()),
                Fr::from(OsRng.r#gen::<u64>()),
            ])))
        })
    });
    group.finish();

    let mut group = c.benchmark_group("zswap_memo_statement");
    for len in shuffled(&lengths, ORDER_SEED) {
        let memo = Memo::new(memo_bytes(len)).expect("checked above");
        let id = json!({
            "container_type": "none",
            "memo_len": len,
            "memo_chunks": memo_chunks(len),
            "hash_inputs": hash_inputs(len),
            "poseidon_permutations": poseidon_permutations(len),
        });
        group.bench_function(id.to_string(), |b| {
            b.iter(|| black_box(memo_to_field(black_box(&memo))))
        });
    }
    group.finish();
}

/// The aggregation assumption: memo work over several memo-bearing inputs of mixed lengths.
pub fn memo_aggregate(c: &mut Criterion) {
    let profile = Profile::from_env();
    let max = max_inputs();
    let mut group = c.benchmark_group("zswap_memo_aggregate");
    for count in shuffled(&profile.aggregate_counts(max), ORDER_SEED ^ 0x11) {
        let memos: Vec<Memo> = (0..count)
            .map(|i| {
                let len = MIXED_LENGTHS[i % MIXED_LENGTHS.len()];
                Memo::new(memo_bytes(len)).expect("mixed lengths are valid memos")
            })
            .collect();
        let total_bytes: usize = memos.iter().map(|m| m.len()).sum();
        let total_permutations: usize = memos.iter().map(|m| poseidon_permutations(m.len())).sum();
        let id = json!({
            "container_type": "none",
            "memo_inputs": count,
            "total_memo_bytes": total_bytes,
            "total_poseidon_permutations": total_permutations,
            "mix": MIXED_LENGTHS.to_vec(),
        });
        group.bench_function(id.to_string(), |b| {
            b.iter(|| {
                let mut acc = Fr::from(0u64);
                for memo in black_box(&memos) {
                    acc = acc + black_box(memo_to_field(memo));
                }
                black_box(acc)
            })
        });
    }
    group.finish();
}

/// The integrated verifier path, to detect memo-attributable work this harness omits.
pub fn memo_validation(c: &mut Criterion) {
    if !integrated_enabled() {
        return;
    }
    let profile = Profile::from_env();
    let mut group = c.benchmark_group("zswap_memo_validation");
    for (memo_inputs, plain_inputs, memo_len) in
        shuffled(&profile.validation_cases(), ORDER_SEED ^ 0x22)
    {
        let inputs = proven_inputs(memo_inputs, plain_inputs, memo_len);
        let id = json!({
            "container_type": "none",
            "memo_inputs": memo_inputs,
            "plain_inputs": plain_inputs,
            "memo_len": memo_len.unwrap_or(0),
        });
        bench_validation(&mut group, id.to_string(), inputs);
    }
    group.finish();
}

fn bench_validation(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: String,
    inputs: Vec<Input<Proof, DB>>,
) {
    group.bench_function(id, |b| {
        b.iter(|| {
            for input in black_box(&inputs) {
                black_box(input.well_formed(0)).expect("benchmarked inputs must be well formed");
            }
        })
    });
}

/// Builds and proves the inputs for one integrated case.
///
/// Proving happens outside the timed region; only `well_formed` is measured.
fn proven_inputs(
    memo_inputs: usize,
    plain_inputs: usize,
    memo_len: Option<usize>,
) -> Vec<Input<Proof, DB>> {
    let mut rng = StdRng::seed_from_u64(0x5EED_0002);
    let resolver = ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            ZSWAP_EXPECTED_FILES.to_owned(),
        )
        .expect("the Zswap data provider must initialise; set MIDNIGHT_PP to a populated cache"),
    );
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime must build");

    let mut out = Vec::with_capacity(memo_inputs + plain_inputs);
    for i in 0..(memo_inputs + plain_inputs) {
        let memo = if i < memo_inputs {
            let len = memo_len.expect("a memo-bearing case must name a memo length");
            Some(Memo::new(memo_bytes(len)).expect("integrated lengths are valid memos"))
        } else {
            None
        };
        let unproven = unproven_input(&mut rng, &keys, memo);
        let provider = LocalProvingProvider {
            rng: rng.split(),
            params: &resolver,
            resolver: &resolver,
        };
        let proven = runtime
            .block_on(unproven.prove(provider))
            .expect("proving a benchmark input must succeed");
        proven
            .well_formed(0)
            .expect("a freshly proven benchmark input must verify before it is benchmarked");
        out.push(proven);
    }
    out
}

/// Builds one unproven, user-owned input through the crate's public construction path.
///
/// Each input gets its own single-coin local state, so the merkle index is always 0 and no
/// bookkeeping from a previous input can leak into the next one.
fn unproven_input(
    rng: &mut StdRng,
    keys: &SecretKeys,
    memo: Option<Memo>,
) -> Input<ProofPreimage, DB> {
    const COIN_VALUE: u128 = 5_000_000_000;
    let coin = CoinInfo::new(rng, COIN_VALUE, Default::default());
    let output = ZswapOutput::new(rng, &coin, None, &keys.coin_public_key(), None)
        .expect("an output to our own key must be constructible");
    let offer = Offer {
        inputs: storage::storage::Array::new(),
        outputs: vec![output].into(),
        transient: storage::storage::Array::new(),
        deltas: storage::storage::Array::new(),
    };
    let local = ZswapLocalState::<DB>::new()
        .watch_for(&keys.coin_public_key(), &coin)
        .apply(keys, &offer)
        .expect("applying our own output must succeed");
    let (_, qualified) = local
        .coins
        .iter()
        .next()
        .expect("the applied output must be visible to its owner");
    let (_, input) = local
        .spend_with_memo(rng, keys, &qualified, None, memo)
        .expect("a user-owned spend must be constructible");
    input
}

/// Marks the run complete. Nothing downstream accepts a run without this file.
pub fn memo_finish(_c: &mut Criterion) {
    let profile = Profile::from_env();
    let out = out_dir();
    std::fs::write(
        out.join("completed.json"),
        serde_json::to_string_pretty(&json!({
            "profile": profile.name(),
            "acceptance_data": profile == Profile::Acceptance,
            "status": "all groups completed",
        }))
        .expect("completion marker must serialise"),
    )
    .expect("completion marker must be writable");
}

criterion_group!(
    name = memo_cost;
    config = configure();
    targets = memo_statement, memo_aggregate, memo_validation, memo_finish);
criterion_main!(memo_cost);
