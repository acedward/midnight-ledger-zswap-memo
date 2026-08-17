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

//! Trust-aware reading of Zswap input memos.
//!
//! A memo is authenticated by the spend proof of the *one* input carrying it, and only once the
//! concrete transaction has passed complete real validation **and** its carrying segment has
//! applied successfully. Reading the bytes off a transaction proves nothing on its own: anyone
//! can put bytes in that field. This module exists so that the difference is carried in the type
//! rather than left to the caller to remember.
//!
//! The rule the API enforces:
//!
//! - [`Transaction::memo_records`] — for a transaction that has *not* been validated. Every
//!   record is [`MemoTrust::Unverified`].
//! - [`Transaction::memo_records_rejected`] — for a transaction complete validation has just
//!   rejected. Every record is [`MemoTrust::Invalid`].
//! - [`VerifiedTransaction::memo_records`] — well-formedness alone is not a state transition, so
//!   records remain [`MemoTrust::Unverified`].
//! - `LedgerState::validate_apply_and_inspect_memos` — validates the concrete verifier-enabled
//!   wire transaction with the complete default policy, applies it, and returns final per-segment
//!   [`MemoTrust::Authenticated`] or [`MemoTrust::Invalid`] records paired with that exact result.
//!
//! A proof-erased, unproven, proof-invalid, verifier-disabled, or application-invalid transaction
//! therefore cannot produce a record whose private trust field is authenticated, and there is no
//! setter that would let a caller relabel one. A partial application authenticates only records in
//! successful segments; records in failed segments are invalid.
//!
//! Attribution is per input. Each record names the nullifier whose proof committed to those
//! bytes, so a transaction carrying several memos yields several independent records and no memo
//! is ever promoted to "the message of" the offer, the transaction, or a person.

#[cfg(feature = "proof-verifying")]
use crate::error::MalformedTransaction;
#[cfg(feature = "proof-verifying")]
use crate::semantics::{TransactionContext, TransactionResult};
use crate::structure::{
    GUARANTEED_SEGMENT, ProofKind, Segment, SignatureKind, StandardTransaction, Transaction,
    VerifiedTransaction,
};
#[cfg(feature = "proof-verifying")]
use crate::structure::{LedgerState, ProofMarker, Signature};
#[cfg(feature = "proof-verifying")]
use crate::verify::WellFormedStrictness;
use coin_structure::coin::Nullifier;
#[cfg(feature = "proof-verifying")]
use onchain_runtime::context::BlockContext;
use serialize::Tagged;
use std::fmt::{self, Debug, Display, Formatter};
use storage::Storable;
use storage::db::DB;
#[cfg(feature = "proof-verifying")]
use transient_crypto::commitment::PureGeneratorPedersen;
use zswap::{Memo, Offer as ZswapOffer};

/// What a reader is entitled to believe about a memo's authenticity.
///
/// Deliberately not `Default` and not orderable: there is no "safe fallback" trust level to reach
/// for by accident, and ranking these would invite `>= Authenticated` style checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoTrust {
    /// Nothing has been checked, or only part of validation has run. The bytes are
    /// attacker-controlled and authenticate nobody.
    ///
    /// This is the state of a memo read from a proof-erased, unproven, or merely deserialized
    /// transaction, and it is the correct state for anything arriving over a network.
    Unverified,
    /// Complete real transaction validation and this segment's state transition succeeded, so
    /// this input's spend proof committed to exactly these bytes. They are authenticated for
    /// [`MemoInspection::nullifier`] — for that input, and for nothing wider.
    Authenticated,
    /// Validation or application rejected the containing transaction or this carrying segment.
    /// The bytes are shown for diagnosis only.
    Invalid,
}

impl Display for MemoTrust {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            MemoTrust::Unverified => write!(formatter, "unverified"),
            MemoTrust::Authenticated => write!(formatter, "authenticated"),
            MemoTrust::Invalid => write!(formatter, "invalid"),
        }
    }
}

/// One memo, the input that carries it, and what has actually been checked about it.
///
/// The `trust` field is private and there is no setter, so a record cannot be promoted after the
/// fact; the only public path to a record whose trust field is
/// [`MemoTrust::Authenticated`] is `LedgerState::validate_apply_and_inspect_memos`.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoInspection {
    nullifier: Nullifier,
    segment: Segment,
    ledger_version: String,
    memo: Memo,
    trust: MemoTrust,
}

impl MemoInspection {
    /// The nullifier of the input carrying this memo. Authentication, when present, is scoped to
    /// exactly this nullifier.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// The transaction segment the carrying input sits in.
    pub fn segment(&self) -> Segment {
        self.segment
    }

    /// The ledger transaction format this record was read from, e.g. `transaction[v13]`.
    ///
    /// Memo support is a v13 property; a reader that pins verdicts against a format needs to know
    /// which one produced them.
    pub fn ledger_version(&self) -> &str {
        &self.ledger_version
    }

    /// What has been checked. See [`MemoTrust`].
    pub fn trust(&self) -> MemoTrust {
        self.trust
    }

    /// True only for [`MemoTrust::Authenticated`].
    ///
    /// Provided so callers branch on one obvious predicate rather than matching the enum and
    /// getting the `Invalid` arm subtly wrong.
    pub fn is_authenticated(&self) -> bool {
        matches!(self.trust, MemoTrust::Authenticated)
    }

    /// The exact memo bytes, unmodified.
    ///
    /// These are opaque application data and are untrusted unless [`Self::is_authenticated`].
    /// Anything rendering them to a human should use [`Self::render_inert`] rather than
    /// interpreting them.
    pub fn bytes(&self) -> &[u8] {
        self.memo.as_bytes()
    }

    /// The memo itself.
    pub fn memo(&self) -> &Memo {
        &self.memo
    }

    /// A rendering safe to put in a log, a terminal, or a web page.
    ///
    /// The bytes are emitted as lowercase hex and never as text. Memo content is chosen by
    /// whoever built the input, so treating it as text would hand them terminal escape sequences,
    /// bidirectional overrides, NULs, markup and URLs in whatever displays this. Hex has none of
    /// those hazards and stays faithful to invalid UTF-8.
    ///
    /// The trust state and the carrying nullifier lead, so the reader cannot see bytes without
    /// seeing what they are worth and which input carried them.
    pub fn render_inert(&self) -> String {
        format!(
            "[{}] memo for nullifier {} in segment {} ({}, {} bytes): {}",
            self.trust,
            hex_lower(&self.nullifier.0.0),
            self.segment,
            self.ledger_version,
            self.memo.len(),
            hex_lower(self.memo.as_bytes()),
        )
    }
}

/// Inert by construction: `Debug` and `Display` both go through [`MemoInspection::render_inert`],
/// so there is no formatting path that leaks raw memo bytes into a message.
impl Debug for MemoInspection {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.render_inert())
    }
}

impl Display for MemoInspection {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.render_inert())
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Collects one record per memo-bearing input, in `(segment, nullifier)` order.
fn records_of_offer<P: Storable<D> + Ord, D: DB>(
    offer: &ZswapOffer<P, D>,
    segment: Segment,
    ledger_version: &str,
    trust: MemoTrust,
    out: &mut Vec<MemoInspection>,
) {
    for input in offer.inputs.iter() {
        let Some(memo) = input.memo() else {
            continue;
        };
        out.push(MemoInspection {
            nullifier: input.nullifier,
            segment,
            ledger_version: ledger_version.to_owned(),
            memo: memo.clone(),
            trust,
        });
    }
}

fn records_of_standard<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB>(
    stx: &StandardTransaction<S, P, B, D>,
    ledger_version: &str,
    trust: MemoTrust,
) -> Vec<MemoInspection> {
    let mut out = Vec::new();
    if let Some(offer) = stx.guaranteed_coins.as_deref() {
        records_of_offer(offer, GUARANTEED_SEGMENT, ledger_version, trust, &mut out);
    }
    // Sorted by segment so the record order is deterministic regardless of map iteration order:
    // callers compare these across runs and across implementations.
    let mut fallible = Vec::new();
    for entry in stx.fallible_coins.iter() {
        fallible.push((*entry.0, entry.1.clone()));
    }
    fallible.sort_by_key(|(segment, _)| *segment);
    for (segment, offer) in &fallible {
        records_of_offer(offer, *segment, ledger_version, trust, &mut out);
    }
    // Raw/unvalidated transactions need not already be normalized. Keep the public ordering
    // promise true even for hostile hand-built values, and use a stable sort so duplicate
    // nullifiers retain their wire-relative order.
    out.sort_by_key(|record| (record.segment, record.nullifier));
    out
}

fn records_of_transaction<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB>(
    tx: &Transaction<S, P, B, D>,
    trust: MemoTrust,
) -> Vec<MemoInspection>
where
    Transaction<S, P, B, D>: Tagged,
{
    let ledger_version = <Transaction<S, P, B, D> as Tagged>::tag().into_owned();
    match tx {
        Transaction::Standard(stx) => records_of_standard(stx, &ledger_version, trust),
        // Reward claims carry no Zswap offer, so there is nothing to attribute.
        Transaction::ClaimRewards(_) => Vec::new(),
    }
}

impl<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> Transaction<S, P, B, D>
where
    Transaction<S, P, B, D>: Tagged,
{
    /// Memo records for a transaction that has **not** been validated.
    ///
    /// Every record is [`MemoTrust::Unverified`]. This is the right call for anything received
    /// over a network, read from a file, or deserialized: the bytes are present, but nothing has
    /// established who authorized them. Final authenticated records are produced only by
    /// `LedgerState::validate_apply_and_inspect_memos`, which pairs concrete full validation
    /// with the exact state-transition result.
    pub fn memo_records(&self) -> Vec<MemoInspection> {
        records_of_transaction(self, MemoTrust::Unverified)
    }

    /// Memo records for a transaction complete validation has just **rejected**.
    ///
    /// Every record is [`MemoTrust::Invalid`]. Intended for diagnostics — showing an operator
    /// what a rejected transaction claimed — never as evidence of authorship.
    ///
    /// Nothing stops a caller from using this on a transaction that would in fact validate, and
    /// that is deliberate: the resulting mislabelling errs towards distrust. The direction that
    /// must never be reachable is the other one, and it is not — [`MemoTrust::Authenticated`]
    /// requires private evidence produced only by the concrete complete-real validation path.
    pub fn memo_records_rejected(&self) -> Vec<MemoInspection> {
        records_of_transaction(self, MemoTrust::Invalid)
    }
}

impl<D: DB> VerifiedTransaction<D> {
    /// Memo records for a transaction that has passed well-formedness checks but has not been
    /// paired with a successful state transition.
    ///
    /// Every record remains [`MemoTrust::Unverified`]. A proof can be valid while application
    /// rejects an already-spent nullifier, an unknown root, a duplicate commitment, or another
    /// stateful conflict. Use `LedgerState::validate_apply_and_inspect_memos` to obtain a final
    /// trust verdict tied to the exact application result.
    pub fn memo_records(&self) -> Vec<MemoInspection> {
        records_of_transaction(&self.inner, MemoTrust::Unverified)
    }
}

#[cfg(feature = "proof-verifying")]
fn records_after_application<D: DB>(
    tx: &VerifiedTransaction<D>,
    result: &TransactionResult<D>,
) -> Vec<MemoInspection> {
    let mut records = records_of_transaction(&tx.inner, MemoTrust::Unverified);
    for record in &mut records {
        record.trust = trust_after_application(record.segment, result);
    }
    records
}

#[cfg(feature = "proof-verifying")]
fn trust_after_application<D: DB>(segment: Segment, result: &TransactionResult<D>) -> MemoTrust {
    match result {
        TransactionResult::Success(_) => MemoTrust::Authenticated,
        TransactionResult::Failure(_) => MemoTrust::Invalid,
        TransactionResult::PartialSuccess(segments, _) => match segments.get(&segment) {
            Some(Ok(())) => MemoTrust::Authenticated,
            Some(Err(_)) | None => MemoTrust::Invalid,
        },
    }
}

#[cfg(feature = "proof-verifying")]
impl<D: DB> LedgerState<D> {
    /// Validates, applies and inspects one concrete wire transaction as a single trust operation.
    ///
    /// This is the only API that can produce a [`MemoInspection`] whose private trust field is
    /// [`MemoTrust::Authenticated`]. Both type and policy are fixed: real Zswap proofs, real
    /// signatures and a sealed binding are checked with [`WellFormedStrictness::default`], against
    /// this concrete ledger state. The resulting records are then derived from the exact paired
    /// application result rather than from a caller-supplied status. The verdict is relative to
    /// this supplied state and `block_context`; it does not by itself prove chain inclusion,
    /// confirmations, or finality.
    ///
    /// A full application failure yields only [`MemoTrust::Invalid`] records. On partial success,
    /// records in successful segments are authenticated and records in failed segments are
    /// invalid. A malformed or proof-invalid transaction returns `Err` before application; callers
    /// may inspect its attacker-controlled claims with [`Transaction::memo_records_rejected`].
    pub fn validate_apply_and_inspect_memos(
        &self,
        tx: &Transaction<Signature, ProofMarker, PureGeneratorPedersen, D>,
        block_context: &BlockContext,
    ) -> Result<(Self, TransactionResult<D>, Vec<MemoInspection>), MalformedTransaction<D>> {
        // Construct the full application context here. Accepting one from a caller would also
        // accept `whitelist`, whose filtering intentionally skips state updates for inputs outside
        // the selected contracts. That is useful for scoped execution, but it is not a complete
        // transaction verdict and could turn a duplicate-nullifier failure into apparent success.
        let context = TransactionContext {
            ref_state: self.clone(),
            block_context: block_context.clone(),
            whitelist: None,
        };
        let verified =
            tx.well_formed(self, WellFormedStrictness::default(), block_context.tblock)?;
        let (next_state, result) = self.apply(&verified, &context);
        let records = records_after_application(&verified, &result);
        Ok((next_state, result, records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "proof-verifying")]
    use crate::error::TransactionInvalid;
    #[cfg(feature = "proof-verifying")]
    use std::collections::BTreeMap;
    #[cfg(feature = "proof-verifying")]
    use storage::db::InMemoryDB;

    #[test]
    fn inert_rendering_hex_encodes_hostile_binary_content() {
        let hostile = vec![
            0xff, 0xfe, 0x00, b'<', b's', b'c', b'r', b'i', b'p', b't', b'>', 0x1b, b'[', b'3',
            b'1', b'm', 0xe2, 0x80, 0xae, b'h', b't', b't', b'p', b':', b'/', b'/',
        ];
        let record = MemoInspection {
            nullifier: Default::default(),
            segment: GUARANTEED_SEGMENT,
            ledger_version: "transaction[v13]".to_owned(),
            memo: Memo::new(hostile.clone()).unwrap(),
            trust: MemoTrust::Unverified,
        };

        let rendered = record.render_inert();
        assert!(rendered.is_ascii());
        assert!(rendered.starts_with("[unverified] memo for nullifier "));
        assert!(rendered.ends_with(&hex_lower(&hostile)));
        assert!(!rendered.contains('<'));
        assert!(!rendered.contains("script"));
        assert!(!rendered.contains("http://"));
        assert!(!rendered.contains('\0'));
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(format!("{record}"), rendered);
        assert_eq!(format!("{record:?}"), rendered);
    }

    #[cfg(feature = "proof-verifying")]
    #[test]
    fn partial_application_authenticates_only_successful_segments() {
        let mut segments = BTreeMap::new();
        segments.insert(GUARANTEED_SEGMENT, Ok(()));
        segments.insert(7, Err(TransactionInvalid::<InMemoryDB>::DivideByZero));
        let partial = TransactionResult::PartialSuccess(segments, Vec::new());

        assert_eq!(
            trust_after_application(GUARANTEED_SEGMENT, &partial),
            MemoTrust::Authenticated
        );
        assert_eq!(trust_after_application(7, &partial), MemoTrust::Invalid);
        assert_eq!(
            trust_after_application(8, &partial),
            MemoTrust::Invalid,
            "a missing segment verdict must fail closed"
        );

        let failed = TransactionResult::Failure(TransactionInvalid::<InMemoryDB>::DivideByZero);
        assert_eq!(
            trust_after_application(GUARANTEED_SEGMENT, &failed),
            MemoTrust::Invalid
        );
        let succeeded = TransactionResult::<InMemoryDB>::Success(Vec::new());
        assert_eq!(
            trust_after_application(7, &succeeded),
            MemoTrust::Authenticated
        );
    }
}
