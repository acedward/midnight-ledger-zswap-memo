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

//! Prior transaction wire versions, and the version-preserving envelope for reading both.
//!
//! `transaction[v12]` predates zswap input memos. The mirrors here carry the exact v12-era
//! layout — every component identical to today's except the zswap offers, whose inputs lack the
//! memo field (see [`zswap::prior`]) — and convert into the current types with absent memos,
//! which is byte-for-byte how the old rules verified: the spend statement's first element was
//! the constant `0` that an absent memo still produces.
//!
//! The envelope is deliberately version-preserving: a decoded value keeps its source variant.
//! Converting to the current shape via [`VersionedTransaction::to_latest`] is for shared
//! application logic only; reserialization, rule selection, diagnostics, and fixture comparison
//! must use the variant, so a v12 transaction can never silently acquire a v13 header.
//! [`versioned_deserialize`] round-trip-checks every accepted v12 payload against its own
//! serializer before returning, so non-canonical encodings are rejected at the boundary rather
//! than surviving as unreproducible values.

use crate::structure::{
    ClaimRewardsTransaction, Intent, ProofKind, Segment, SignatureKind, StandardTransaction,
    Transaction,
};
use derive_where::derive_where;
use serialize::{
    Deserializable, Tagged, peek_tag, tag_enforcement_test, tagged_deserialize, tagged_serialize,
};
use std::io::Cursor;
use storage::Storable;
use storage::arena::ArenaKey;
use storage::arena::Sp;
use storage::db::DB;
#[cfg(test)]
use storage::db::InMemoryDB;
use storage::storable::Loader;
use storage::storage::HashMap;
use transient_crypto::commitment::PedersenRandomness;
use zswap::prior::OfferV12;

/// The pre-memo `standard-transaction[v12]` layout: intents and binding randomness unchanged,
/// zswap offers in their v12 (memo-less) form.
#[derive(Storable)]
#[storable(db = D)]
#[derive_where(Clone, Debug; S, P, B)]
#[tag = "standard-transaction[v12]"]
pub struct StandardTransactionV12<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> {
    pub network_id: String,
    pub intents: HashMap<Segment, Intent<S, P, B, D>, D>,
    pub guaranteed_coins: Option<Sp<OfferV12<P::LatestProof, D>, D>>,
    pub fallible_coins: HashMap<Segment, OfferV12<P::LatestProof, D>, D>,
    pub binding_randomness: PedersenRandomness,
}
tag_enforcement_test!(
    StandardTransactionV12<(), (), transient_crypto::commitment::Pedersen, InMemoryDB>
);

/// The pre-memo `transaction[v12]` layout. `ClaimRewards` is identical across the eras.
#[derive(Storable)]
#[storable(db = D)]
#[derive_where(Clone; S, B, P)]
#[tag = "transaction[v12]"]
#[allow(clippy::large_enum_variant)]
pub enum TransactionV12<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> {
    Standard(StandardTransactionV12<S, P, B, D>),
    ClaimRewards(ClaimRewardsTransaction<S, D>),
}
tag_enforcement_test!(TransactionV12<(), (), transient_crypto::commitment::Pedersen, InMemoryDB>);

impl<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB>
    From<&StandardTransactionV12<S, P, B, D>> for StandardTransaction<S, P, B, D>
{
    fn from(old: &StandardTransactionV12<S, P, B, D>) -> Self {
        StandardTransaction {
            network_id: old.network_id.clone(),
            intents: old.intents.clone(),
            guaranteed_coins: old
                .guaranteed_coins
                .as_ref()
                .map(|sp| Sp::new(zswap::Offer::from(&**sp))),
            fallible_coins: old
                .fallible_coins
                .iter()
                .map(|kv| (*kv.0, zswap::Offer::from(&*kv.1)))
                .collect(),
            binding_randomness: old.binding_randomness,
        }
    }
}

impl<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> From<&TransactionV12<S, P, B, D>>
    for Transaction<S, P, B, D>
{
    fn from(old: &TransactionV12<S, P, B, D>) -> Self {
        match old {
            TransactionV12::Standard(st) => Transaction::Standard(st.into()),
            TransactionV12::ClaimRewards(cr) => Transaction::ClaimRewards(cr.clone()),
        }
    }
}

/// A transaction decoded from the wire, still carrying which era's encoding it arrived in.
#[derive_where(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum VersionedTransaction<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> {
    V12(TransactionV12<S, P, B, D>),
    V13(Transaction<S, P, B, D>),
}

impl<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> VersionedTransaction<S, P, B, D> {
    /// The current-shaped value for shared validation/application logic. For a v12 source the
    /// memos are absent, reproducing the historical zero statement element exactly.
    ///
    /// This is a projection, not a replacement: keep the envelope for anything that concerns
    /// the wire — reserialization, version-specific rules, diagnostics, fixtures.
    pub fn to_latest(&self) -> Transaction<S, P, B, D> {
        match self {
            VersionedTransaction::V12(tx) => tx.into(),
            VersionedTransaction::V13(tx) => tx.clone(),
        }
    }

    /// Reserializes in the *source* encoding — v12 stays v12.
    pub fn serialize_source(&self, writer: &mut impl std::io::Write) -> std::io::Result<()>
    where
        TransactionV12<S, P, B, D>: serialize::Serializable + Tagged,
        Transaction<S, P, B, D>: serialize::Serializable + Tagged,
    {
        match self {
            VersionedTransaction::V12(tx) => tagged_serialize(tx, writer),
            VersionedTransaction::V13(tx) => tagged_serialize(tx, writer),
        }
    }

    pub fn is_v12(&self) -> bool {
        matches!(self, VersionedTransaction::V12(_))
    }
}

/// Decodes a transaction of either supported wire era, preserving which one it was.
///
/// Unknown or malformed tags fail with a structured error naming both accepted tags. An
/// accepted v12 payload is additionally round-trip-checked: its reserialization must reproduce
/// the input bytes exactly, so a non-canonical encoding is rejected at the boundary instead of
/// surviving as an unreproducible value.
pub fn versioned_deserialize<S, P, B, D>(
    bytes: &[u8],
) -> std::io::Result<VersionedTransaction<S, P, B, D>>
where
    S: SignatureKind<D>,
    P: ProofKind<D>,
    B: Storable<D>,
    D: DB,
    TransactionV12<S, P, B, D>: Deserializable + Tagged,
    Transaction<S, P, B, D>: Deserializable + Tagged,
{
    let mut cursor = Cursor::new(bytes);
    let tag = peek_tag(&mut cursor)?;
    let v12_tag = <TransactionV12<S, P, B, D> as Tagged>::tag();
    let v13_tag = <Transaction<S, P, B, D> as Tagged>::tag();
    if tag == v13_tag {
        Ok(VersionedTransaction::V13(tagged_deserialize(bytes)?))
    } else if tag == v12_tag {
        let tx: TransactionV12<S, P, B, D> = tagged_deserialize(bytes)?;
        let mut reserialized = Vec::with_capacity(bytes.len());
        tagged_serialize(&tx, &mut reserialized)?;
        if reserialized != bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "v12 transaction did not reserialize byte-identically; \
                 rejecting non-canonical encoding",
            ));
        }
        Ok(VersionedTransaction::V12(tx))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unsupported transaction wire version: got tag '{tag}', \
                 accepted: '{v12_tag}' (historical) or '{v13_tag}' (current)"
            ),
        ))
    }
}
