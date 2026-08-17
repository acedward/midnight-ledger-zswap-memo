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

//! Prior wire versions of the Zswap structures, for reading pre-memo history.
//!
//! `zswap-input[v2]` predates the memo field, so an updated reader cannot decode it through the
//! current types. These mirrors carry the exact v2-era layout — the same fields minus the memo
//! `Option` — and convert into the current types with `memo: None`, which is precisely how the
//! old rules behaved: the spend statement's first element was the constant `0` that
//! [`memo_statement_element`](crate::memo_statement_element) still produces for an absent memo.
//!
//! Layout identity with the genuinely released v2 wire is not taken on faith: each mirror pins
//! its tag decomposition against the *historical* `.tag-decompositions` files, which have been
//! committed since before the memo existed. If a mirror drifted from the real old layout, those
//! tests fail.
//!
//! Conversion is one-way and deliberate. A v12-era value converts into the current shape for
//! shared application logic, but reserialization of history must go through the mirror types so
//! that accepted old bytes reproduce byte-identically — a v12 transaction must never silently
//! acquire a v13 header.

use crate::structure::{Delta, Input, Memo, Offer, Output, Transient};
use coin_structure::coin::Nullifier;
use coin_structure::contract::ContractAddress;
use serialize::tag_enforcement_test;
use std::sync::Arc;
use storage::Storable;
use storage::arena::Sp;
use storage::arena::{ArenaHash, ArenaKey};
use storage::db::DB;
#[cfg(test)]
use storage::db::InMemoryDB;
use storage::storable::Loader;
use storage::storage::Array;
use transient_crypto::commitment::Pedersen;
use transient_crypto::merkle_tree::MerkleTreeDigest;

use derive_where::derive_where;
use serde::Serialize;
use serialize::{Deserializable, Serializable, Tagged};
use std::fmt::{self, Debug, Formatter};

/// The pre-memo `zswap-input[v2]` wire layout: today's [`Input`] minus the memo field.
#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-input[v2]"]
#[storable(db = D)]
pub struct InputV12<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub merkle_tree_root: MerkleTreeDigest,
    pub proof: Arc<P>,
}
tag_enforcement_test!(InputV12<(), InMemoryDB>);

/// The pre-memo `zswap-offer[v5]` wire layout. Outputs, transients, and deltas are unchanged
/// between the eras; only the input element type differs.
#[derive(Storable)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Clone; P)]
#[tag = "zswap-offer[v5]"]
#[storable(db = D)]
pub struct OfferV12<P: Storable<D>, D: DB> {
    pub inputs: Array<InputV12<P, D>, D>,
    pub outputs: Array<Output<P, D>, D>,
    pub transient: Array<Transient<P, D>, D>,
    pub deltas: Array<Delta, D>,
}
tag_enforcement_test!(OfferV12<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> From<&InputV12<P, D>> for Input<P, D> {
    fn from(old: &InputV12<P, D>) -> Self {
        Input {
            nullifier: old.nullifier,
            value_commitment: old.value_commitment,
            contract_address: old.contract_address.clone(),
            merkle_tree_root: old.merkle_tree_root,
            // The historical rules had no memo; absence is the exact semantic equivalent, and
            // reproduces the constant-zero statement element old proofs were made against.
            memo: None,
            proof: old.proof.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> From<&OfferV12<P, D>> for Offer<P, D> {
    fn from(old: &OfferV12<P, D>) -> Self {
        Offer {
            inputs: old
                .inputs
                .iter()
                .map(|i| Input::from(&*i))
                .collect::<Vec<_>>()
                .into(),
            outputs: old.outputs.clone(),
            transient: old.transient.clone(),
            deltas: old.deltas.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> InputV12<P, D> {
    /// The reverse projection, for tests and for reproducing v12 bytes from values that are
    /// known to be memo-less. Fails on a memo-bearing input: a memo has no v12 representation,
    /// and pretending otherwise would strip a proof-bound value.
    pub fn try_from_current(input: &Input<P, D>) -> Result<Self, MemoHasNoPriorEncoding> {
        if input.memo().is_some() {
            return Err(MemoHasNoPriorEncoding);
        }
        Ok(InputV12 {
            nullifier: input.nullifier,
            value_commitment: input.value_commitment,
            contract_address: input.contract_address.clone(),
            merkle_tree_root: input.merkle_tree_root,
            proof: input.proof.clone(),
        })
    }
}

/// A memo-bearing value cannot be represented in the pre-memo wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoHasNoPriorEncoding;

impl std::fmt::Display for MemoHasNoPriorEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a memo-bearing input has no v12 wire representation")
    }
}
impl std::error::Error for MemoHasNoPriorEncoding {}

// Sanity coupling: if `Memo` ever becomes representable in the v12 mirror, this module's
// premise is wrong. Referencing the type keeps the import meaningful under all feature sets.
const _: fn(&Memo) -> usize = |m| m.as_bytes().len();

impl<P: Storable<D>, D: DB> Debug for InputV12<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "<v12 shielded input {:?}>", self.nullifier)
    }
}

impl<P: Storable<D>, D: DB> Debug for OfferV12<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "<v12 offer: {} inputs, {} outputs, {} transient>",
            self.inputs.len(),
            self.outputs.len(),
            self.transient.len()
        )
    }
}
