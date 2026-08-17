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

#![deny(unreachable_pub)]
#![deny(warnings)]
#![allow(unused_imports)]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate lazy_static;

pub const ZSWAP_TREE_HEIGHT: u8 = 32;

pub(crate) fn ciphertext_to_field(c: &CoinCiphertext) -> transient_crypto::curve::Fr {
    use transient_crypto::hash::{transient_commit, transient_hash};
    transient_commit(
        &c.ciph[..],
        transient_hash(&[
            transient_crypto::curve::Fr::from_le_bytes(b"midnight:zswap-ciphertext")
                .expect("Domain sep should be in range for field"),
            c.c.x().unwrap_or(0.into()),
            c.c.y().unwrap_or(0.into()),
        ]),
    )
}

/// Commits to a memo, producing the field element an [`Input`]'s spend proof binds to.
///
/// The bytes are packed into field elements `MEMO_BYTES_PER_FIELD` at a time and prefixed with
/// the byte length. The prefix is what makes the packing injective: without it a memo and the
/// same memo followed by zero bytes would pack to the same field elements, since the final chunk
/// is zero-padded.
///
/// Domain separated from `ciphertext_to_field`, so cross-protocol reinterpretation requires a
/// collision in the underlying hash rather than following directly from the encoding.
pub fn memo_to_field(m: &Memo) -> transient_crypto::curve::Fr {
    use transient_crypto::curve::Fr;
    use transient_crypto::hash::{transient_commit, transient_hash};
    let mut fields = vec![Fr::from(m.len() as u64)];
    for chunk in m.as_bytes().chunks(MEMO_BYTES_PER_FIELD) {
        let mut buf = [0u8; MEMO_BYTES_PER_FIELD];
        buf[..chunk.len()].copy_from_slice(chunk);
        fields.push(
            Fr::from_le_bytes(&buf).expect("chunk below field width should be in range for field"),
        );
    }
    transient_commit(
        &fields[..],
        transient_hash(&[Fr::from_le_bytes(b"midnight:zswap-memo[v1]")
            .expect("Domain sep should be in range for field")]),
    )
}

/// The first element of a Zswap spend proof's statement: the memo commitment, or zero when there
/// is no memo.
///
/// Both proof construction and verification derive the value through this one function. They must
/// agree exactly — a divergence would be a consensus split, not a local bug — so it deliberately
/// has no second implementation.
pub(crate) fn memo_statement_element(memo: Option<&Memo>) -> transient_crypto::curve::Fr {
    memo.map(memo_to_field).unwrap_or_else(|| 0.into())
}

mod construct;
pub mod error;
pub mod keys;
pub mod ledger;
pub mod local;
#[cfg(test)]
mod memo_tests;
pub mod prior;
pub mod prove;
mod structure;
pub mod verify;

use midnight_onchain_runtime::{ops::Op, result_mode::ResultMode};
use storage::db::DB;

pub(crate) fn filter_invalid<M: ResultMode<D>, I: Iterator<Item = Op<M, D>>, D: DB>(
    iter: I,
) -> impl Iterator<Item = Op<M, D>> {
    iter.filter(|op| match op {
        Op::Idx { path, .. } => !path.is_empty(),
        Op::Ins { n, .. } => *n != 0,
        _ => true,
    })
}

pub use structure::*;
