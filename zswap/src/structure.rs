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

use crate::ZSWAP_TREE_HEIGHT;
use crate::error::MalformedOffer;
use coin_structure::coin::{
    Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey, ShieldedTokenType,
    TokenType, UnshieldedTokenType,
};
use coin_structure::contract::ContractAddress;
use derive_where::derive_where;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::Serialize;
use serialize::{Deserializable, Serializable, Tagged, tag_enforcement_test};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::ops::{Add, Sub};
use std::sync::Arc;
use storage::Storable;
use storage::arena::Sp;
use storage::arena::{ArenaHash, ArenaKey};
use storage::db::DB;
#[cfg(test)]
use storage::db::InMemoryDB;
use storage::storable::Loader;
use storage::storage::Array;
use transient_crypto::commitment::{Pedersen, PedersenRandomness};
use transient_crypto::curve::{EmbeddedGroupAffine, Fr};
use transient_crypto::encryption;
use transient_crypto::merkle_tree::{MerkleTree, MerkleTreeDigest};
use transient_crypto::proofs::ProofPreimage;
use transient_crypto::repr::{FieldRepr, FromFieldRepr};

macro_rules! exptfile {
    ($name:literal, $desc:literal) => {
        (
            concat!("zswap/", midnight_ledger_static::version!(), "/", $name),
            base_crypto::data_provider::hexhash(
                &include_bytes!(concat!("../static/", $name, ".sha256"))
                    .split_at(64)
                    .0,
            ),
            $desc,
        )
    };
}

/// Files provided by Midnight's data provider for Zswap.
pub const ZSWAP_EXPECTED_FILES: &[(&str, [u8; 32], &str)] = &[
    exptfile!(
        "spend.prover",
        "zero-knowledge proving key for Zswap inputs"
    ),
    exptfile!(
        "spend.verifier",
        "zero-knowledge verifying key for Zswap inputs"
    ),
    exptfile!("spend.bzkir", "ZKIR source for Zswap inputs"),
    exptfile!(
        "output.prover",
        "zero-knowledge proving key for Zswap outputs"
    ),
    exptfile!(
        "output.verifier",
        "zero-knowledge verifying key for Zswap outputs"
    ),
    exptfile!("output.bzkir", "ZKIR source for Zswap outputs"),
    exptfile!(
        "sign.prover",
        "zero-knowledge proving key for Zswap signing operations"
    ),
    exptfile!(
        "sign.verifier",
        "zero-knowledge verifying key for Zswap signing operations"
    ),
    exptfile!("sign.bzkir", "ZKIR source for Zswap signing operations"),
];

pub(crate) const COIN_CIPHERTEXT_LEN: usize = 6;
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Storable)]
#[storable(base)]
pub struct CoinCiphertext {
    pub c: EmbeddedGroupAffine,
    pub ciph: [Fr; COIN_CIPHERTEXT_LEN],
}

impl Tagged for CoinCiphertext {
    fn tag() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("zswap-coin-ciphertext[v1]")
    }
    fn tag_unique_factor() -> String {
        format!("(embedded-group-affine[v1],array(fr-bls,{COIN_CIPHERTEXT_LEN}))")
    }
}
tag_enforcement_test!(CoinCiphertext);

impl Serializable for CoinCiphertext {
    fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        <EmbeddedGroupAffine as Serializable>::serialize(&self.c, writer)?;
        // Because this is unversioned we need not send COIN_CIPHERTEXT_LEN
        for elem in self.ciph {
            <Fr as Serializable>::serialize(&elem, writer)?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        EmbeddedGroupAffine::serialized_size(&self.c)
            + self
                .ciph
                .iter()
                .map(Serializable::serialized_size)
                .sum::<usize>()
    }
}

impl Deserializable for CoinCiphertext {
    fn deserialize(
        reader: &mut impl std::io::Read,
        recursive_depth: u32,
    ) -> Result<Self, std::io::Error> {
        let c = EmbeddedGroupAffine::deserialize(reader, recursive_depth)?;
        // See note in `transient_crypto::encryption::SecretKey::decrypt` for why the identity
        // element is excluded.
        if c.is_identity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ciphertext challenge may not be the point at infinity",
            ));
        };
        let ciph = {
            let mut res = [Fr::default(); COIN_CIPHERTEXT_LEN];
            for byte in res.iter_mut() {
                *byte = Fr::deserialize(reader, recursive_depth)?;
            }
            res
        };
        Ok(Self { c, ciph })
    }
}

impl CoinCiphertext {
    pub fn new<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
        coin: &CoinInfo,
        pk: encryption::PublicKey,
    ) -> CoinCiphertext {
        pk.encrypt(rng, coin)
            .try_into()
            .expect("ciphertext should have ciphertext length")
    }
}

impl TryFrom<encryption::Ciphertext> for CoinCiphertext {
    type Error = ();

    fn try_from(ciph: encryption::Ciphertext) -> Result<Self, ()> {
        if ciph.ciph.len() != COIN_CIPHERTEXT_LEN {
            return Err(());
        }
        let mut arr = [0.into(); COIN_CIPHERTEXT_LEN];
        arr.copy_from_slice(&ciph.ciph);
        Ok(CoinCiphertext {
            c: ciph.c,
            ciph: arr,
        })
    }
}

impl From<CoinCiphertext> for encryption::Ciphertext {
    fn from(ciph: CoinCiphertext) -> encryption::Ciphertext {
        encryption::Ciphertext {
            c: ciph.c,
            ciph: ciph.ciph.to_vec(),
        }
    }
}

/// The largest permitted [`Memo`], in bytes.
///
/// Memo bytes are consensus data and are paid for through the transaction's serialized size, so
/// the bound exists to keep a memo from being the cheapest way to put arbitrary data on chain.
/// This should become a ledger parameter rather than a compile-time constant.
pub const MAX_MEMO_BYTES: usize = 512;

/// How many bytes of a memo are packed into each field element by
/// [`memo_to_field`](crate::memo_to_field). One below the 32-byte field width, so that any
/// chunk is guaranteed to be less than the field modulus.
pub(crate) const MEMO_BYTES_PER_FIELD: usize = 31;

/// Opaque bytes attached to an [`Input`] and committed to by its spend proof.
///
/// A commitment to the memo occupies the spend proof's binding input, so a memo cannot be added,
/// altered, or removed without invalidating a successfully verified proof. Proof verification
/// establishes that the holder of the spending secret committed to the bytes; the ledger's
/// stronger public `Authenticated` inspection status additionally requires complete real
/// transaction validation and successful application of the carrying segment. Until that paired
/// verdict these bytes are attacker-controlled claims. The ledger does not interpret them;
/// whether they are plaintext or a ciphertext addressed to some audience is left to the
/// application.
///
/// A memo is between 1 and [`MAX_MEMO_BYTES`] bytes. Zero-length memos are rejected so that
/// "no memo" has exactly one representation, keeping it distinct from any memo's commitment.
///
/// The byte vector is private: every checked constructor ([`Memo::new`] and the `TryFrom`
/// implementations) enforces the same range. Serialization and deserialization re-check anyway
/// — see `check_memo_len` — so that a value reconstituted from storage or produced by some
/// future unchecked path still cannot reach the wire.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Storable)]
#[storable(base)]
pub struct Memo(Vec<u8>);

/// The single place the memo length rule is decided.
///
/// Construction, serialization and deserialization all funnel through this, so the bound cannot
/// drift between the boundary that accepts a memo and the boundary that encodes it.
pub(crate) fn check_memo_len(len: usize) -> Result<(), MalformedOffer> {
    match len {
        0 => Err(MalformedOffer::EmptyMemo),
        len if len > MAX_MEMO_BYTES => Err(MalformedOffer::MemoTooLarge {
            size: len,
            limit: MAX_MEMO_BYTES,
        }),
        _ => Ok(()),
    }
}

/// The complete memo policy for one input, shared by checked construction, untrusted storage
/// decoding, standalone validation and complete offer/transaction validation.
pub(crate) fn memo_well_formed(
    memo: Option<&Memo>,
    contract_address: Option<&ContractAddress>,
) -> Result<(), MalformedOffer> {
    let Some(memo) = memo else {
        return Ok(());
    };
    // A contract-owned spend proves no user secret, so a memo on it would carry none of the
    // authorization a memo exists to convey. Rejected before the size rule so the more specific
    // diagnosis wins.
    if let Some(address) = contract_address {
        return Err(MalformedOffer::MemoOnContractOwnedInput { address: *address });
    }
    check_memo_len(memo.len())
}

impl Memo {
    /// Creates a memo, rejecting sizes outside `1..=MAX_MEMO_BYTES`.
    pub fn new(bytes: Vec<u8>) -> Result<Self, MalformedOffer> {
        check_memo_len(bytes.len())?;
        Ok(Memo(bytes))
    }

    /// The memo's bytes. Always between 1 and [`MAX_MEMO_BYTES`] of them.
    ///
    /// These are opaque application data. Proof verification can establish their binding to the
    /// carrying spend, but callers should treat the bytes as unverified until complete real
    /// validation and successful application of the carrying segment; see [`Input`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the memo, returning its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The memo's length in bytes, always in `1..=MAX_MEMO_BYTES`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the backing value is empty.
    ///
    /// Checked construction makes this `false` for every valid `Memo`; reading the bytes rather
    /// than hard-coding the answer keeps this accessor honest if corrupted storage or a future
    /// internal unchecked path ever reconstructs an invalid value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for Memo {
    type Error = MalformedOffer;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Memo::new(bytes)
    }
}

impl TryFrom<&[u8]> for Memo {
    type Error = MalformedOffer;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // This is a public boundary for borrowed, potentially attacker-controlled bytes. Check
        // the bound before cloning so an oversized request cannot force an attacker-sized
        // allocation merely to learn that it is invalid.
        check_memo_len(bytes.len())?;
        Ok(Memo(bytes.to_vec()))
    }
}

impl AsRef<[u8]> for Memo {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Tagged for Memo {
    fn tag() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("zswap-memo[v1]")
    }
    fn tag_unique_factor() -> String {
        format!("(bounded-bytes,{MAX_MEMO_BYTES})")
    }
}
tag_enforcement_test!(Memo);

/// Wraps a memo length rejection as the I/O error the serialization traits deal in.
fn memo_io_error(err: MalformedOffer) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

/// Lowercase hex, for rendering untrusted bytes inertly.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

impl Serializable for Memo {
    fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        // Defensive. `Memo::new` already guarantees this, but serialization is the last point
        // before a value becomes consensus data, and an invalid one must never get that far --
        // it would be a memo no verifier could accept and no deserializer could read back.
        // The check is also what makes the `as u32` below lossless.
        check_memo_len(self.0.len()).map_err(memo_io_error)?;
        <u32 as Serializable>::serialize(&(self.0.len() as u32), writer)?;
        writer.write_all(&self.0)
    }

    fn serialized_size(&self) -> usize {
        <u32 as Serializable>::serialized_size(&(self.0.len() as u32)) + self.0.len()
    }
}

impl Deserializable for Memo {
    fn deserialize(
        reader: &mut impl std::io::Read,
        recursive_depth: u32,
    ) -> Result<Self, std::io::Error> {
        let len = <u32 as Deserializable>::deserialize(reader, recursive_depth)? as usize;
        // Checked *before* allocating: the length is attacker-controlled, so a hostile
        // `u32::MAX` here must cost a comparison rather than 4GiB.
        check_memo_len(len).map_err(memo_io_error)?;
        let mut bytes = vec![0u8; len];
        // A truncated body fails here rather than yielding a short memo.
        reader.read_exact(&mut bytes)?;
        Ok(Memo(bytes))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize)]
#[tag = "zswap-authorized-claim[v3]"]
/// A claim to a specific public key, authorized by the user's private key.
pub struct AuthorizedClaim<P> {
    pub coin: CoinInfo,
    pub recipient: CoinPublicKey,
    pub proof: Arc<P>,
}
tag_enforcement_test!(AuthorizedClaim<()>);

impl<P> AuthorizedClaim<P> {
    pub fn erase_proof(&self) -> AuthorizedClaim<()> {
        AuthorizedClaim {
            coin: self.coin,
            recipient: self.recipient,
            proof: Arc::new(()),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-input[v3]"]
#[storable(db = D, invariant = input_invariant)]
pub struct Input<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub value_commitment: Pedersen,
    pub(crate) contract_address: Option<Sp<ContractAddress, D>>,
    pub merkle_tree_root: MerkleTreeDigest,
    /// An optional message, bound into this spend's proof. See [`Memo`].
    pub(crate) memo: Option<Sp<Memo, D>>,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Input<(), InMemoryDB>);

fn input_invariant<P: Storable<D>, D: DB>(input: &Input<P, D>) -> std::io::Result<()> {
    memo_well_formed(input.memo.as_deref(), input.contract_address.as_deref())
        .map_err(memo_io_error)
}

impl<P> Debug for AuthorizedClaim<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "<claim of {} of token {:?} for recipient {:?}>",
            self.coin.value, self.coin.type_, self.recipient
        )
    }
}

impl<P: Storable<D>, D: DB> Input<P, D> {
    /// The contract that owns this input, or `None` for a user-secret-owned spend.
    pub fn contract_address(&self) -> Option<&ContractAddress> {
        self.contract_address.as_deref()
    }

    /// The memo carried by this input, if any.
    pub fn memo(&self) -> Option<&Memo> {
        self.memo.as_deref()
    }

    /// Returns a clone *claiming* `memo`, after enforcing the same size and ownership policy as
    /// validation.
    ///
    /// This does not recompute a proof or a [`ProofPreimage`] binding input. It is suitable for
    /// inspecting or deliberately tampering with an untrusted transaction, but changing a memo on
    /// an already-built input will make that input fail proof verification. Real spends should be
    /// constructed with `local::State::spend_with_memo`, which binds the memo while creating the
    /// spend. The placement fields themselves remain crate-private, so a safe external caller
    /// cannot assemble a contract-owned memo and serialize it.
    pub fn with_memo(&self, memo: Option<Memo>) -> Result<Self, MalformedOffer> {
        memo_well_formed(memo.as_ref(), self.contract_address())?;
        Ok(Input {
            memo: memo.map(Sp::new),
            ..self.clone()
        })
    }

    pub fn erase_proof(&self) -> Input<(), D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: self.merkle_tree_root,
            memo: self.memo.clone(),
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs
        // Input before last is CoinInfo
        let inputs = &self.proof.inputs;
        let coin = CoinInfo::from_field_repr(
            &inputs[inputs.len() - 1 - CoinInfo::FIELD_SIZE..inputs.len() - 1],
        )
        .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs
        // rc is the last input, and should be a single Fr element.
        (*self
            .proof
            .inputs
            .last()
            .expect("must have witness to extract from"))
        .try_into()
        .expect("extracted binding randomness is invalid")
    }
}

impl<P: Storable<D>, D: DB> Debug for Input<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded input {:?} for: {:?}",
                self.nullifier, addr
            )?,
            None => write!(formatter, "<shielded input {:?}", self.nullifier)?,
        }
        // Rendered so that inspection tooling can show what a spend actually carries, as inert
        // lowercase hex rather than as text: memo bytes are attacker-controlled, and hex cannot
        // carry markup, a URL, a terminal escape, a NUL or invalid UTF-8 into whatever displays
        // this.
        //
        // Labelled `unverified` unconditionally. `Debug` has no verification outcome to consult,
        // and these bytes receive the public authenticated status only after the complete
        // transaction validates and this carrying segment applies successfully. Callers that can
        // distinguish those states should render through a verification-aware inspection layer.
        if let Some(memo) = self.memo.as_deref() {
            write!(
                formatter,
                " unverified memo({} bytes): {}",
                memo.len(),
                hex_lower(memo.as_bytes())
            )?;
        }
        write!(formatter, ">")
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-output[v2]"]
#[storable(db = D)]
pub struct Output<P: Storable<D>, D: DB> {
    pub coin_com: Commitment,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Output<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Output<P, D> {
    pub fn erase_proof(&self) -> Output<(), D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Output<ProofPreimage, D> {
    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs.
        // Input before last is CoinInfo
        let inputs = &self.proof.inputs;
        let coin = CoinInfo::from_field_repr(
            &inputs[inputs.len() - 1 - CoinInfo::FIELD_SIZE..inputs.len() - 1],
        )
        .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX).saturating_neg(),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs.
        // rc is the last input, and should be a single Fr element.
        // NOTE: rc negated because output commitments are subtracted
        -PedersenRandomness::try_from(
            *self
                .proof
                .inputs
                .last()
                .expect("must have witness to extract from"),
        )
        .expect("extracted binding randomness is invalid")
    }
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

impl<P: Storable<D>, D: DB> Debug for Output<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded output {:?} for: {:?}>",
                self.coin_com, addr
            ),
            None => write!(formatter, "<shielded output {:?}>", self.coin_com),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialOrd, Ord, PartialEq, Eq, Clone; P)]
#[tag = "zswap-transient[v2]"]
#[storable(db = D)]
pub struct Transient<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub coin_com: Commitment,
    pub value_commitment_input: Pedersen,
    pub value_commitment_output: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof_input: Arc<P>,
    pub proof_output: Arc<P>,
}
tag_enforcement_test!(Transient<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Transient<P, D> {
    pub fn erase_proof(&self) -> Transient<(), D> {
        Transient {
            nullifier: self.nullifier,
            coin_com: self.coin_com,
            value_commitment_input: self.value_commitment_input,
            value_commitment_output: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof_input: Arc::new(()),
            proof_output: Arc::new(()),
        }
    }
}

impl<D: DB> Transient<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.as_input().binding_randomness() + self.as_output().binding_randomness()
    }
    pub fn segment(&self) -> Option<u16> {
        self.as_input().segment()
    }
}

impl<P: Clone + Storable<D>, D: DB> Transient<P, D> {
    pub fn as_input(&self) -> Input<P, D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment_input,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: MerkleTree::<_>::blank(ZSWAP_TREE_HEIGHT)
                .try_update_hash(0, self.coin_com.0, ())
                .expect("updating hash on non-collapsed tree should always succeed")
                .rehash()
                .root()
                .expect("rehashed tree must have root"),
            // Transients carry no memo: the spend and the output are the same transaction, so
            // there is no offer for a message to accompany.
            memo: None,
            proof: self.proof_input.clone(),
        }
    }

    pub fn as_output(&self) -> Output<P, D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: self.proof_output.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Transient<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self.contract_address.clone() {
            Some(addr) => {
                write!(
                    formatter,
                    "<shielded transient coin {:?} {:?} for: {:?}>",
                    self.coin_com, self.nullifier, addr
                )
            }
            None => write!(
                formatter,
                "<shielded transient coin {:?} {:?}>",
                self.coin_com, self.nullifier
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize, Storable)]
#[storable(base)]
#[tag = "zswap-delta"]
pub struct Delta {
    pub token_type: ShieldedTokenType,
    pub value: i128,
}
tag_enforcement_test!(Delta);

#[derive(Storable)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Clone; P)]
#[tag = "zswap-offer[v6]"]
#[storable(db = D)]
/// A Zswap offer consists of a potentially unbalanced set of Zswap
/// inputs/outputs.
///
/// All vectors must be sorted to be valid, and `deltas` must be key-unique
/// (i.e. not contain tuples sharing their first element `(a, b)` and `(a, c)`).
/// This is to have a canonical representation while operating on sets and maps.
pub struct Offer<P: Storable<D>, D: DB> {
    /// A set of Inputs
    pub inputs: Array<Input<P, D>, D>,
    /// A set of Outputs
    pub outputs: Array<Output<P, D>, D>,
    /// A set of "transient" Zswap coins: Coins that are created and spent in
    /// the same transaction
    pub transient: Array<Transient<P, D>, D>,
    /// A map from types (coin colors) to the offer value in this type.
    /// A positive value means more coins have been spent, a negative value
    /// means more coins were created.
    pub deltas: Array<Delta, D>,
}
tag_enforcement_test!(Offer<(), InMemoryDB>);

impl<D: DB> Offer<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.inputs
            .iter()
            .map(|i| i.binding_randomness())
            .chain(self.outputs.iter().map(|o| o.binding_randomness()))
            .chain(self.transient.iter().map(|t| t.binding_randomness()))
            .fold(0.into(), |a, b| a + b)
    }
}

impl<P: Storable<D>, D: DB> Offer<P, D> {
    pub fn erase_proofs(&self) -> Offer<(), D> {
        Offer {
            inputs: self.inputs.iter_deref().map(Input::erase_proof).collect(),
            outputs: self.outputs.iter_deref().map(Output::erase_proof).collect(),
            transient: self
                .transient
                .iter_deref()
                .map(Transient::erase_proof)
                .collect(),
            deltas: self.deltas.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Offer<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_map()
            .entry(&Symbol("inputs"), &self.inputs)
            .entry(&Symbol("outputs"), &self.outputs)
            .entry(&Symbol("transient"), &self.transient)
            .entry(
                &Symbol("deltas"),
                &self
                    .deltas
                    .iter_deref()
                    .cloned()
                    .map(DebugDelta)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

struct DebugDelta(Delta);

impl Debug for DebugDelta {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?} -> {:?}", self.0.token_type, self.0.value)
    }
}

pub fn normalize_deltas<T: Ord, I: Iterator<Item = (T, i128)>>(deltas: I) -> Vec<(T, i128)> {
    let mut new_deltas: Vec<_> = deltas
        .fold(BTreeMap::new(), |mut map, (k, v)| {
            *map.entry(k).or_insert(0) += v;
            map
        })
        .into_iter()
        .collect();
    new_deltas.retain(|(_, v)| *v != 0);
    new_deltas.sort();
    new_deltas
}

impl<P: Clone + Ord + Storable<D>, D: DB> Offer<P, D> {
    pub fn normalize(&mut self) {
        self.inputs = self.inputs.iter_deref().sorted().cloned().collect();
        self.outputs = self.outputs.iter_deref().sorted().cloned().collect();
        self.transient = self.transient.iter_deref().sorted().cloned().collect();
        self.deltas = normalize_deltas(
            self.deltas
                .iter_deref()
                .map(|delta| (delta.token_type, delta.value)),
        )
        .into_iter()
        .map(|(token_type, value)| Delta { token_type, value })
        .collect();
    }

    #[instrument(skip(self, other))]
    pub fn merge(&self, other: &Self) -> Result<Self, MalformedOffer> {
        #[allow(clippy::mutable_key_type)]
        let inputs1: BTreeSet<_> = self.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let inputs2: BTreeSet<_> = other.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs1: BTreeSet<_> = self.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs2: BTreeSet<_> = other.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient1: BTreeSet<_> = self.transient.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient2: BTreeSet<_> = other.transient.iter_deref().cloned().collect();
        if inputs1.is_disjoint(&inputs2)
            && outputs1.is_disjoint(&outputs2)
            && transient1.is_disjoint(&transient2)
        {
            let mut res = Offer {
                inputs: inputs1.into_iter().chain(inputs2.into_iter()).collect(),
                outputs: outputs1.into_iter().chain(outputs2.into_iter()).collect(),
                transient: transient1
                    .iter()
                    .chain(transient2.iter())
                    .cloned()
                    .collect(),
                deltas: self
                    .deltas
                    .iter_deref()
                    .chain(other.deltas.iter_deref())
                    .cloned()
                    .collect(),
            };
            res.normalize();
            Ok(res)
        } else {
            warn!("overlap in coins attempted to merge");
            Err(MalformedOffer::NonDisjointCoinMerge)
        }
    }
}

struct Symbol(&'static str);

impl Debug for Symbol {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

pub const INPUT_PIS: usize = 68;
pub const INPUT_PROOF_SIZE: usize = 4_832;
pub const OUTPUT_PIS: usize = 77;
pub const OUTPUT_PROOF_SIZE: usize = 4_832;
pub const AUTHORIZED_CLAIM_PIS: usize = 13;
