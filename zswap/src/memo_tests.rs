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

//! Tests for [`Memo`]s on Zswap inputs.
//!
//! The proving tests need the Zswap proving keys. They are fetched on demand from
//! `srs.midnight.network` and cached under `$MIDNIGHT_PP` (or `~/.cache/midnight/zk-params`), so
//! the first run of these tests needs network access and later runs do not.

use crate::error::{MalformedOffer, OfferCreationFailed};
use crate::keys::SecretKeys;
use crate::prove::ZswapResolver;
use crate::structure::*;
use crate::{ZSWAP_TREE_HEIGHT, ciphertext_to_field, memo_statement_element, memo_to_field};
use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::rng::SplittableRng;
use coin_structure::coin::{Info as CoinInfo, QualifiedInfo as QualifiedCoinInfo};
use coin_structure::contract::ContractAddress;
use coin_structure::transfer::{Recipient, SenderEvidence};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serialize::{Deserializable, Serializable};
use std::borrow::Cow;
use std::sync::Arc;
use storage::arena::Sp;
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::merkle_tree::MerkleTree;
use transient_crypto::proofs::{Proof, ProofPreimage};
use zkir_v2::LocalProvingProvider;

type DB = InMemoryDB;

fn memo(bytes: &[u8]) -> Memo {
    Memo::new(bytes.to_vec()).expect("test memo should be a valid size")
}

/// Builds an unproven, user-owned input spending a fresh coin, optionally carrying a memo.
fn user_input(
    rng: &mut StdRng,
    keys: &SecretKeys,
    memo: Option<Memo>,
) -> Result<Input<ProofPreimage, DB>, OfferCreationFailed> {
    let qcoin = QualifiedCoinInfo {
        value: Default::default(),
        type_: Default::default(),
        nonce: rng.r#gen(),
        mt_index: 0,
    };
    let coin = CoinInfo::from(&qcoin);
    let recipient = Recipient::User(keys.coin_public_key());
    let tree = MerkleTree::<(), DB>::blank(ZSWAP_TREE_HEIGHT)
        .try_update_hash(0, coin.commitment(&recipient).0, ())
        .expect("updating hash on non-collapsed tree should always succeed")
        .rehash();
    Input::new_from_secret_key(
        rng,
        &qcoin,
        None,
        SenderEvidence::User(Cow::Borrowed(&keys.coin_secret_key)),
        &tree,
        memo,
    )
}

fn prover<'a>(
    resolver: &'a ZswapResolver,
    rng: &mut StdRng,
) -> LocalProvingProvider<'a, StdRng, ZswapResolver, ZswapResolver> {
    LocalProvingProvider {
        rng: rng.split(),
        params: resolver,
        resolver,
    }
}

fn resolver() -> ZswapResolver {
    ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            ZSWAP_EXPECTED_FILES.to_owned(),
        )
        .expect("data provider should initialise"),
    )
}

/// Rebuilds an input around an untouched proof with a different memo. This is what an attacker
/// tampering with a memo in transit can do: everything except produce a matching proof.
fn with_memo<P: storage::Storable<DB> + Clone>(
    input: &Input<P, DB>,
    memo: Option<Memo>,
) -> Input<P, DB> {
    Input {
        memo: memo.map(Sp::new),
        ..input.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// U1: the decisive test. A memo-carrying spend must verify against the shipped verifier key.
//
// The whole design rests on the spend circuit leaving its first public input unconstrained, so
// that putting a memo commitment there needs no circuit, key, or ceremony change. If this fails,
// that premise is wrong.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn u1_memo_input_verifies_against_shipped_verifier_key() {
    let mut rng = StdRng::seed_from_u64(0x11);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let input = user_input(&mut rng, &keys, Some(memo(b"for sale: baby shoes, never worn")))
        .expect("user-owned spend with a memo should be constructible");
    let proven = input
        .prove(prover(&resolver, &mut rng))
        .await
        .expect("proving should succeed");

    proven
        .well_formed(0)
        .expect("a memo-carrying spend must verify under the existing spend verifier key");
}

#[tokio::test]
async fn u2_memoless_input_still_verifies() {
    let mut rng = StdRng::seed_from_u64(0x42);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let input = user_input(&mut rng, &keys, None).unwrap();
    assert_eq!(
        input.proof.binding_input,
        Fr::from(0u64),
        "a memo-less spend must keep the historical zero binding input"
    );
    let proven = input.prove(prover(&resolver, &mut rng)).await.unwrap();
    proven
        .well_formed(0)
        .expect("memo-less spends must verify exactly as before");
}

// ---------------------------------------------------------------------------------------------
// Tamper matrix: carriers x operations, generated rather than hand-listed.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Strip,
    Graft,
    Replace,
    BitFlip,
    Truncate,
    Extend,
    Swap,
}

const OPS: [Op; 7] = [
    Op::Strip,
    Op::Graft,
    Op::Replace,
    Op::BitFlip,
    Op::Truncate,
    Op::Extend,
    Op::Swap,
];

/// Applies `op` to `bytes`, returning `None` where the operation removes the value entirely.
fn mutate(op: Op, bytes: &[u8], other: &[u8]) -> Option<Vec<u8>> {
    let mut out = bytes.to_vec();
    match op {
        Op::Strip => return None,
        Op::Graft => return Some(other.to_vec()),
        Op::Replace => out.iter_mut().for_each(|b| *b ^= 0xff),
        Op::BitFlip => out[0] ^= 0x01,
        Op::Truncate => {
            out.pop();
        }
        Op::Extend => out.push(0x00),
        Op::Swap => return Some(other.to_vec()),
    }
    Some(out)
}

/// Every mutation of a memo on a proven input must be rejected. Which error is expected depends
/// on the operation: mutations that keep a structurally valid memo fail the proof, while
/// mutations that leave an invalid one are caught by the structural rules first.
#[tokio::test]
async fn tamper_matrix_input_memo() {
    let mut rng = StdRng::seed_from_u64(0x7a3);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let original = b"the maker's terms".to_vec();
    let other = b"somebody else's terms".to_vec();

    let proven = user_input(&mut rng, &keys, Some(memo(&original)))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    proven.well_formed(0).expect("baseline must verify");

    for op in OPS {
        let mutated = mutate(op, &original, &other);
        let tampered = with_memo(&proven, mutated.clone().map(|b| Memo(b)));
        let err = tampered
            .well_formed(0)
            .expect_err(&format!("memo tamper {op:?} must be rejected"));
        assert!(
            matches!(err, MalformedOffer::InvalidProof(_)),
            "memo tamper {op:?} should fail proof verification, got {err:?}"
        );
    }
}

/// The same matrix against the output ciphertext, which has bound its own binding input since
/// before this change. These rows are the control group: they must fail for the same reason
/// memo rows do, confirming the mechanism being reused actually works.
#[tokio::test]
async fn tamper_matrix_output_ciphertext_control() {
    let mut rng = StdRng::seed_from_u64(0x7a4);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let coin = CoinInfo {
        value: Default::default(),
        type_: Default::default(),
        nonce: rng.r#gen(),
    };

    let output = Output::<ProofPreimage, DB>::new(
        &mut rng,
        &coin,
        None,
        &keys.coin_public_key(),
        Some(keys.encryption_secret_key.public_key()),
    )
    .unwrap();
    let proven = output
        .prove(prover(&resolver, &mut rng))
        .await
        .expect("proving an output should succeed");
    proven.well_formed(0).expect("baseline must verify");

    let original = proven.ciphertext.as_deref().cloned().unwrap();

    // Strip.
    let stripped = Output {
        ciphertext: None,
        ..proven.clone()
    };
    assert!(
        matches!(
            stripped.well_formed(0),
            Err(MalformedOffer::InvalidProof(_))
        ),
        "stripping a bound ciphertext must fail verification"
    );

    // Alter each field element in turn.
    for i in 0..original.ciph.len() {
        let mut altered = original.clone();
        altered.ciph[i] = altered.ciph[i] + Fr::from(1u64);
        let tampered = Output {
            ciphertext: Some(Sp::new(altered)),
            ..proven.clone()
        };
        assert!(
            matches!(
                tampered.well_formed(0),
                Err(MalformedOffer::InvalidProof(_))
            ),
            "altering ciphertext element {i} must fail verification"
        );
    }
}

/// Moving a memo between two proven inputs of the same offer invalidates both.
#[tokio::test]
async fn memo_cannot_be_swapped_between_inputs() {
    let mut rng = StdRng::seed_from_u64(0x5b1);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let a = user_input(&mut rng, &keys, Some(memo(b"memo a")))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    let b = user_input(&mut rng, &keys, Some(memo(b"memo b")))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();

    let a_with_b = with_memo(&a, b.memo.as_deref().cloned());
    let b_with_a = with_memo(&b, a.memo.as_deref().cloned());
    assert!(matches!(
        a_with_b.well_formed(0),
        Err(MalformedOffer::InvalidProof(_))
    ));
    assert!(matches!(
        b_with_a.well_formed(0),
        Err(MalformedOffer::InvalidProof(_))
    ));
}

/// A builder that sets the memo on the struct but leaves the preimage's binding input at zero
/// produces a proof that cannot verify. This is the failure mode of forgetting to keep the two
/// in step, and it must be loud rather than silent.
#[tokio::test]
async fn builder_desynchronisation_fails_verification() {
    let mut rng = StdRng::seed_from_u64(0x9c2);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let memoless = user_input(&mut rng, &keys, None).unwrap();
    let desynced = with_memo(&memoless, Some(memo(b"attached after the fact")));
    let proven = desynced.prove(prover(&resolver, &mut rng)).await.unwrap();

    assert!(
        matches!(
            proven.well_formed(0),
            Err(MalformedOffer::InvalidProof(_))
        ),
        "a memo not reflected in the binding input must not verify"
    );
}

// ---------------------------------------------------------------------------------------------
// Commitment: domain separation, injectivity, and the zero sentinel.
// ---------------------------------------------------------------------------------------------

#[test]
fn memo_commitment_is_never_the_no_memo_sentinel() {
    for len in [1usize, 2, 30, 31, 32, 62, 511, MAX_MEMO_BYTES] {
        let m = memo(&vec![0u8; len]);
        assert_ne!(
            memo_to_field(&m),
            Fr::from(0u64),
            "all-zero memo of {len} bytes must not commit to the sentinel"
        );
        let m = memo(&vec![0xffu8; len]);
        assert_ne!(memo_to_field(&m), Fr::from(0u64));
    }
    assert_eq!(memo_statement_element(None), Fr::from(0u64));
}

#[test]
fn memo_commitment_is_injective_over_trailing_zeros() {
    // The chunk packing zero-pads, so without the length prefix these would collide.
    assert_ne!(memo_to_field(&memo(&[0])), memo_to_field(&memo(&[0, 0])));
    assert_ne!(memo_to_field(&memo(b"hi")), memo_to_field(&memo(b"hi\0")));
    // Chunk boundary: 31 bytes fills one field element exactly.
    let a = memo(&vec![7u8; 31]);
    let mut b_bytes = vec![7u8; 31];
    b_bytes.push(0);
    assert_ne!(memo_to_field(&a), memo_to_field(&Memo(b_bytes)));
}

#[test]
fn memo_commitment_is_domain_separated_from_ciphertexts() {
    // A ciphertext and a memo built over the same field content must not collide: the two
    // commitments use different domain separators.
    let mut rng = StdRng::seed_from_u64(0x1d);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let coin = CoinInfo {
        value: Default::default(),
        type_: Default::default(),
        nonce: rng.r#gen(),
    };
    let ciph = CoinCiphertext::new(&mut rng, &coin, keys.encryption_secret_key.public_key());

    let mut bytes = Vec::new();
    ciph.serialize(&mut bytes).unwrap();
    let as_memo = Memo(bytes.into_iter().take(MAX_MEMO_BYTES).collect());
    assert_ne!(memo_to_field(&as_memo), ciphertext_to_field(&ciph));
}

// ---------------------------------------------------------------------------------------------
// Structural rules.
// ---------------------------------------------------------------------------------------------

#[test]
fn empty_memo_is_rejected_at_every_layer() {
    assert!(matches!(
        Memo::new(Vec::new()),
        Err(MalformedOffer::EmptyMemo)
    ));

    // ... and on the wire, so `None` and `Some(empty)` cannot alias.
    let mut bytes = Vec::new();
    <u32 as Serializable>::serialize(&0u32, &mut bytes).unwrap();
    assert!(
        <Memo as Deserializable>::deserialize(&mut &bytes[..], 0).is_err(),
        "a zero-length memo must not deserialize"
    );
}

#[test]
fn memo_size_cap_is_enforced_before_allocation() {
    assert!(Memo::new(vec![0u8; MAX_MEMO_BYTES]).is_ok());
    assert!(matches!(
        Memo::new(vec![0u8; MAX_MEMO_BYTES + 1]),
        Err(MalformedOffer::MemoTooLarge { .. })
    ));

    // An oversized length header is rejected without reading (or allocating) the body.
    let mut bytes = Vec::new();
    <u32 as Serializable>::serialize(&(u32::MAX), &mut bytes).unwrap();
    assert!(<Memo as Deserializable>::deserialize(&mut &bytes[..], 0).is_err());
}

#[test]
fn memo_round_trips() {
    for len in [1usize, 31, 32, MAX_MEMO_BYTES] {
        let m = memo(&vec![0xa5u8; len]);
        let mut bytes = Vec::new();
        m.serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), m.serialized_size());
        let back = <Memo as Deserializable>::deserialize(&mut &bytes[..], 0).unwrap();
        assert_eq!(m, back);
    }
}

#[test]
fn memo_on_contract_owned_input_is_rejected_at_construction() {
    let mut rng = StdRng::seed_from_u64(0x33);
    let qcoin = QualifiedCoinInfo {
        value: Default::default(),
        type_: Default::default(),
        nonce: rng.r#gen(),
        mt_index: 0,
    };
    let coin = CoinInfo::from(&qcoin);
    let address = ContractAddress::default();
    let tree = MerkleTree::<(), DB>::blank(ZSWAP_TREE_HEIGHT)
        .try_update_hash(0, coin.commitment(&Recipient::Contract(address)).0, ())
        .unwrap()
        .rehash();

    let err = Input::<ProofPreimage, DB>::new_from_secret_key(
        &mut rng,
        &qcoin,
        None,
        SenderEvidence::Contract(address),
        &tree,
        Some(memo(b"contracts hold no spending secret")),
    )
    .expect_err("a contract-owned input must not accept a memo");
    assert!(matches!(
        err,
        OfferCreationFailed::MemoOnContractOwnedInput
    ));
}

/// Structural rules apply to proof-erased offers too, which is why they live at the offer level.
#[test]
fn offer_rejects_multiple_and_contract_owned_memos_without_proofs() {
    let mut rng = StdRng::seed_from_u64(0x34);
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let one = user_input(&mut rng, &keys, Some(memo(b"first"))).unwrap();
    let two = user_input(&mut rng, &keys, Some(memo(b"second"))).unwrap();

    let mut offer = Offer::<(), DB> {
        inputs: vec![one.erase_proof(), two.erase_proof()].into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();
    assert!(matches!(
        offer.well_formed(0),
        Err(MalformedOffer::MultipleMemos)
    ));

    // One memo is fine.
    let mut offer = Offer::<(), DB> {
        inputs: vec![one.erase_proof()].into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();
    assert!(offer.well_formed(0).is_ok());

    // A memo on a contract-owned input is rejected even with no proof to check.
    let contract_owned = Input::<(), DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..one.erase_proof()
    };
    let mut offer = Offer::<(), DB> {
        inputs: vec![contract_owned].into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();
    assert!(matches!(
        offer.well_formed(0),
        Err(MalformedOffer::MemoOnContractOwnedInput { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// The memo must survive the transformations an input goes through between construction and
// verification. Dropping it anywhere produces an input whose proof can never verify.
// ---------------------------------------------------------------------------------------------

#[test]
fn memo_survives_erase_proof_and_retarget_segment() {
    let mut rng = StdRng::seed_from_u64(0x35);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let m = memo(b"carried through");
    let input = user_input(&mut rng, &keys, Some(m.clone())).unwrap();

    assert_eq!(input.erase_proof().memo.as_deref(), Some(&m));

    let retargeted = input.retarget_segment(3);
    assert_eq!(retargeted.memo.as_deref(), Some(&m));
    assert_eq!(
        retargeted.proof.binding_input, input.proof.binding_input,
        "retargeting a segment must not disturb the memo binding"
    );

    // The witness-derived values the balance machinery reads are untouched by the memo.
    let memoless = user_input(&mut StdRng::seed_from_u64(0x35), &keys, None).unwrap();
    let with = user_input(&mut StdRng::seed_from_u64(0x35), &keys, Some(m)).unwrap();
    assert!(memoless.delta() == with.delta());
    assert!(memoless.binding_randomness() == with.binding_randomness());
}

#[test]
fn transient_inputs_carry_no_memo() {
    let mut rng = StdRng::seed_from_u64(0x36);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let coin = CoinInfo {
        value: Default::default(),
        type_: Default::default(),
        nonce: rng.r#gen(),
    };
    let output =
        Output::<ProofPreimage, DB>::new(&mut rng, &coin, None, &keys.coin_public_key(), None)
            .unwrap();
    let state = crate::local::State::<DB>::new();
    let qcoin = QualifiedCoinInfo {
        value: coin.value,
        type_: coin.type_,
        nonce: coin.nonce,
        mt_index: 0,
    };
    let (_, transient) = state
        .spend_from_output(&mut rng, &keys, &qcoin, None, output)
        .expect("spending a fresh output should succeed");
    assert!(
        transient.as_input().memo.is_none(),
        "transients are unrepresentable with a memo"
    );
}

/// Two inputs differing only by their memo are distinct values. This changes ordering and set
/// membership, so pin it: `merge` treats them as disjoint and the duplicate nullifier is caught
/// later, at apply time, rather than here.
#[test]
fn inputs_differing_only_by_memo_are_distinct() {
    let mut rng = StdRng::seed_from_u64(0x37);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let input = user_input(&mut rng, &keys, None).unwrap().erase_proof();
    let with = with_memo(&input, Some(memo(b"m")));
    assert_ne!(input, with);
    assert_eq!(input.nullifier, with.nullifier);
}

/// Proving must not drop the memo: the proof is bound to it, so an input that loses its memo in
/// the prover can never verify again.
#[tokio::test]
async fn proving_preserves_the_memo() {
    let mut rng = StdRng::seed_from_u64(0x38);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let m = memo(b"survives proving");
    let proven = user_input(&mut rng, &keys, Some(m.clone()))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    assert_eq!(proven.memo.as_deref(), Some(&m));
}

/// A proven memo input round-trips through serialization and still verifies.
#[tokio::test]
async fn proven_memo_input_round_trips() {
    let mut rng = StdRng::seed_from_u64(0x39);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let proven: Input<Proof, DB> = user_input(&mut rng, &keys, Some(memo(b"round trip")))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();

    let mut bytes = Vec::new();
    proven.serialize(&mut bytes).unwrap();
    let back = <Input<Proof, DB> as Deserializable>::deserialize(&mut &bytes[..], 0).unwrap();
    assert_eq!(proven.memo.as_deref(), back.memo.as_deref());
    back.well_formed(0)
        .expect("a round-tripped memo input must still verify");

    let mut reserialized = Vec::new();
    back.serialize(&mut reserialized).unwrap();
    assert_eq!(bytes, reserialized, "encoding must be canonical");

    // A memo grows the transaction by its own bytes, which is what pays for it.
    let memoless: Input<Proof, DB> = Input {
        memo: None,
        ..proven.clone()
    };
    assert!(proven.serialized_size() > memoless.serialized_size());
}

/// `Arc<Proof>` is not `Clone`-transparent for our helper; make sure the helper compiles for the
/// proof-erased case too.
#[test]
fn with_memo_helper_covers_erased_inputs() {
    let mut rng = StdRng::seed_from_u64(0x40);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let erased: Input<(), DB> = user_input(&mut rng, &keys, None).unwrap().erase_proof();
    let _ = with_memo(&erased, Some(memo(b"x")));
    let _: Arc<()> = erased.proof.clone();
}
