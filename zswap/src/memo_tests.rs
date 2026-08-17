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
use serialize::{Deserializable, Serializable, tagged_deserialize, tagged_serialize};
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

    let input = user_input(
        &mut rng,
        &keys,
        Some(memo(b"for sale: baby shoes, never worn")),
    )
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

/// Every mutation of a memo on a proven input must be rejected by proof verification.
///
/// `Input::well_formed` first applies the shared size and placement policy and then verifies the
/// proof. Every mutation in this matrix remains structurally valid, so every cell specifically
/// expects `InvalidProof`, including the strip case, where the statement falls back to the
/// no-memo sentinel and no longer matches what was proved.
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
        // Every mutation here stays inside 1..=MAX_MEMO_BYTES, so it is a memo a hostile party
        // could really put on the wire. The point is that the *proof* rejects it, not the size
        // rule.
        let tampered = with_memo(&proven, mutated.clone().map(|b| memo(&b)));
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
        matches!(proven.well_formed(0), Err(MalformedOffer::InvalidProof(_))),
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
    let a = memo(&[7u8; 31]);
    let mut b_bytes = vec![7u8; 31];
    b_bytes.push(0);
    assert_ne!(memo_to_field(&a), memo_to_field(&memo(&b_bytes)));
}

#[test]
fn memo_commitment_is_domain_separated_from_ciphertexts() {
    use transient_crypto::hash::{transient_commit, transient_hash};

    // The two commitments must not collide even on identical committed content. Feeding the same
    // field vector through both openings isolates the domain separator as the only difference —
    // comparing `memo_to_field` against `ciphertext_to_field` on unrelated inputs would pass
    // whether or not they were separated, and so would prove nothing.
    let values: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let memo_domain = Fr::from_le_bytes(b"midnight:zswap-memo[v1]").unwrap();
    let ciphertext_domain = Fr::from_le_bytes(b"midnight:zswap-ciphertext").unwrap();
    assert_ne!(memo_domain, ciphertext_domain);
    assert_ne!(
        transient_commit(&values[..], transient_hash(&[memo_domain])),
        transient_commit(&values[..], transient_hash(&[ciphertext_domain])),
    );

    // And end to end: a ciphertext's own bytes read as a memo do not commit to the ciphertext.
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
    let as_memo = memo(&bytes.into_iter().take(MAX_MEMO_BYTES).collect::<Vec<u8>>());
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
    assert!(matches!(err, OfferCreationFailed::MemoOnContractOwnedInput));
}

fn erased_offer(inputs: Vec<Input<(), DB>>) -> Offer<(), DB> {
    let mut offer = Offer::<(), DB> {
        inputs: inputs.into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();
    offer
}

/// An offer may carry a memo per input. The ledger does not pick one as "the offer's" message:
/// each is bound to its own input's proof and nullifier, so authorship is already unambiguous,
/// and forbidding several would break batch settlement, where many parties' offers are merged
/// into one and each party may have something to say.
#[test]
fn offer_accepts_a_memo_per_input() {
    let mut rng = StdRng::seed_from_u64(0x34);
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let one = user_input(&mut rng, &keys, Some(memo(b"first"))).unwrap();
    let two = user_input(&mut rng, &keys, Some(memo(b"second"))).unwrap();
    let bare = user_input(&mut rng, &keys, None).unwrap();

    assert!(erased_offer(vec![one.erase_proof()]).well_formed(0).is_ok());
    assert!(
        erased_offer(vec![one.erase_proof(), two.erase_proof()])
            .well_formed(0)
            .is_ok(),
        "several memos in one offer must be valid"
    );
    assert!(
        erased_offer(vec![
            one.erase_proof(),
            two.erase_proof(),
            bare.erase_proof()
        ])
        .well_formed(0)
        .is_ok()
    );
}

/// Structural rules apply to proof-erased offers too, which is why they live at the offer level.
#[test]
fn offer_rejects_contract_owned_memo_without_proofs() {
    let mut rng = StdRng::seed_from_u64(0x34);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let one = user_input(&mut rng, &keys, Some(memo(b"first"))).unwrap();

    let contract_owned = Input::<(), DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..one.erase_proof()
    };
    assert!(matches!(
        erased_offer(vec![contract_owned]).well_formed(0),
        Err(MalformedOffer::MemoOnContractOwnedInput { .. })
    ));
}

/// Safe public mutation cannot create an invalid memo placement, and hostile bytes encoding that
/// placement are rejected while decoding the complete input.
///
/// This test deliberately uses crate-private field access for the second half to model bytes from
/// an untrusted peer. External safe code cannot perform that construction because both placement
/// fields are private; its only mutation API is [`Input::with_memo`].
#[test]
fn checked_input_construction_and_decoding_enforce_memo_placement() {
    let mut rng = StdRng::seed_from_u64(0x34_51);
    let keys = SecretKeys::from_rng_seed(&mut rng);
    let user_owned = user_input(&mut rng, &keys, None).unwrap().erase_proof();
    let contract_owned = Input::<(), DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..user_owned
    };

    assert!(matches!(
        contract_owned.with_memo(Some(memo(b"not authorized by a user secret"))),
        Err(MalformedOffer::MemoOnContractOwnedInput { .. })
    ));

    // Simulate an invalid value received from an older/hostile implementation. Internal code can
    // assemble it for this negative test, but the Storable invariant must prevent it from being
    // reconstructed at the trust boundary.
    let invalid_wire_value = Input::<(), DB> {
        memo: Some(Sp::new(memo(b"hostile wire claim"))),
        ..contract_owned
    };
    let mut encoded = Vec::new();
    tagged_serialize(&invalid_wire_value, &mut encoded).unwrap();
    assert!(
        tagged_deserialize::<Input<(), DB>>(&encoded[..]).is_err(),
        "a contract-owned memo must not survive untrusted input decoding"
    );
}

/// The batch-settlement case: two separately built memo-carrying offers merge into one that is
/// still valid, and both memos survive intact. Merging cannot strip a memo even in principle —
/// doing so would drop the statement back to the no-memo sentinel and invalidate that input's
/// proof — so this is the only outcome that lets many parties settle together.
#[tokio::test]
async fn memo_carrying_offers_can_be_merged() {
    let mut rng = StdRng::seed_from_u64(0x5c);
    let resolver = resolver();
    let alice = SecretKeys::from_rng_seed(&mut rng);
    let bob = SecretKeys::from_rng_seed(&mut rng);

    let alice_memo = memo(b"alice: selling 100 at 3");
    let bob_memo = memo(b"bob: buying 100 at 3");

    let alice_offer = Offer::<Proof, DB> {
        inputs: vec![
            user_input(&mut rng, &alice, Some(alice_memo.clone()))
                .unwrap()
                .prove(prover(&resolver, &mut rng))
                .await
                .unwrap(),
        ]
        .into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    let bob_offer = Offer::<Proof, DB> {
        inputs: vec![
            user_input(&mut rng, &bob, Some(bob_memo.clone()))
                .unwrap()
                .prove(prover(&resolver, &mut rng))
                .await
                .unwrap(),
        ]
        .into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };

    let merged = alice_offer
        .merge(&bob_offer)
        .expect("offers with disjoint coins must merge");
    merged
        .well_formed(0)
        .expect("a merged offer carrying both parties' memos must verify");

    let carried: Vec<Memo> = merged
        .inputs
        .iter()
        .filter_map(|i| i.memo.as_deref().cloned())
        .collect();
    assert_eq!(carried.len(), 2, "both memos must survive the merge");
    assert!(carried.contains(&alice_memo) && carried.contains(&bob_memo));
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

/// Frozen expected values for [`memo_to_field`].
///
/// This is the one test that can catch an accidental change to the memo encoding. Construction
/// and verification deliberately share `memo_statement_element`, so if the packing, the length
/// prefix, the chunk width or the domain separator changed, *both* sides would change together
/// and every round-trip, injectivity and domain-separation test here would still pass — while
/// silently altering a consensus rule and invalidating every previously proved memo. These
/// vectors are what makes such a change fail loudly.
///
/// If one of these assertions fires, the encoding changed. That is a hard fork: do not update
/// the constants to match unless that is precisely what you intend.
#[test]
fn memo_to_field_matches_golden_vectors() {
    const GOLDEN: [(&str, &str); 5] = [
        // (memo, expected memo_to_field as little-endian hex)
        (
            "one zero byte",
            "731dab59a22ef473b632068c8cd8dfc198f2d9327bfde81cf34b767bd1eee72f",
        ),
        (
            "ascii",
            "9c91754b311713226fc113e8aebf987d49405645b8e9c5be2a385ac56cfd8d56",
        ),
        // 31 bytes fills exactly one field element; 32 spills into a second, zero-padded one.
        (
            "31 x 0x07",
            "aaa161b051f591f39b2ffbe8362a197bbabadab66a7455530d29b5596a42fe3a",
        ),
        (
            "32 x 0x07",
            "86b0785f04932e03e6c069c781a2c2924eeede02e447dc9e3f3af7f2bf355f37",
        ),
        (
            "512 x 0xa5",
            "880ded964331c1f45a20a8c6991b9879ac1d776937ded66e608d8d225418e762",
        ),
    ];
    let inputs: [Vec<u8>; 5] = [
        vec![0x00; 1],
        b"midnight offer memo".to_vec(),
        vec![0x07; 31],
        vec![0x07; 32],
        vec![0xa5; MAX_MEMO_BYTES],
    ];

    for ((label, expected), bytes) in GOLDEN.iter().zip(inputs) {
        let actual = hex::encode(memo_to_field(&memo(&bytes)).as_le_bytes());
        assert_eq!(
            &actual, expected,
            "memo_to_field({label}) changed -- this is a consensus-visible encoding change"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Public boundaries: an invalid memo must be unconstructible, unreadable and unwritable.
// ---------------------------------------------------------------------------------------------

/// Encodes a memo body of `declared_len` bytes behind a length header, without going through
/// `Memo` — which is the point: this is what a hostile peer sends.
fn encoded_memo(declared_len: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    <u32 as Serializable>::serialize(&declared_len, &mut bytes).unwrap();
    bytes.extend_from_slice(body);
    bytes
}

/// Every public way to build a `Memo` rejects the out-of-range lengths, and there is no way in
/// that skips the check.
///
/// The tuple field is private, so `Memo(vec![])` no longer compiles; these are the remaining
/// doors. If a new constructor is added and forgets to validate, this test will not catch it —
/// but `check_memo_len` being the only place the rule is written means there is one obvious thing
/// for that constructor to call.
#[test]
fn every_public_constructor_rejects_out_of_range_memos() {
    for bad in [Vec::new(), vec![0u8; MAX_MEMO_BYTES + 1]] {
        assert!(
            Memo::new(bad.clone()).is_err(),
            "Memo::new accepted {} bytes",
            bad.len()
        );
        assert!(
            Memo::try_from(bad.clone()).is_err(),
            "TryFrom<Vec<u8>> accepted {} bytes",
            bad.len()
        );
        assert!(
            Memo::try_from(&bad[..]).is_err(),
            "TryFrom<&[u8]> accepted {} bytes",
            bad.len()
        );
        // ... and on the wire, so a peer cannot deliver what a caller cannot build.
        assert!(
            <Memo as Deserializable>::deserialize(
                &mut &encoded_memo(bad.len() as u32, &bad)[..],
                0
            )
            .is_err(),
            "deserialize accepted {} bytes",
            bad.len()
        );
    }

    // The accepted boundary, including both sides of the 31-byte chunk width.
    for len in [1usize, 31, 32, 511, MAX_MEMO_BYTES] {
        let m = Memo::new(vec![0x5au8; len]).expect("length {len} must be accepted");
        assert_eq!(m.len(), len);
        assert!(!m.is_empty());
        assert_eq!(m.as_bytes(), &vec![0x5au8; len][..]);
    }
}

/// A hostile declared length must cost a comparison, not an allocation.
///
/// `u32::MAX` here would be a 4GiB `vec![0u8; len]` if the bound were checked after allocating,
/// which is a remote out-of-memory kill for the price of five bytes.
#[test]
fn deserialization_rejects_hostile_lengths_before_allocating() {
    for declared in [0u32, (MAX_MEMO_BYTES + 1) as u32, u32::MAX / 2, u32::MAX] {
        let bytes = encoded_memo(declared, &[]);
        assert!(
            <Memo as Deserializable>::deserialize(&mut &bytes[..], 0).is_err(),
            "declared length {declared} must be rejected"
        );
    }
}

/// A body shorter than its header is a truncated encoding, not a shorter memo.
#[test]
fn deserialization_rejects_truncated_and_reads_exactly_one_memo() {
    let bytes = encoded_memo(32, &[0xa5u8; 31]);
    assert!(
        <Memo as Deserializable>::deserialize(&mut &bytes[..], 0).is_err(),
        "a truncated body must fail rather than yield a 31-byte memo"
    );

    // Trailing bytes belong to whatever comes next in the stream: the memo decoder must consume
    // exactly its own encoding and leave the rest, not swallow it and not fail.
    let m = memo(b"exactly this");
    let mut stream = Vec::new();
    m.serialize(&mut stream).unwrap();
    stream.extend_from_slice(b"NOT PART OF THE MEMO");
    let mut cursor = &stream[..];
    let back = <Memo as Deserializable>::deserialize(&mut cursor, 0).unwrap();
    assert_eq!(back, m);
    assert_eq!(cursor, b"NOT PART OF THE MEMO");

    // Nested decoding is supposed to leave bytes for the next field. A top-level tagged value,
    // however, must consume its entire input so a peer cannot append an alternate spelling or
    // malformed suffix and still have it accepted as one memo.
    let mut top_level = Vec::new();
    tagged_serialize(&m, &mut top_level).unwrap();
    assert_eq!(tagged_deserialize::<Memo>(&top_level[..]).unwrap(), m);
    top_level.extend_from_slice(b"TRAILING");
    assert!(
        tagged_deserialize::<Memo>(&top_level[..]).is_err(),
        "a top-level memo encoding with trailing bytes must be rejected"
    );
}

// ---------------------------------------------------------------------------------------------
// Standalone input validation must agree with complete offer validation, and must decide the
// cheap questions first.
// ---------------------------------------------------------------------------------------------

/// The same contract-owned memo is rejected the same way whether it is judged alone or inside an
/// offer, with proofs and without.
///
/// Divergence here is the interesting bug: an input that passes on its own and fails in a block
/// (or the reverse) is a place where two nodes can disagree about the same bytes.
#[tokio::test]
async fn standalone_and_offer_validation_agree_on_memo_placement() {
    let mut rng = StdRng::seed_from_u64(0xc0a1);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let proven = user_input(&mut rng, &keys, Some(memo(b"not a contract's to send")))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();

    // Re-home the memo-bearing input onto a contract, which is exactly what a hand-assembled or
    // decoded input can claim.
    let contract_owned = Input::<Proof, DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..proven.clone()
    };

    assert!(
        matches!(
            contract_owned.well_formed(0),
            Err(MalformedOffer::MemoOnContractOwnedInput { .. })
        ),
        "standalone proven-input validation must reject a contract-owned memo"
    );
    assert!(
        matches!(
            Input::<ProofPreimage, DB> {
                contract_address: Some(Sp::new(ContractAddress::default())),
                ..user_input(&mut rng, &keys, Some(memo(b"preimage parity"))).unwrap()
            }
            .well_formed(0),
            Err(MalformedOffer::MemoOnContractOwnedInput { .. })
        ),
        "standalone proof-preimage validation must reject it identically"
    );
    assert!(
        matches!(
            contract_owned.erase_proof().well_formed(0),
            Err(MalformedOffer::MemoOnContractOwnedInput { .. })
        ),
        "standalone proof-erased validation must reject it identically"
    );
    assert!(
        matches!(
            erased_offer(vec![contract_owned.erase_proof()]).well_formed(0),
            Err(MalformedOffer::MemoOnContractOwnedInput { .. })
        ),
        "complete offer validation must reject it identically"
    );
}

/// Structural rejection must happen *before* proof verification.
///
/// The input below is invalid twice over: its memo sits on a contract-owned input, and its proof
/// cannot verify against a statement that now includes a contract address. Which error comes back
/// is therefore a direct read-out of the order the two checks run in. Getting this backwards
/// means every verifier on the network pays for a pairing check before discarding the input on a
/// rule that three comparisons settle.
#[tokio::test]
async fn structural_memo_rejection_precedes_proof_verification() {
    let mut rng = StdRng::seed_from_u64(0xc0de);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let proven = user_input(&mut rng, &keys, Some(memo(b"cheap check first")))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    let doubly_invalid = Input::<Proof, DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..proven.clone()
    };
    assert!(
        matches!(
            doubly_invalid.well_formed(0),
            Err(MalformedOffer::MemoOnContractOwnedInput { .. })
        ),
        "the structural verdict must win, which it can only do by being checked first"
    );

    // Control: with no memo the same re-homing is *only* a proof failure, so the assertion above
    // is really about ordering and not about the structural check swallowing every error.
    let memoless = user_input(&mut rng, &keys, None)
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    let proof_only = Input::<Proof, DB> {
        contract_address: Some(Sp::new(ContractAddress::default())),
        ..memoless
    };
    assert!(
        matches!(
            proof_only.well_formed(0),
            Err(MalformedOffer::InvalidProof(_))
        ),
        "without a memo there is no structural rule to trip, so the proof must be what fails"
    );
}

// ---------------------------------------------------------------------------------------------
// Consensus mapping: checked against a second implementation, not just against itself.
// ---------------------------------------------------------------------------------------------

/// A second implementation of the memo statement mapping, written from the normative description
/// in `spec/zswap.md` rather than from [`memo_to_field`].
///
/// It deliberately calls `transient_hash` directly instead of `transient_commit`, so it re-derives
/// the commitment structure rather than inheriting it. A change to the packing, the length prefix,
/// the chunk width, the domain separator, or the commitment shape breaks agreement between the two
/// — which is what the frozen vectors alone cannot catch if both sides are the same code.
fn memo_to_field_per_spec(bytes: &[u8]) -> Fr {
    use transient_crypto::hash::transient_hash;

    let domain = Fr::from_le_bytes(b"midnight:zswap-memo[v1]").expect("domain separator in range");
    let opening = transient_hash(&[domain]);
    let mut elems = vec![opening, Fr::from(bytes.len() as u64)];
    for chunk in bytes.chunks(31) {
        let mut padded = [0u8; 31];
        padded[..chunk.len()].copy_from_slice(chunk);
        elems.push(Fr::from_le_bytes(&padded).expect("31 bytes is below the field width"));
    }
    transient_hash(&elems)
}

#[test]
fn independent_implementation_reproduces_the_mapping() {
    // Chunk boundaries, the length-prefix cases, and a spread in between.
    let cases: Vec<Vec<u8>> = vec![
        vec![0x00; 1],
        vec![0x00; 2],
        b"midnight offer memo".to_vec(),
        vec![0x07; 30],
        vec![0x07; 31],
        vec![0x07; 32],
        vec![0x07; 62],
        vec![0xff; 511],
        vec![0xa5; MAX_MEMO_BYTES],
    ];
    for bytes in cases {
        let m = memo(&bytes);
        assert_eq!(
            memo_to_field(&m),
            memo_to_field_per_spec(&bytes),
            "the two implementations disagree for a {}-byte memo",
            bytes.len()
        );
    }

    // Absence is the reserved sentinel in both readings.
    assert_eq!(memo_statement_element(None), Fr::from(0u64));
}

// ---------------------------------------------------------------------------------------------
// Hostile content must be inert wherever it is rendered.
// ---------------------------------------------------------------------------------------------

/// Memo bytes are chosen by whoever built the input. Rendering them as text would hand that party
/// terminal escapes, bidirectional overrides, NULs, markup and URLs in every log line and
/// debugging session that touches the transaction.
#[test]
fn debug_rendering_is_inert_and_never_claims_authenticity() {
    let mut rng = StdRng::seed_from_u64(0xbad0);
    let keys = SecretKeys::from_rng_seed(&mut rng);

    let hostile: Vec<u8> = [
        b"<script>alert(1)</script>".as_slice(),
        b"https://evil.example/steal",
        b"\x1b[31mred\x1b[0m",
        b"\x00\x07\x7f",
        // A bidirectional override, and bytes that are not valid UTF-8 at all.
        "\u{202e}".as_bytes(),
        b"\xff\xfe\xfd",
    ]
    .concat();
    let input = user_input(&mut rng, &keys, Some(memo(&hostile))).unwrap();
    let rendered = format!("{:?}", input);

    assert!(
        rendered.contains(&hex::encode(&hostile)),
        "the exact bytes must still be recoverable, as hex"
    );
    for forbidden in ["<script", "https://", "alert(1)", "evil.example"] {
        assert!(
            !rendered.contains(forbidden),
            "rendering leaked {forbidden:?} as text: {rendered}"
        );
    }
    for forbidden in ['\u{1b}', '\0', '\u{7f}', '\u{202e}'] {
        assert!(
            !rendered.contains(forbidden),
            "rendering leaked control character {forbidden:?}"
        );
    }
    assert!(
        rendered.contains("unverified memo"),
        "an unvalidated rendering must say so, got: {rendered}"
    );
    assert!(
        !rendered.contains("authenticated"),
        "`Debug` has no verification result and must never imply one: {rendered}"
    );
}

// ---------------------------------------------------------------------------------------------
// Length matrix through the real proving path.
// ---------------------------------------------------------------------------------------------

/// Each accepted length proves, round-trips and verifies with byte-for-byte equality.
///
/// 31 and 32 straddle the chunk width and 512 is the cap, so this covers every place the packing
/// changes shape.
#[tokio::test]
async fn valid_lengths_survive_prove_round_trip_and_verify() {
    let mut rng = StdRng::seed_from_u64(0x1e0);
    let resolver = resolver();
    let keys = SecretKeys::from_rng_seed(&mut rng);

    for len in [1usize, 31, 32, 511, MAX_MEMO_BYTES] {
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let m = memo(&bytes);
        let proven = user_input(&mut rng, &keys, Some(m.clone()))
            .unwrap()
            .prove(prover(&resolver, &mut rng))
            .await
            .unwrap_or_else(|e| panic!("proving a {len}-byte memo failed: {e:?}"));

        let mut encoded = Vec::new();
        proven.serialize(&mut encoded).unwrap();
        let back = <Input<Proof, DB> as Deserializable>::deserialize(&mut &encoded[..], 0).unwrap();

        assert_eq!(
            back.memo.as_deref().map(Memo::as_bytes),
            Some(&bytes[..]),
            "a {len}-byte memo must survive the round trip byte for byte"
        );
        back.well_formed(0)
            .unwrap_or_else(|e| panic!("a {len}-byte memo must verify: {e:?}"));
    }
}

/// Two different coins may legitimately carry the *same* memo bytes, and each must be
/// authenticated on its own.
///
/// Equal bytes are the case where an implementation that keyed authenticity on the memo rather
/// than on the carrying input would look correct right up until it credited one party's message
/// to the other.
#[tokio::test]
async fn identical_memo_bytes_on_two_carriers_verify_independently() {
    let mut rng = StdRng::seed_from_u64(0x7317);
    let resolver = resolver();
    let alice = SecretKeys::from_rng_seed(&mut rng);
    let bob = SecretKeys::from_rng_seed(&mut rng);

    let shared = memo(b"same words, two authors");
    let a = user_input(&mut rng, &alice, Some(shared.clone()))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    let b = user_input(&mut rng, &bob, Some(shared.clone()))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();

    assert_ne!(
        a.nullifier, b.nullifier,
        "distinct coins, distinct carriers"
    );
    a.well_formed(0)
        .expect("alice's copy must verify on its own");
    b.well_formed(0).expect("bob's copy must verify on its own");

    let offer = Offer::<Proof, DB> {
        inputs: vec![a.clone(), b.clone()].into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    let mut offer = offer;
    offer.normalize();
    offer
        .well_formed(0)
        .expect("both memo-bearing inputs must verify together");
    assert_eq!(
        offer
            .inputs
            .iter()
            .filter(|i| i.memo.as_deref() == Some(&shared))
            .count(),
        2,
        "equal bytes must not be deduplicated into one carrier"
    );

    // The proofs are not interchangeable even though the memos are identical: each is bound to
    // its own nullifier, so swapping the proofs must fail.
    let a_with_b_proof = Input::<Proof, DB> {
        proof: b.proof.clone(),
        ..a.clone()
    };
    assert!(
        matches!(
            a_with_b_proof.well_formed(0),
            Err(MalformedOffer::InvalidProof(_))
        ),
        "equal memo bytes must not make two carriers' proofs interchangeable"
    );
}

/// The interoperability target: a maker publishes a memo-bearing offer, a settler merges an
/// ordinary memo-less offer into it, and the combined settlement still verifies with the maker's
/// memo intact and readable on the maker's own input.
///
/// The settler here uses the *unchanged* memo-less construction, whose statement element stays
/// the legacy `0` — the same value a pre-memo build would produce. That is what makes memo-less
/// and memo-bearing spends composable in one settlement.
#[tokio::test]
async fn maker_memo_survives_settlement_and_is_readable_per_input() {
    let mut rng = StdRng::seed_from_u64(0x9e);
    let resolver = resolver();
    let maker = SecretKeys::from_rng_seed(&mut rng);
    let settler = SecretKeys::from_rng_seed(&mut rng);
    let maker_memo = memo(b"selling 100 NIGHT, terms attached");

    let maker_input = user_input(&mut rng, &maker, Some(maker_memo.clone()))
        .unwrap()
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();
    let maker_nullifier = maker_input.nullifier;

    // The settler spends through the ordinary API; no memo, legacy statement element.
    let settler_unproven = user_input(&mut rng, &settler, None).unwrap();
    assert_eq!(settler_unproven.proof.binding_input, Fr::from(0u64));
    let settler_input = settler_unproven
        .prove(prover(&resolver, &mut rng))
        .await
        .unwrap();

    let offer_of = |i: Input<Proof, DB>| Offer::<Proof, DB> {
        inputs: vec![i].into(),
        outputs: vec![].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    let settlement = offer_of(maker_input)
        .merge(&offer_of(settler_input))
        .expect("maker and settler coins are disjoint");
    settlement
        .well_formed(0)
        .expect("the settlement must verify with one memo-bearing and one memo-less input");

    // Round-trip the settlement the way a counterparty would receive it, then read the memo back.
    let mut bytes = Vec::new();
    settlement.serialize(&mut bytes).unwrap();
    let received = <Offer<Proof, DB> as Deserializable>::deserialize(&mut &bytes[..], 0).unwrap();
    received
        .well_formed(0)
        .expect("proof verification must establish the memo binding before it is inspected");

    // Proof binding is per input: the memo is carried by the nullifier whose proof committed to
    // it. The ledger-level `MemoTrust::Authenticated` status additionally requires successful
    // validation and application against a concrete ledger state.
    let carried: Vec<(_, _)> = received
        .inputs
        .iter()
        .map(|i| (i.nullifier, i.memo.as_deref().cloned()))
        .collect();
    let maker_entry = carried
        .iter()
        .find(|(n, _)| *n == maker_nullifier)
        .expect("the maker input must survive settlement");
    assert_eq!(
        maker_entry.1.as_ref(),
        Some(&maker_memo),
        "the maker's memo must be readable on the maker's own input"
    );
    assert_eq!(
        carried.iter().filter(|(_, m)| m.is_some()).count(),
        1,
        "the settler contributed no memo, so exactly one input carries one"
    );

    // And the settlement is no more malleable than a lone input: altering or removing the
    // maker's memo while keeping its proof breaks verification.
    for tampered_memo in [Some(memo(b"selling 100 NIGHT, different terms")), None] {
        let inputs: Vec<Input<Proof, DB>> = received
            .inputs
            .iter()
            .map(|i| {
                if i.nullifier == maker_nullifier {
                    with_memo(&i, tampered_memo.clone())
                } else {
                    (*i).clone()
                }
            })
            .collect();
        let mut tampered = Offer::<Proof, DB> {
            inputs: inputs.into(),
            outputs: vec![].into(),
            transient: vec![].into(),
            deltas: vec![].into(),
        };
        tampered.normalize();
        assert!(
            matches!(
                tampered.well_formed(0),
                Err(MalformedOffer::InvalidProof(_))
            ),
            "tampering with the maker memo inside a settlement must be rejected"
        );
    }
}
