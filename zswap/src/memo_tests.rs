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
/// `Input::well_formed` checks only the proof; the size and placement rules live at the offer
/// level and are covered separately. So every cell here expects `InvalidProof`, including the
/// strip case, where the statement falls back to the no-memo sentinel and so no longer matches
/// what was proved.
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
        let tampered = with_memo(&proven, mutated.clone().map(Memo));
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
    assert_ne!(memo_to_field(&a), memo_to_field(&Memo(b_bytes)));
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
        ("one zero byte", "731dab59a22ef473b632068c8cd8dfc198f2d9327bfde81cf34b767bd1eee72f"),
        ("ascii", "9c91754b311713226fc113e8aebf987d49405645b8e9c5be2a385ac56cfd8d56"),
        // 31 bytes fills exactly one field element; 32 spills into a second, zero-padded one.
        ("31 x 0x07", "aaa161b051f591f39b2ffbe8362a197bbabadab66a7455530d29b5596a42fe3a"),
        ("32 x 0x07", "86b0785f04932e03e6c069c781a2c2924eeede02e447dc9e3f3af7f2bf355f37"),
        ("512 x 0xa5", "880ded964331c1f45a20a8c6991b9879ac1d776937ded66e608d8d225418e762"),
    ];
    let inputs: [Vec<u8>; 5] = [
        vec![0x00; 1],
        b"midnight offer memo".to_vec(),
        vec![0x07; 31],
        vec![0x07; 32],
        vec![0xa5; MAX_MEMO_BYTES],
    ];

    for ((label, expected), bytes) in GOLDEN.iter().zip(inputs) {
        let actual = hex::encode(memo_to_field(&Memo(bytes)).as_le_bytes());
        assert_eq!(
            &actual, expected,
            "memo_to_field({label}) changed -- this is a consensus-visible encoding change"
        );
    }
}
