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

//! Memos through a real, nonzero-value settlement.
//!
//! `zswap/src/memo_tests.rs` proves the per-input property in isolation, against zero-value coins
//! and bare offers. That is not the thing the feature is for. This file exercises the case the
//! specification actually names: a maker with a *nonzero* shielded coin attaches a memo, an
//! independent settler merges its own memo-less offer in and pays the fees, and the combined
//! standard transaction goes all the way through construction, balancing, proving, strict
//! well-formedness, byte round-trip, application, and post-application state.
//!
//! Everything here needs real proofs, so it is gated on `proving` like the other end-to-end
//! ledger tests. `cargo test -p midnight-ledger-v9` **without** `--features proving` compiles
//! these out silently.

#![cfg(all(feature = "proving", feature = "proof-verifying"))]

use base_crypto::rng::SplittableRng;
use coin_structure::coin::{Info as CoinInfo, ShieldedTokenType};
use lazy_static::lazy_static;
use midnight_ledger::error::{
    MalformedTransaction, TransactionInvalid as LedgerTransactionInvalid,
};
use midnight_ledger::memo_inspection::MemoTrust;
use midnight_ledger::semantics::{TransactionResult, ZswapLocalStateExt};
use midnight_ledger::structure::{
    ProofPreimageMarker, Signature, StandardTransaction, Transaction,
};
use midnight_ledger::test_utilities::{Resolver, TestState, TxBound, test_resolver, tx_prove_bind};
use midnight_ledger::verify::{RevalidationReference, WellFormedStrictness};
use midnight_ledger_v9 as midnight_ledger;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serialize::{Deserializable, Serializable};
use storage::arena::Sp;
use storage::db::{DB, InMemoryDB};
use transient_crypto::commitment::PedersenRandomness;
use zswap::keys::SecretKeys;
use zswap::local::State as ZswapLocalState;
use zswap::{Delta, Input, Memo, Offer, Output};

lazy_static! {
    static ref RESOLVER: Resolver = test_resolver("");
}

/// What the settler assembles and balances, before proofs exist.
type UnprovenTx = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;
/// What `tx_prove` returns and what validation, round-trip and application see.
type ProvenTx = TxBound<Signature, InMemoryDB>;

fn memo(bytes: &[u8]) -> Memo {
    Memo::new(bytes.to_vec()).expect("test memo must be a valid size")
}

/// Mints a nonzero shielded coin to `recipient` and returns the events, so that a party other
/// than the `TestState`'s own owner can learn about the coin it now holds.
///
/// `TestState::rewards_shielded` always pays its own `zswap_keys`. Using it for the maker would
/// make "the memo is attributable to the maker rather than the settler" vacuously true, because
/// there would only be one party.
async fn mint_shielded_to<D: DB>(
    state: &mut TestState<D>,
    rng: &mut StdRng,
    recipient: &SecretKeys,
    token: ShieldedTokenType,
    amount: u128,
) -> Vec<midnight_ledger::events::Event<D>> {
    let coin = CoinInfo {
        nonce: rng.r#gen(),
        value: amount,
        type_: token,
    };
    let output = Output::<_, D>::new(
        rng,
        &coin,
        Some(0u16),
        &recipient.coin_public_key(),
        Some(recipient.enc_public_key()),
    )
    .expect("output creation must succeed");
    let offer = Offer {
        inputs: vec![].into(),
        outputs: vec![output].into(),
        transient: vec![].into(),
        deltas: vec![Delta {
            token_type: token,
            value: -(amount as i128),
        }]
        .into(),
    };
    let tx = Transaction::<(), _, _, D>::new(
        "local-test",
        storage::storage::HashMap::new(),
        Some(offer),
        storage::storage::HashMap::new(),
    );
    let mut strictness = WellFormedStrictness::default();
    strictness.enforce_balancing = false;
    let result = state
        .apply(&tx, strictness)
        .expect("minting transaction must be well-formed");
    assert!(
        matches!(result, TransactionResult::Success(..)),
        "minting must succeed, got {result:?}"
    );
    result.events().to_vec()
}

/// Replaces the memo on whichever guaranteed input carries `nullifier`, leaving its proof alone.
///
/// This is what a relay or counterparty can do to a settlement in flight: rewrite bytes, but not
/// produce a matching proof.
fn retamper_memo(
    tx: &ProvenTx,
    nullifier: coin_structure::coin::Nullifier,
    memo: Option<Memo>,
) -> ProvenTx {
    let Transaction::Standard(stx) = tx.clone() else {
        panic!("expected a standard transaction");
    };
    let offer = stx
        .guaranteed_coins
        .as_deref()
        .expect("expected guaranteed coins")
        .clone();
    let inputs: Vec<Input<_, InMemoryDB>> = offer
        .inputs
        .iter()
        .map(|input| {
            if input.nullifier == nullifier {
                input
                    .with_memo(memo.clone())
                    .expect("the target is a user-owned input and the tamper memo is in range")
            } else {
                (*input).clone()
            }
        })
        .collect();
    let mut tampered_offer = Offer {
        inputs: inputs.into(),
        outputs: offer.outputs.clone(),
        transient: offer.transient.clone(),
        deltas: offer.deltas.clone(),
    };
    tampered_offer.normalize();
    Transaction::Standard(StandardTransaction {
        guaranteed_coins: Some(Sp::new(tampered_offer)),
        ..stx
    })
}

/// Replaces one input's proof with another input's proof while leaving the target memo bytes and
/// carrier nullifier untouched. This yields the same claimed memo through the proof-invalid view,
/// which is the trust-status corpus case that mutating the memo itself cannot cover.
fn transplant_other_proof(tx: &ProvenTx, target: coin_structure::coin::Nullifier) -> ProvenTx {
    let Transaction::Standard(stx) = tx.clone() else {
        panic!("expected a standard transaction");
    };
    let offer = stx
        .guaranteed_coins
        .as_deref()
        .expect("expected guaranteed coins")
        .clone();
    let replacement = offer
        .inputs
        .iter()
        .find(|input| input.nullifier != target)
        .expect("the independently funded settler input supplies a different proof")
        .proof
        .clone();
    let inputs: Vec<Input<_, InMemoryDB>> = offer
        .inputs
        .iter()
        .map(|input| {
            if input.nullifier == target {
                let mut changed = (*input).clone();
                changed.proof = replacement.clone();
                changed
            } else {
                (*input).clone()
            }
        })
        .collect();
    let mut tampered_offer = Offer {
        inputs: inputs.into(),
        outputs: offer.outputs.clone(),
        transient: offer.transient.clone(),
        deltas: offer.deltas.clone(),
    };
    tampered_offer.normalize();
    Transaction::Standard(StandardTransaction {
        guaranteed_coins: Some(Sp::new(tampered_offer)),
        ..stx
    })
}

/// The specification's Story 2 target, end to end.
///
/// A maker spends a real 100-million-unit shielded coin with a memo attached and pays a settler
/// with it. The settler merges in its own memo-less coin selection and covers the fees. The
/// combined transaction must prove, strictly verify, balance, round-trip, apply, and leave state
/// in which the maker's nullifier is spent, the settler holds the value, and the memo is
/// attributable to the maker's input and to nothing else.
#[tokio::test]
async fn nonzero_maker_memo_settles_through_application() {
    let mut rng = StdRng::seed_from_u64(0x5e771e);
    let mut settler: TestState<InMemoryDB> = TestState::new(&mut rng);

    // A genuinely separate party, with its own keys and its own local state.
    let maker_keys = SecretKeys::from_rng_seed(&mut rng);
    let maker_zswap = ZswapLocalState::<InMemoryDB>::new();

    settler.give_fee_token(&mut rng, 10).await;

    let token: ShieldedTokenType = Default::default();
    let maker_value = 100_000_000u128;
    let events = mint_shielded_to(&mut settler, &mut rng, &maker_keys, token, maker_value).await;
    let maker_zswap = maker_zswap
        .replay_events(&maker_keys, events.iter())
        .expect("the maker must be able to replay its own funding");

    let maker_coin = *maker_zswap
        .coins
        .iter()
        .next()
        .expect("the maker must hold a coin")
        .1;
    assert_eq!(
        maker_coin.value, maker_value,
        "the maker's coin must be nonzero -- a zero-value exercise would not test settlement"
    );

    // Fund the settler with an independent shielded coin. The eventual transaction therefore
    // merges two real Zswap offers: the maker's memo-bearing trade and the settler's memo-less
    // participation. Dust still pays the fee, but is not being mistaken for a settler offer.
    let settler_value = 25_000_000u128;
    settler.rewards_shielded(&mut rng, token, settler_value);
    let settler_coin = *settler
        .zswap
        .coins
        .iter()
        .find(|(_, coin)| coin.value == settler_value && coin.type_ == token)
        .expect("the settler must hold its independently funded shielded coin")
        .1;

    // The maker spends it, attaching a memo, and pays the settler.
    let maker_memo = memo(b"maker: selling 100_000_000, terms in attachment 4");
    let (next_maker_state, maker_input) = maker_zswap
        .spend_with_memo(
            &mut rng,
            &maker_keys,
            &maker_coin,
            Some(0),
            Some(maker_memo.clone()),
        )
        .expect("the maker must be able to spend its own coin with a memo");
    // Records the pending spend. Kept for shape even though this test spends only once.
    let _maker_zswap = next_maker_state;
    let maker_nullifier = maker_input.nullifier;

    let payout = CoinInfo {
        nonce: rng.r#gen(),
        value: maker_value,
        type_: token,
    };
    let payout_output = Output::new(
        &mut rng,
        &payout,
        Some(0),
        &settler.zswap_keys.coin_public_key(),
        Some(settler.zswap_keys.enc_public_key()),
    )
    .expect("payout output must be constructible");

    // Value in equals value out, so the offer carries no delta of its own and the settler is
    // balancing fees rather than the maker's trade.
    let maker_offer = Offer {
        inputs: vec![maker_input].into(),
        outputs: vec![payout_output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };

    // The settler independently spends and returns its own value without a memo. This offer is
    // economically neutral but cryptographically real, and its merge is what proves the maker's
    // bytes do not become a transaction-wide or settler-authored message.
    let (_next_settler_state, settler_input) = settler
        .zswap
        .spend(&mut rng, &settler.zswap_keys, &settler_coin, Some(0))
        .expect("the settler must be able to spend its own coin without a memo");
    assert!(
        settler_input.memo().is_none(),
        "the settler offer is memo-less"
    );
    assert_ne!(settler_input.nullifier, maker_nullifier);
    let settler_nullifier = settler_input.nullifier;
    let settler_refund = CoinInfo {
        nonce: rng.r#gen(),
        value: settler_value,
        type_: token,
    };
    let settler_output = Output::new(
        &mut rng,
        &settler_refund,
        Some(0),
        &settler.zswap_keys.coin_public_key(),
        Some(settler.zswap_keys.enc_public_key()),
    )
    .expect("settler refund output must be constructible");
    let settler_offer = Offer {
        inputs: vec![settler_input].into(),
        outputs: vec![settler_output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    let merged_offer = maker_offer
        .merge(&settler_offer)
        .expect("independently owned offers must merge");
    assert_eq!(merged_offer.inputs.len(), 2, "one carrier per participant");
    assert_eq!(
        merged_offer
            .inputs
            .iter()
            .filter(|input| input.memo().is_some())
            .count(),
        1,
        "only the maker's input carries a memo"
    );

    let tx: UnprovenTx = Transaction::new(
        "local-test",
        storage::storage::HashMap::new(),
        Some(merged_offer),
        storage::storage::HashMap::new(),
    );

    // Merely running the generic validation machinery over preimages or erased proofs must not
    // mint authentication evidence. It is useful structural checking, but no spend proof has
    // been verified.
    let mut structural_strictness = WellFormedStrictness::default();
    structural_strictness.enforce_balancing = false;
    let checked_preimage = tx
        .well_formed(&settler.ledger, structural_strictness, settler.time)
        .expect("the balanced preimage shape should pass structural validation");
    assert!(
        checked_preimage
            .memo_records()
            .iter()
            .all(|record| record.trust() == MemoTrust::Unverified),
        "preimage validation must never authenticate memo bytes"
    );
    let checked_erased = tx
        .erase_proofs()
        .well_formed(&settler.ledger, structural_strictness, settler.time)
        .expect("the proof-erased shape should pass structural validation");
    assert!(
        checked_erased
            .memo_records()
            .iter()
            .all(|record| record.trust() == MemoTrust::Unverified),
        "proof-erased validation must never authenticate memo bytes"
    );

    // Prove first, then balance. `balance_tx` sizes the dust fee from the transaction handed to
    // it, and a proof is much larger than the preimage it replaces -- balancing first would
    // under-fund the fee for the transaction that actually gets submitted.
    let proven_core = tx_prove_bind(rng.split(), &tx, &RESOLVER)
        .await
        .expect("the settlement must prove");
    let proven = settler
        .balance_tx(rng.split(), proven_core, &RESOLVER)
        .await
        .expect("the settlement must balance");

    // Before validation, nothing is authenticated -- not even the memo we just built ourselves.
    let before = proven.memo_records();
    assert_eq!(before.len(), 1, "exactly one input carries a memo");
    assert_eq!(
        before[0].trust(),
        MemoTrust::Unverified,
        "an unvalidated transaction must yield only unverified records"
    );

    let strictness = WellFormedStrictness::default();

    // Even the canonical representation stays unverified through the generic API, including
    // every lax policy. Only the concrete complete-real entry point below owns the private trust
    // upgrade, so downstream proof-marker implementations cannot forge it.
    let generic_checked = proven
        .well_formed(&settler.ledger, strictness, settler.time)
        .expect("the canonical transaction is well formed");
    assert!(
        generic_checked
            .memo_records()
            .iter()
            .all(|r| !r.is_authenticated())
    );
    let revalidation = RevalidationReference {
        previously_validated_state: settler.ledger.clone(),
        new_state: settler.ledger.clone(),
    };
    let revalidated = proven
        .well_formed(&revalidation, strictness, settler.time)
        .expect("revalidation may reuse previously completed stateless checks");
    assert!(
        revalidated
            .memo_records()
            .iter()
            .all(|r| !r.is_authenticated()),
        "a reference that skips stateless proof checks must never mint memo authentication"
    );
    let mut lax_policies = Vec::new();
    for disable in 0..5 {
        let mut lax = WellFormedStrictness::default();
        match disable {
            0 => lax.enforce_balancing = false,
            1 => lax.verify_native_proofs = false,
            2 => lax.verify_contract_proofs = false,
            3 => lax.verify_signatures = false,
            4 => lax.enforce_limits = false,
            _ => unreachable!(),
        }
        lax_policies.push(lax);
    }
    for lax in lax_policies {
        let checked = proven
            .well_formed(&settler.ledger, lax, settler.time)
            .expect("disabling a check cannot invalidate this otherwise-valid transaction");
        assert!(
            checked.memo_records().iter().all(|r| !r.is_authenticated()),
            "generic or lax validation must never produce authenticated records"
        );
    }

    // Byte round-trip, the way a counterparty receives it.
    let mut bytes = Vec::new();
    proven.serialize(&mut bytes).expect("serialization");
    let received = <ProvenTx as Deserializable>::deserialize(&mut &bytes[..], 0)
        .expect("a settlement must round-trip");
    let mut reserialized = Vec::new();
    received
        .serialize(&mut reserialized)
        .expect("re-serialization");
    assert_eq!(bytes, reserialized, "the encoding must be canonical");
    let received_verified = received
        .well_formed(&settler.ledger, strictness, settler.time)
        .expect("the round-tripped settlement must still verify");
    assert_eq!(
        received_verified.memo_records()[0].bytes(),
        maker_memo.as_bytes(),
        "the memo must survive the round trip byte for byte"
    );
    assert_eq!(
        received_verified.memo_records()[0].trust(),
        MemoTrust::Unverified,
        "well-formedness alone is not an application verdict"
    );
    let block_context = settler.context().block_context;

    // The *same* memo bytes and carrier through a proof-invalid view must be Invalid, never
    // authenticated. Transplant only the independently funded settler's proof onto the maker;
    // unlike the tamper matrix below, this leaves the memo byte-for-byte unchanged.
    let proof_invalid = transplant_other_proof(&proven, maker_nullifier);
    let proof_invalid_error = settler
        .ledger
        .validate_apply_and_inspect_memos(&proof_invalid, &block_context)
        .expect_err("a transplanted spend proof must fail before application");
    assert!(
        matches!(
            &proof_invalid_error,
            MalformedTransaction::Zswap(zswap::error::MalformedOffer::InvalidProof(_))
        ),
        "the corpus must exercise a proof-invalid verdict, got {proof_invalid_error:?}"
    );
    let proof_invalid_records = proof_invalid.memo_records_rejected();
    assert_eq!(proof_invalid_records.len(), 1);
    assert_eq!(proof_invalid_records[0].trust(), MemoTrust::Invalid);
    assert_eq!(proof_invalid_records[0].nullifier(), maker_nullifier);
    assert_eq!(proof_invalid_records[0].bytes(), maker_memo.as_bytes());

    // A rejected proof-invalid transaction exposes the same bytes only as Invalid. Perform this
    // before application so rejection cannot be explained by the coin already being spent.
    for tampered_memo in [
        Some(memo(b"maker: selling 100_000_000, DIFFERENT terms")),
        None,
    ] {
        let still_carries_memo = tampered_memo.is_some();
        let tampered = retamper_memo(&proven, maker_nullifier, tampered_memo);
        assert!(
            settler
                .ledger
                .validate_apply_and_inspect_memos(&tampered, &block_context)
                .is_err(),
            "tampering with the maker's memo inside a settlement must be rejected"
        );
        let rejected = tampered.memo_records_rejected();
        if still_carries_memo {
            assert_eq!(rejected.len(), 1);
            assert_eq!(rejected[0].trust(), MemoTrust::Invalid);
            assert!(!rejected[0].is_authenticated());
        } else {
            assert!(
                rejected.is_empty(),
                "removing a memo leaves no attacker-supplied bytes to display; proof rejection is the evidence"
            );
        }
    }

    // Apply, and check what the chain now believes.
    let pre_nullifier_spent = settler
        .ledger
        .zswap
        .nullifiers
        .contains_key(&maker_nullifier);
    assert!(
        !pre_nullifier_spent,
        "the maker's nullifier must not be spent before application"
    );

    // The final trust result is produced by validating and applying the *round-tripped* artifact
    // as one operation. A proof-valid but state-invalid transaction never reaches Authenticated.
    let (applied_ledger, result, records) = settler
        .ledger
        .validate_apply_and_inspect_memos(&received, &block_context)
        .expect("the settlement must pass complete real validation");
    assert!(
        matches!(&result, TransactionResult::Success(..)),
        "the settlement must apply successfully, got {result:?}"
    );

    // Authentication is per carrier, and only the successful state transition produces it.
    assert_eq!(
        records.len(),
        1,
        "the settler contributed no memo, so exactly one record exists: {records:?}"
    );
    let record = &records[0];
    assert!(
        record.is_authenticated(),
        "a fully applied settlement must authenticate its memo: {record:?}"
    );
    assert_eq!(record.nullifier(), maker_nullifier);
    assert_eq!(record.bytes(), maker_memo.as_bytes());
    assert!(record.ledger_version().contains("v13"));
    assert!(
        record
            .render_inert()
            .starts_with("[authenticated] memo for nullifier ")
    );

    settler.zswap = settler
        .zswap
        .replay_events(&settler.zswap_keys, result.events())
        .expect("the successfully applied settlement must replay into the settler wallet");
    settler.ledger = applied_ledger;

    assert!(
        settler
            .ledger
            .zswap
            .nullifiers
            .contains_key(&maker_nullifier),
        "the maker's coin must be spent after application"
    );
    assert!(
        settler
            .ledger
            .zswap
            .nullifiers
            .contains_key(&settler_nullifier),
        "the independently merged settler leg must also be applied"
    );
    assert!(
        settler.zswap.coins.iter().any(|(_, coin)| {
            coin.nonce == payout.nonce && coin.value == maker_value && coin.type_ == token
        }),
        "the settler must now hold the maker's value"
    );
    assert!(
        settler.zswap.coins.iter().any(|(_, coin)| {
            coin.nonce == settler_refund.nonce && coin.value == settler_value && coin.type_ == token
        }),
        "the settler's independent shielded input must produce its refund output"
    );
}

/// Several makers, each with their own memo, settle together -- including two carrying byte-for-byte
/// identical memos.
///
/// Equal bytes on distinct carriers is the case an implementation that keyed authenticity on the
/// memo rather than on the carrying input would get wrong, by crediting one maker's message to the
/// other. Each record must name its own nullifier.
#[tokio::test]
async fn several_memos_including_identical_bytes_authenticate_independently() {
    let mut rng = StdRng::seed_from_u64(0x33ee);
    let mut settler: TestState<InMemoryDB> = TestState::new(&mut rng);
    settler.give_fee_token(&mut rng, 10).await;

    let token: ShieldedTokenType = Default::default();
    let value = 40_000_000u128;

    // Two independent makers. Both say exactly the same thing.
    let shared_text = b"maker: filling at the posted price".to_vec();
    // Fund both makers first, keeping the whole event history. A local zswap state rebuilds the
    // commitment tree by insertion order, so each maker has to replay everything from the start,
    // not just the events that mention its own coin -- replaying only its own would try to insert
    // at index 1 into an empty tree.
    let mut keys_list = Vec::new();
    let mut history = Vec::new();
    for _ in 0..2 {
        let keys = SecretKeys::from_rng_seed(&mut rng);
        history.extend(mint_shielded_to(&mut settler, &mut rng, &keys, token, value).await);
        keys_list.push(keys);
    }
    let mut makers = Vec::new();
    for keys in keys_list {
        let local = ZswapLocalState::<InMemoryDB>::new()
            .replay_events(&keys, history.iter())
            .expect("maker must replay the chain history");
        makers.push((keys, local));
    }

    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut nullifiers = Vec::new();
    for (keys, local) in makers.iter_mut() {
        let coin = *local.coins.iter().next().expect("maker must hold a coin").1;
        assert_eq!(coin.value, value);
        let (next, input) = local
            .spend_with_memo(&mut rng, keys, &coin, Some(0), Some(memo(&shared_text)))
            .expect("maker spend with memo");
        *local = next;
        nullifiers.push(input.nullifier);
        inputs.push(input);

        let payout = CoinInfo {
            nonce: rng.r#gen(),
            value,
            type_: token,
        };
        outputs.push(
            Output::new(
                &mut rng,
                &payout,
                Some(0),
                &settler.zswap_keys.coin_public_key(),
                Some(settler.zswap_keys.enc_public_key()),
            )
            .expect("payout output"),
        );
    }

    let mut offer = Offer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();

    let tx: UnprovenTx = Transaction::new(
        "local-test",
        storage::storage::HashMap::new(),
        Some(offer),
        storage::storage::HashMap::new(),
    );
    let proven_core = tx_prove_bind(rng.split(), &tx, &RESOLVER)
        .await
        .expect("settlement must prove");
    let proven = settler
        .balance_tx(rng.split(), proven_core, &RESOLVER)
        .await
        .expect("settlement must balance");

    // Identical bytes do not couple the proofs: changing only one carrier invalidates the whole
    // settlement while the other carrier remains byte-for-byte untouched.
    let tampered = retamper_memo(
        &proven,
        nullifiers[0],
        Some(memo(b"one maker changed this independently")),
    );
    let block_context = settler.context().block_context;
    assert!(
        settler
            .ledger
            .validate_apply_and_inspect_memos(&tampered, &block_context)
            .is_err(),
        "mutating one participant's memo must reject the complete transaction"
    );

    let (applied, result, records) = settler
        .ledger
        .validate_apply_and_inspect_memos(&proven, &block_context)
        .expect("a settlement with two identical memos must verify");
    assert!(matches!(&result, TransactionResult::Success(_)));
    assert_eq!(records.len(), 2, "one record per memo-bearing input");
    assert!(records.iter().all(|r| r.is_authenticated()));
    assert!(
        records.iter().all(|r| r.bytes() == &shared_text[..]),
        "both makers said the same thing"
    );

    let attributed: Vec<_> = records.iter().map(|r| r.nullifier()).collect();
    assert_ne!(
        attributed[0], attributed[1],
        "identical bytes must not collapse into one carrier"
    );
    for nullifier in &nullifiers {
        assert!(
            attributed.contains(nullifier),
            "every maker's nullifier must appear exactly once in the records"
        );
    }

    settler.ledger = applied;
    for nullifier in &nullifiers {
        assert!(
            settler.ledger.zswap.nullifiers.contains_key(nullifier),
            "each maker's coin must be spent"
        );
    }
}

/// A settlement containing the same nullifier twice, with *different* memos on the two copies,
/// must be rejected with a structured error rather than applied.
///
/// Differing memos are what makes the two inputs distinct values, so normalization will not
/// deduplicate them and the duplicate has to be caught by the spend rules. If it were not, the
/// pair would look like two independently authenticated messages from one coin.
#[tokio::test]
async fn duplicate_nullifier_with_differing_memos_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0xd0b1);
    let mut settler: TestState<InMemoryDB> = TestState::new(&mut rng);
    settler.give_fee_token(&mut rng, 10).await;

    let token: ShieldedTokenType = Default::default();
    let value = 50_000_000u128;
    let maker_keys = SecretKeys::from_rng_seed(&mut rng);
    let events = mint_shielded_to(&mut settler, &mut rng, &maker_keys, token, value).await;
    let maker_zswap = ZswapLocalState::<InMemoryDB>::new()
        .replay_events(&maker_keys, events.iter())
        .expect("maker must replay its funding");
    let coin = *maker_zswap
        .coins
        .iter()
        .next()
        .expect("maker must hold a coin")
        .1;

    // The same coin spent twice, saying two different things.
    let (_, first) = maker_zswap
        .spend_with_memo(
            &mut rng,
            &maker_keys,
            &coin,
            Some(0),
            Some(memo(b"first claim on this coin")),
        )
        .expect("first spend");
    let (_, second) = maker_zswap
        .spend_with_memo(
            &mut rng,
            &maker_keys,
            &coin,
            Some(0),
            Some(memo(b"second, contradictory claim")),
        )
        .expect("second spend");
    assert_eq!(
        first.nullifier, second.nullifier,
        "the same coin must produce the same nullifier"
    );
    let duplicated_nullifier = first.nullifier;
    assert_ne!(
        first.memo(),
        second.memo(),
        "the two copies differ only by memo, which is what keeps them distinct values"
    );

    let payout = CoinInfo {
        nonce: rng.r#gen(),
        value: value * 2,
        type_: token,
    };
    let payout_output = Output::new(
        &mut rng,
        &payout,
        Some(0),
        &settler.zswap_keys.coin_public_key(),
        Some(settler.zswap_keys.enc_public_key()),
    )
    .expect("payout output");

    let mut offer = Offer {
        inputs: vec![first, second].into(),
        outputs: vec![payout_output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    offer.normalize();

    let tx: UnprovenTx = Transaction::new(
        "local-test",
        storage::storage::HashMap::new(),
        Some(offer),
        storage::storage::HashMap::new(),
    );
    let proven_core = tx_prove_bind(rng.split(), &tx, &RESOLVER)
        .await
        .expect("proving a doomed settlement should still succeed");
    let proven = settler
        .balance_tx(rng.split(), proven_core, &RESOLVER)
        .await
        .expect("balancing a doomed settlement should still succeed");

    // Both individual proofs are valid, so complete validation reaches application. The second
    // insertion of the same nullifier must then fail with the exact structured double-spend
    // verdict, and the functional state transition must roll the whole guaranteed segment back.
    let before_hash = settler.ledger.state_hash();
    let before_coin_tree = settler.ledger.zswap.coin_coms.clone();
    let before_first_free = settler.ledger.zswap.first_free;
    assert!(
        !settler
            .ledger
            .zswap
            .nullifiers
            .contains_key(&duplicated_nullifier)
    );

    let block_context = settler.context().block_context;
    let (after, result, records) = settler
        .ledger
        .validate_apply_and_inspect_memos(&proven, &block_context)
        .expect("the duplicate is an application conflict, not a catch-all validation failure");
    match &result {
        TransactionResult::Failure(LedgerTransactionInvalid::Zswap(
            zswap::error::TransactionInvalid::NullifierAlreadyPresent(actual),
        )) => assert_eq!(*actual, duplicated_nullifier),
        other => panic!("expected the exact duplicate-nullifier application error, got {other:?}"),
    }
    assert_eq!(records.len(), 2, "both rejected claims remain inspectable");
    assert!(
        records
            .iter()
            .all(|record| record.trust() == MemoTrust::Invalid),
        "a proof-valid but application-invalid transaction must authenticate no memo: {records:?}"
    );
    assert_eq!(
        after.state_hash(),
        before_hash,
        "a failed guaranteed segment must leave the complete ledger state unchanged"
    );
    assert!(
        !after.zswap.nullifiers.contains_key(&duplicated_nullifier),
        "neither copy of the duplicated spend may be committed"
    );
    assert_eq!(
        after.zswap.coin_coms, before_coin_tree,
        "failed application must create no shielded outputs"
    );
    assert_eq!(
        after.zswap.first_free, before_first_free,
        "failed application must not advance the output tree"
    );
}
