# ZSwap input memos — implementation notes

Branch `feat/zswap-input-memo`, based on `4823b535` (tag `ledger-9.1.0.0-rc.3`).

## What the change is

`Input` gains `memo: Option<Sp<Memo, D>>`. A commitment to the memo is placed in the spend
proof's `binding_input` — the proof's first public input, which the circuit leaves
unconstrained and which ZSwap inputs previously hardcoded to zero. ZSwap *outputs* have always
used the same slot to bind their coin ciphertext; this reuses that mechanism on the input side.

Because the slot is unconstrained, **no circuit, proving key, verifying key, or trusted-setup
change is needed**. `u1_memo_input_verifies_against_shipped_verifier_key` proves a memo-carrying
spend and verifies it against the shipped `static/spend.verifier`, which is the direct test of
that claim. `prove::tests::test_pi_lengths` continues to pass, confirming the public-input count
is unchanged (`INPUT_PIS == 68`).

Two properties follow:

- **Integrity.** Any change to the memo — altering, removing, adding, or moving it to another
  input — changes the statement and the proof no longer verifies.
- **Authorization.** The spend circuit proves knowledge of the coin's secret key, so only a
  party who can produce that proof can attach a memo. No public key or signature is revealed.

## Decisions

| Decision | Rationale |
| --- | --- |
| `Memo(Vec<u8>)`, 1..=512 bytes, tag `zswap-memo[v1]` | Opaque to the ledger; whether the bytes are plaintext or ciphertext is an application concern. The bound keeps memos from being the cheapest way to put data on chain. |
| Empty memos invalid | `None` and `Some(empty)` would otherwise be two spellings of "no memo" with different commitments, and the zero sentinel would need to be distinguished from a memo that happens to commit to zero. Rejecting empty removes the question. |
| Memos forbidden on contract-owned inputs | The spend circuit takes `Either<ZswapCoinSecretKey, ContractAddress>`. On the contract branch there is no user secret, so "authorized by the spending secret" degrades to "authored by whoever assembled the call". Rather than ship a weaker guarantee under the same name, the case is rejected. |
| No memo on `Transient` | A transient's coin is created and spent in one transaction, so there is no offer for a message to accompany. `as_input()` yields `memo: None`. |
| Any number of memos per offer, at most one per input | One per input is structural — `Input::memo` is a single field. The ledger does **not** try to nominate one of them as "the offer's" message. See the discussion below. |
| Memo priced by size only | Memo bytes flow into `serialized_size` → `est_size` → `block_usage` → fees, and into the 1 MiB transaction limit, with no new code. The verifier-side hashing cost is *not* modelled; a `TODO(zswap-memo)` in `ledger/src/structure.rs` marks it. |

### Why the ledger permits several memos

An earlier revision of this branch enforced at most one memo per offer, on the reasoning that
merging is permissionless: a third party holding any spendable coin — including a zero-value one,
which does not perturb the offer's deltas because `normalize_deltas` drops zero entries — can
merge a memo-carrying input into a republished copy of someone else's offer, leaving a reader
unable to tell which memo was the maker's.

That rule was removed, for two reasons.

**It broke the main use case.** Merging is not an edge case, it is the settlement mechanism.
Batch settlement (coincidence of wants) merges many parties' offers into a single transaction,
and every party may legitimately have something to say. A rule that makes two memo-carrying
offers unmergeable forecloses that outright. Note also that merging cannot strip a memo even in
principle: removing one drops that input's statement back to the zero sentinel and invalidates
its proof. So there is no "reconcile at merge" escape hatch — the validity rule was the only
lever, and it was pointed at the wrong thing.

**It was buying less than it cost.** Authorship is *already* unambiguous cryptographically. A
memo is bound into its own input's proof alongside that input's nullifier, so it cannot be moved
between inputs (`memo_cannot_be_swapped_between_inputs`), and a memo is a field *on* an input —
there is no `offer.memo` to misread. What the rule actually protected against was software
treating "some memo in this offer" as "the offer's message". That is a question about a
particular artifact's semantics, not about consensus.

So the constraint belongs at the layer where "one maker, one message" is actually true: a
published offer file is a single maker's advertisement, and its decoder should require exactly
one memo. Once offers are merged into a settlement transaction, that artifact is no longer an
offer file and several memos are correct.

Rejected alternative: nominating a designated input (say, the lowest nullifier) as the one whose
memo "counts". A nullifier is a hash of the coin and secret key, so an attacker can grind nonces
over their own coins until they hold the lowest nullifier in a merged offer and thereby capture
the designated slot. That converts a visible ambiguity into a silent hijack.

## Where the code is

| Concern | Location |
| --- | --- |
| `Memo`, `MAX_MEMO_BYTES`, `Input.memo` | `zswap/src/structure.rs` |
| `memo_to_field`, `memo_statement_element` | `zswap/src/lib.rs` |
| Binding input set at construction | `zswap/src/construct.rs`, `Input::new_from_secret_key` |
| Statement element at verification | `zswap/src/verify.rs`, `Input::<Proof, _>::well_formed` |
| Structural rules | `zswap/src/verify.rs`, `memos_well_formed` |
| Public API | `zswap/src/local.rs`, `State::spend_with_memo` |
| Tests | `zswap/src/memo_tests.rs` |

**Construction and verification derive the statement's first element through the single
`memo_statement_element` function.** They must agree exactly: a divergence would be a consensus
split rather than a local bug, so there is deliberately no second implementation.

### Memo commitment

`memo_to_field` mirrors `ciphertext_to_field`. The bytes are packed into field elements 31 at a
time (one below the 32-byte field width, so every chunk is below the modulus), prefixed with the
byte length, and committed under the domain separator `midnight:zswap-memo[v1]`.

The length prefix is what makes the packing injective — the final chunk is zero-padded, so
without it a memo and the same memo followed by zero bytes would commit to the same value.
`memo_commitment_is_injective_over_trailing_zeros` pins this.

## Wire format

Tags bump `zswap-input[v2]` → `[v3]`, cascading to `zswap-offer[v5]` → `[v6]`,
`standard-transaction[v12]` → `[v13]`, and `transaction[v12]` → `[v13]`. The tag-decomposition
tests confirm this is the complete set: exactly five new files under `.tag-decompositions/`
(the four bumps plus `zswap-memo[v1]`) and no existing file changed.

This is backwards-incompatible in both directions that matter — a non-upgraded node cannot
decode the new format, and the validity rules differ — so it needs a coordinated upgrade.
Memo-less inputs compute `statement[0] = 0` exactly as before, so history stays valid and the
change is a rule change rather than a cryptographic one.

## Workspace layout

The workspace is trimmed to `zswap` and `ledger`, and their internal `path` dependencies have
been stripped — the same treatment upstream's per-crate release tags get. A consumer patching
these two crates by path therefore resolves every *other* dependency normally instead of
dragging this whole workspace in. The root `[patch.crates-io]` points them back at the local
crates so this workspace still builds and tests as one unit, and mirrors midnight-node's own
patch table so what is tested here is what the node builds.

This matters concretely: the published `midnight-storage-core 1.2.0` is not the same source as
the `1.2.0` in this tree, and patching it by path breaks the `midnight-storage 1.1.1` that the
ledger-7 stack still resolves from crates.io.

## Running the tests

```bash
cargo test -p midnight-zswap --release     # includes U1 and the tamper matrix
cargo test -p midnight-ledger-v9 --release # tag cascade, transaction-level tests
```

The proving tests need the ZSwap proving keys, fetched on demand from `srs.midnight.network`
and cached under `$MIDNIGHT_PP` (or `~/.cache/midnight/zk-params`). The first run needs network
access; later runs do not.

## Not done

- **Cost-model calibration** for the memo hashing cost (`TODO(zswap-memo)`).
- **`ledger-wasm` / TypeScript surface.** The memo is not exposed to the JS SDK, so wallets and
  the indexer cannot read or set one yet. midnight-node does not consume `ledger-wasm`, so this
  was out of scope here, but it is required before any wallet integration.
- **Fuzzing** of the memo deserializer. The length is checked before allocation and unit tests
  cover the boundaries, but there is no fuzz target.
- **The amending MIP** for MIP-0005/0006, and in particular a decision on the one-memo-per-offer
  rule above.
- **Privacy guidance.** Plaintext memos deanonymize by content, and memo length leaks even when
  encrypted. The ledger is deliberately agnostic; the application layer needs a position on
  ciphertext-by-default and length padding.
