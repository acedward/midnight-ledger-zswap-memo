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
| At most one memo per offer | Merging is permissionless. Without this rule, a third party holding any spendable coin — including a zero-value one, which does not perturb the offer's deltas — could merge a memo-carrying input into a republished copy of someone else's offer. Each memo would still be authorized by *its own* spender, but a reader could not tell which memo was the maker's. **This is the most debatable default**: it also makes merging two memo-carrying offers invalid, which is the intended semantics for offer files (one maker, one memo) but forecloses other uses. Worth an explicit decision before this ships. |
| Memo priced by size only | Memo bytes flow into `serialized_size` → `est_size` → `block_usage` → fees, and into the 1 MiB transaction limit, with no new code. The verifier-side hashing cost is *not* modelled; a `TODO(zswap-memo)` in `ledger/src/structure.rs` marks it. |

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
