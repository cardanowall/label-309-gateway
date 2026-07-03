# cardano-poe-tx

A deterministic builder for Cardano transactions that carry a Proof-of-Existence
record under transaction metadata **label 309**. Given a record payload, a set
of spendable UTxOs, the current protocol parameters, a change address, and the
payment verification key, it performs deterministic coin selection, computes the
exact linear fee, folds or adds inputs until the change output clears the
minimum-ADA threshold, and emits an unsigned transaction whose body is
byte-for-byte reproducible from the same inputs. A separate signing step
witnesses the body with an Ed25519 transaction witness over its Blake2b-256 hash,
occupying exactly the byte budget the fee already accounted for, so signing never
changes the body, the fee, or the transaction id.

The builder is intentionally side-effect free: it never queries a node, never
reads a clock, never draws randomness, and never picks fee parameters of its
own. Every input that influences the resulting bytes (`min_fee_a`, `min_fee_b`,
`coins_per_utxo_byte`, the candidate UTxO set, the optional validity interval,
the verification key) is supplied by the caller. Coin selection is a pure
function of the candidate set (largest lovelace first, ties broken by
transaction-hash bytes then output index), so two callers with the same
`BuildRequest` always get the same `BuiltPoeTx` regardless of the order their
UTxOs happen to be listed in. That determinism is what makes the output testable
against an independent oracle and what lets a gateway reproduce, audit, and
re-sign a transaction without trusting the builder.

The single network entry point, a `preprod-smoke` binary behind the `smoke`
feature, reuses the exact same build function against a live Koios endpoint; the
library itself links no HTTP stack.
