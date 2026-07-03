# Oracle parity report

`parity-report.json` is the committed, classified record of how the builder's
transactions differ from the two independent encoders the out-of-tree Node
oracle runs (Cardano Serialization Library and Lucid Evolution).

Byte-for-byte equality with those encoders is the goal, but both predate the
Conway-era canonical transaction encoding and re-serialise three fields in their
legacy forms. The builder emits the modern Conway forms, so its bytes diverge
from the oracles in a small, fixed, fee-neutral set of ways. This file pins that
set; `tests/parity_report.rs` is its guard.

## The three divergence classes

| Class             | Builder (modern Conway)                       | CSL / Lucid (legacy)          |
| ----------------- | --------------------------------------------- | ----------------------------- |
| `network-id`      | sets the body `network_id` field (key 15)     | omits it                      |
| `output-format`   | post-Babbage map output `{0: addr, 1: value}` | legacy `[addr, value]` array  |
| `aux-data-format` | Conway tag-259 auxiliary data                 | untagged Shelley metadata map |

None of the three changes the fee the builder charges relative to the ledger's
linear fee over its **own exact bytes**: every case carries
`fee_csl_floor_ok: true`, meaning the builder's fee is at least CSL's minimum
fee for the exact transaction it submits, so it can never be rejected with
`FeeTooSmallUTxO`. The `output-format` map output is two bytes larger than the
legacy array, so the builder's fee sits a few lovelace above CSL's re-encoded
floor; that headroom is the builder over-covering its own larger, valid bytes.

`change_below_min_ada_fold` carries no `output-format` divergence because it
folds the whole input into the fee and emits no output, and its `lucid_status`
is `no-change-fold` because Lucid's balancer cannot reproduce a no-change shape.

## Regenerating

```sh
cd ../../tools/oracle
npm install
node generate-oracle.mjs
```

A full-corpus manifest run rewrites this file. The run exits non-zero (and the
report is not trusted) if any case's fee falls below the ledger floor or if a
divergence appears outside the three classes above. After regenerating, run
`cargo test -p cardano-poe-tx --test parity_report` to confirm the live builder
still exhibits exactly the structural facts the report claims.
