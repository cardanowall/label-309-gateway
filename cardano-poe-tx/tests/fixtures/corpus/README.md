# Builder corpus

Shared input fixtures for the deterministic Proof-of-Existence transaction
builder. Each file under `inputs/` is one build scenario. The Rust test suite
consumes these inputs and an out-of-tree Node oracle consumes the identical
files, so a single corpus pins both implementations to the same expected bytes.

## Why inputs only

The fixtures store the _inputs_ to a build, never a hard-coded expected
transaction. Expected bytes are derived: the Rust harness builds the
transaction from the input and the Node oracle builds it independently, and the
two outputs are compared. Storing pre-baked output would let a bug in the test
harness be frozen into the fixture; deriving it on both sides instead makes the
two implementations check each other.

## Deterministic data rules

So that no field is arbitrary and both languages reconstruct identical bytes:

- **Record bytes.** Only `record_len` is stored. The record itself is
  materialised as `b[i] = (i * 7 + 13) mod 256`. Both sides generate it from
  this formula, so the record is reproducible from a single integer.
- **UTxO tx hash.** Each UTxO's `tx_hash` is
  `sha256("corpus:" + name + ":" + index)`, hex-encoded, where `name` is the
  fixture name and `index` is the UTxO's output index. This gives every UTxO a
  stable, collision-free identity that is a pure function of the fixture, with
  no random material to drift between regenerations. The hash also feeds the
  selection tie-break (value first, then `tx_hash` bytes, then index), so the
  selected subset is fully determined by the fixture.
- **Fixed environment.** `change_address` and `network_id` are the same testnet
  values across the whole corpus, and `protocol` carries the same linear-fee and
  min-ADA parameters, so the only variables between cases are the record length,
  the UTxO set, the selection `mode`, and the optional `validity` interval.

## Schema

Each input file is:

```json
{
  "name": "size_64",
  "mode": "standard" | "exact_fit",
  "protocol": {
    "min_fee_a": 44,
    "min_fee_b": 155381,
    "coins_per_utxo_byte": 4310,
    "max_tx_size": 16384
  },
  "record_len": 64,
  "utxos": [{ "tx_hash": "<64-hex>", "index": 0, "lovelace": 6000000 }],
  "validity": null | { "invalid_hereafter": 100000000, "valid_from": null | 50000000 },
  "expect": "ok" | "insufficient_funds",
  "change_address": "addr_test1...",
  "network_id": 0
}
```

## Cases

| Fixture                          | What it pins                                                                                                                                                                                                                                                                                   |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `size_1` … `size_14000`          | A length sweep across the 64-byte metadata chunk boundary (1, 63, 64, 65, 127, 128, 129) and far beyond it (1024, 4096, 14000), each funded by five 6 ADA UTxOs, to exercise single- and multi-chunk metadata encoding and growing transaction size.                                           |
| `multi_input`                    | Four 1.5 ADA UTxOs force selection of more than one input.                                                                                                                                                                                                                                     |
| `change_below_min_ada_fold`      | A single 0.85 ADA UTxO leaves post-fee change below min-ADA with no further input available, so the leftover folds into the fee and no change output is emitted.                                                                                                                               |
| `change_below_min_ada_add_input` | Two ~1 ADA UTxOs: the larger one used alone leaves sub-min-ADA change, so the builder pulls in the second and emits a valid change output instead of folding.                                                                                                                                  |
| `exact_fit`                      | The exact-fit selection mode over five 6 ADA UTxOs.                                                                                                                                                                                                                                            |
| `ttl_set`                        | A TTL-only validity interval (`invalid_hereafter`).                                                                                                                                                                                                                                            |
| `ttl_and_valid_from`             | Both a TTL and a lower validity bound (`valid_from`).                                                                                                                                                                                                                                          |
| `insufficient`                   | A single 0.2 ADA UTxO cannot cover fee plus min-ADA change; expects `insufficient_funds`.                                                                                                                                                                                                      |
| `competing_a` / `competing_b`    | `competing_b` is `competing_a` minus one UTxO. Because selection is a pure function of the candidate set (value first, ties broken by `tx_hash` then index), the two select different inputs, which pins that the build is deterministic and independent of the order the UTxOs are listed in. |

## Regenerating

Run `generate.py` from this directory after changing the case set, and commit
the resulting `inputs/*.json`. The generator is the authority for the rules
above.
