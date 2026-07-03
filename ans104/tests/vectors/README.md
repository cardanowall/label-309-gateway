# ANS-104 golden vectors

Cross-implementation test vectors for the `ans104` crate. They are produced by
the reference JavaScript implementation (`@dha-team/arbundles` 1.0.4 +
`arweave-js` 1.15.7) so the Rust crate can be checked against an independent,
widely deployed encoder/signer. The generator lives in `../../tools` and is
re-runnable:

```
cd ../../tools
npm install
npm run generate
```

## What is stable, and what is not

The test key (`test-jwk.json`) is committed, so re-running the generator
reproduces the same key-derived bytes. The following fields are **byte-stable**
across runs and MUST be byte-compared by the Rust side:

- `owner_hex` — the 512-byte RSA modulus (the data item's `owner`).
- `tags_avro_hex` — the Avro tag frame.
- `deep_hash_hex` — the 48-byte SHA-384 deep-hash that the signature covers
  (the signed message digest).
- `raw_len`, `data_len`, `data_sha256_hex`, `target_hex`, `anchor_hex` and the
  overall data-item layout.

The RSA-PSS signature is **not** stable. PSS draws a fresh random salt for every
signature, so `signature_hex` and the item id derived from it (`id_b64url`)
change on every run. They are recorded only as a per-run snapshot. The Rust side
MUST **verify** signatures (recompute the deep-hash, then check RSA-PSS against
the embedded owner key), never byte-compare them. The id is checked as
`base64url(SHA-256(signature))`, recomputed from whatever signature the item
carries, not compared against `id_b64url`.

`salt_len` records the salt length the reference signer emitted (478 bytes, the
maximum for RSA-4096 + SHA-256). arweave-js signs with the maximum salt and
verifies with salt-length auto-detect, so a conforming verifier should accept
any valid PSS salt length, not require a fixed one.

## test-jwk.json

A throwaway, **valueless** 4096-bit Arweave RSA test key, generated once and
committed so the vectors are reproducible. It guards nothing and holds nothing:
it exists only to sign these fixtures with a deterministic owner. Do not treat
it as a secret and do not reuse it for anything real.

## Vector files

Each signed vector is a pair: `<name>.bin` (the raw signed data-item bytes) and
`<name>.json` (its sidecar metadata). The data payload is deterministic:
`b[i] = (i * 7 + 13) mod 256`.

Sidecar fields: `generator_versions`, `sig_type`, `owner_hex`, `target_hex`,
`anchor_hex`, `tags` (decoded name/value pairs), `tags_avro_hex`, `data_len`,
`data_sha256_hex`, `signature_hex`, `id_b64url`, `deep_hash_hex` (the signed
message digest), `raw_len`, `salt_len`.

Tag-shape vectors:

- `empty_tags` — no tags; `tags_avro_hex` is the zero-length frame.
- `minimal_gateway_tags` — a typical gateway tag set (app name/version, a fixed
  `Unix-Time`, content type). The timestamp is a constant literal, never a clock
  read, so the vector stays reproducible.
- `unicode_tags` — multi-byte UTF-8 in names and values.
- `tag_bytes_4096_boundary` — a tag list whose Avro frame is exactly 4096 bytes,
  the largest the format accepts.
- `tag_bytes_4097_reject` — JSON only, no `.bin`. One byte over the limit. Both
  the encoder (`serializeTags`) and the parser/verifier (`DataItem.verify`)
  reject it; the sidecar records the thrown error and the verify rejection so
  the Rust side can assert the same boundary.

Target/anchor presence vectors: `target_only`, `anchor_only`,
`target_and_anchor`, `neither`.

Data-length vectors: `data_0` (zero-byte payload), `data_1`, `data_511`,
`data_512`, `data_100000`.

## deep-hash-kats.json

Known-answer tests for the recursive SHA-384 deep-hash, independent of the
data-item framing. A blob hashes as `H(H("blob" || ascii(len)) || H(blob))`; a
list of length `n` folds each child into an accumulator seeded with
`H("list" || ascii(n))`. Inputs cover an empty blob, a `"hello"` blob, a 1 KiB
deterministic blob, an empty list, an `["a", "b"]` blob list, and a nested list
`[["a"], ["b", "c"]]`.
