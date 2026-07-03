# Builder oracle

An out-of-tree reference oracle for the deterministic Cardano label-309
transaction builder. It rebuilds each corpus case with two independent encoders
and compares the result against the builder's own output, so a fee or encoding
mistake in the builder cannot hide behind a self-consistent test.

## Why two oracles

The builder is meant to produce one specific transaction for each input. The
only way to know it produced the _right_ one is to have an unrelated
implementation produce the same bytes. A single reference would only tell you
the two agree, not which is correct, so this tool runs two references with
different strengths.

### CSL: the fee and encoding oracle

The Cardano Serialization Library is a low-level CBOR encoder. The oracle uses
it in two roles:

- **Fee floor over the exact bytes.** It parses the builder's unsigned
  transaction verbatim, attaches the single fixed-width Ed25519 vkey witness the
  builder will add, and asks CSL for its **own minimum fee** for those exact
  bytes under the corpus linear-fee parameters. This is the floor that guards
  against `FeeTooSmallUTxO`: the builder's fee must be at least this value, and
  by construction it always is, because the builder meters its fee over the very
  bytes it submits.

- **Structural re-encode.** It also re-encodes the body from the builder's
  decisions (inputs, change, validity, label-309 auxiliary data). CSL
  canonicalises to the pre-Babbage forms, so this body is intentionally not
  byte-identical to the builder's; the structural diff classifies exactly where
  they differ.

CSL does no coin selection of its own; it only re-prices and re-encodes the
builder's decisions, which is what makes it a clean oracle rather than a second
opinion.

### Lucid Evolution: the behaviour-parity oracle

Lucid Evolution is the same library the production publish path drives. Building
each case through it, offline, pins the builder to the exact bytes that path
would have submitted to a node. Where CSL answers "are these bytes a valid,
correctly-priced encoding of these decisions", Lucid answers "would the
production path have produced these decisions and these bytes". The two together
cover both correctness and parity.

Lucid is driven through a synthetic provider that serves the corpus protocol
parameters and answers every network query from memory. It never opens a socket:
any provider method the offline build does not legitimately need throws, so a
regression that starts reaching for the network fails loudly instead of silently
going online.

## What the report contains

For each case the tool writes `out/<name>.json`:

| Field                | Meaning                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| `fee_rust`           | the fee the builder charged (from its manifest), or `null` in fallback mode      |
| `fee_csl_min`        | CSL's minimum fee for the builder's exact transaction bytes (the fee floor)      |
| `fee_lucid`          | the fee Lucid charged building the same case, or `null` for a no-change fold     |
| `fee_csl_floor_ok`   | whether the builder fee is at least the CSL floor (guards `FeeTooSmallUTxO`)     |
| `fee_csl_exact`      | whether the builder fee equals the floor exactly (false by the output-width gap) |
| `fee_lucid_equal`    | whether the builder fee equals Lucid's, where Lucid could build the case         |
| `lucid_status`       | `built`, or `no-change-fold` when the fold shape is outside what Lucid produces  |
| `bytes_equal_csl`    | whether CSL's re-encoded body bytes equal the manifest's body bytes              |
| `bytes_equal_lucid`  | whether Lucid's transaction bytes equal the manifest's unsigned transaction      |
| `csl_aux_data_hash`  | the label-309 auxiliary-data hash CSL's legacy re-encode derived                 |
| `csl_tx_hash`        | the Blake2b-256 of CSL's re-encoded body (an independent transaction id)         |
| `divergence_classes` | the semantic divergence classes present, deduplicated and sorted                 |
| `divergences`        | every structural difference, with its raw `kind`, `path`, and semantic `class`   |

A divergence carries a raw `kind`, a `path` into the decoded CBOR, and a
semantic `class`. The raw kinds are `tag-258`, `int-width`, `map-ordering`,
`field-presence`, `value`, and `type`. The semantic classes name the known
Conway-vs-legacy encoding differences the builder is expected to exhibit:

- `network-id` — the builder writes the body `network_id` field; the legacy
  re-encode omits it.
- `output-format` — the builder emits the post-Babbage map output
  `{0: address, 1: value}`; the legacy re-encode uses the `[address, value]`
  array.
- `aux-data-format` — the builder hashes the Conway tag-259 auxiliary data; the
  legacy re-encode hashes the untagged Shelley metadata map.

Anything the classifier does not recognise keeps its raw kind, so a genuinely
new divergence never hides inside a known class. The committed, pinned summary
of these classes lives at `tests/fixtures/oracle/parity-report.json` and is
asserted by `tests/parity_report.rs`.

Both inputs are decoded with the set tag preserved (rather than collapsed into a
JavaScript `Set`) and with maps kept as `Map` objects, so key order and integer
keys survive the diff.

## Determinism

Every input to a build is fixed:

- record bytes come from the formula `b[i] = (i * 7 + 13) mod 256`, so only the
  record length varies between cases;
- UTxO identities and protocol parameters come from the corpus;
- no step touches the network.

Two runs over the same corpus and the same manifests produce byte-identical
reports.

## Running

```sh
npm install                       # standalone install, outside the workspace
node generate-oracle.mjs          # compare every case that has a builder manifest
node generate-oracle.mjs --case size_64
```

Manifests live next to the corpus inputs under
`tests/fixtures/corpus/rust-out/<name>.json` and carry the builder's selected
inputs, fee, body and transaction bytes, hashes, size, and change. The tool
exits non-zero only on a real builder failure: a case whose fee falls below the
CSL fee floor for its exact bytes, or a structural divergence outside the three
documented Conway-vs-legacy classes. Byte inequality against the legacy oracles
alone is expected and does not fail the run, because the builder deliberately
emits the modern Conway encoding the oracles cannot reproduce. A full-corpus
manifest run also rewrites `tests/fixtures/oracle/parity-report.json`.

### Self-test fallback

Before the builder emits manifests, run:

```sh
node generate-oracle.mjs --selection-from-corpus
```

This reimplements a greedy coin selection in JavaScript (largest value first,
ties broken by `tx_hash` ascending then index ascending) purely so the oracle
can run end-to-end and prove its CSL and Lucid plumbing works. The fallback
selection is **not** the reference and its choices carry no authority: it uses a
coarse fee floor rather than the builder's exact fold-or-add change logic, so its
fees deliberately do not match Lucid's. The authoritative comparison only runs
against real manifests. The fallback never reports a failure, because in this
mode there is no builder output to disagree with.

Cases the corpus marks `insufficient_funds` have no transaction to build and are
recorded as skipped.

## Layout note

This tool installs its own dependencies under `node_modules/` here, separate
from the repository's package manager, because it pins specific encoder versions
(CSL on its last pre-16 stable line, Lucid Evolution matching the production
build path). Both `node_modules/` and the generated `out/` reports are ignored.
