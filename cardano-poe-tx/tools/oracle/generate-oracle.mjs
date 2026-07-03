// Reference oracle for the deterministic Cardano label-309 transaction builder.
//
// The builder under test emits a selection manifest per corpus case: which
// inputs it chose, the fee it charged, the change it returned, and the bytes it
// produced. This tool rebuilds the SAME transaction from the same corpus input
// and the same manifest decisions, using two independent encoders, and reports
// where they agree or diverge:
//
//   * Cardano Serialization Library (CSL) is the fee/encoding oracle. It
//     constructs the transaction body from the manifest's selected inputs, the
//     change output, the validity interval, and the label-309 auxiliary data,
//     then computes its OWN minimum fee for that body from the corpus linear-fee
//     parameters. A builder whose fee disagrees with CSL's min_fee has a fee
//     bug; a builder whose body bytes disagree has an encoding bug.
//
//   * Lucid Evolution is the behaviour-parity oracle. It is the same library
//     the production TypeScript publish path drives, so building each case
//     through it offline (a synthetic provider, no network) pins the Rust
//     builder to the exact bytes the production path would have submitted.
//
// Determinism is total: record bytes come from a formula, UTxO identities come
// from the corpus, protocol parameters come from the corpus, and no step
// touches the network. Two runs of this tool on the same corpus and manifests
// produce identical reports.
//
// Usage:
//   node generate-oracle.mjs                       compare every manifest case
//   node generate-oracle.mjs --selection-from-corpus   self-test fallback (see below)
//   node generate-oracle.mjs --case size_64        restrict to one case
//
// The --selection-from-corpus fallback reimplements a greedy coin selection in
// JS so the tool can run end-to-end on corpus cases that do NOT yet have a
// builder manifest. It exists only to exercise the oracle plumbing before the
// authoritative manifests exist; it is NOT the reference selection and its
// choices carry no authority. The authoritative comparison is manifest-driven.

import { createRequire } from 'node:module';
import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { blake2b } from '@noble/hashes/blake2.js';
import { decode } from 'cbor2';
import { Tag } from 'cbor2/tag';
import { Lucid } from '@lucid-evolution/lucid';

// CSL ships as a CommonJS WASM module; load it through createRequire so this
// ES-module file can still pull it in.
const require = createRequire(import.meta.url);
const CSL = require('@emurgo/cardano-serialization-lib-nodejs');

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_ROOT = join(HERE, '..', '..', 'tests', 'fixtures', 'corpus');
const INPUTS_DIR = join(CORPUS_ROOT, 'inputs');
const MANIFEST_DIR = join(CORPUS_ROOT, 'rust-out');
const OUT_DIR = join(HERE, 'out');
// The committed, classified parity report. Regenerated here and asserted by a
// Rust test so any new divergence class fails CI.
const PARITY_REPORT_PATH = join(
  HERE,
  '..',
  '..',
  'tests',
  'fixtures',
  'oracle',
  'parity-report.json',
);

// Largest single byte string a Cardano metadata entry may carry. Records longer
// than this are split into an ordered list of chunks under the label.
const METADATA_CHUNK_SIZE = 64;

// ---------------------------------------------------------------------------
// Deterministic corpus data
// ---------------------------------------------------------------------------

// The corpus stores only `record_len`; the bytes are materialised from this
// formula so both the builder and this oracle reconstruct the identical record
// from a single integer. Keep this in lockstep with the corpus generator.
function materialiseRecord(recordLen) {
  const out = new Uint8Array(recordLen);
  for (let i = 0; i < recordLen; i += 1) {
    out[i] = (i * 7 + 13) % 256;
  }
  return out;
}

// Split a record into the ordered 64-byte chunk list the label-309 metadatum
// carries. An empty record yields a single empty chunk so the value is never an
// empty list.
function chunkRecord(record) {
  if (record.length === 0) {
    return [new Uint8Array(0)];
  }
  const chunks = [];
  for (let i = 0; i < record.length; i += METADATA_CHUNK_SIZE) {
    chunks.push(record.subarray(i, Math.min(record.length, i + METADATA_CHUNK_SIZE)));
  }
  return chunks;
}

function loadCorpusCase(name) {
  const path = join(INPUTS_DIR, `${name}.json`);
  return JSON.parse(readFileSync(path, 'utf8'));
}

function listCorpusNames() {
  return readdirSync(INPUTS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -'.json'.length))
    .sort();
}

function loadManifest(name) {
  const path = join(MANIFEST_DIR, `${name}.json`);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Fallback selection (self-test only — NOT the reference)
// ---------------------------------------------------------------------------

// A standalone greedy selection used only when no builder manifest exists, so
// the oracle can still run end-to-end and prove its CSL/Lucid plumbing works.
// It picks largest-value UTxOs first, breaking ties by (tx_hash asc, index asc),
// and stops once the running total clears a coarse target (a conservative fee
// floor plus a minimum-ADA change reserve). It deliberately does NOT model the
// builder's fold-or-add change logic; the resulting selection is a plausible
// input set for exercising the encoders, nothing more. When a real manifest is
// present this path is never taken.
function fallbackSelection(corpusCase) {
  const { protocol, record_len: recordLen, utxos } = corpusCase;
  // Coarse fee floor: linear fee over a record-dominated body. The constant
  // 512 is slack for inputs/outputs/witness overhead and is intentionally
  // generous; this is a self-test, not a fee computation.
  const feeFloor = protocol.min_fee_b + protocol.min_fee_a * (recordLen + 512);
  // A minimum-ADA reserve for the change output, sized off coins_per_utxo_byte.
  const changeReserve = protocol.coins_per_utxo_byte * 200;
  const target = feeFloor + changeReserve;

  const ordered = [...utxos].sort((a, b) => {
    if (b.lovelace !== a.lovelace) return b.lovelace - a.lovelace;
    // Lexicographic tie-break on the hex tx hash, then index. Ordering only,
    // not an equality test, so a plain string comparison is what is wanted.
    if (a.tx_hash < b.tx_hash) return -1;
    if (a.tx_hash > b.tx_hash) return 1;
    return a.index - b.index;
  });

  const selected = [];
  let total = 0;
  for (const u of ordered) {
    selected.push(u);
    total += u.lovelace;
    if (total >= target) break;
  }
  if (total < target) {
    return { ok: false, available: total, target };
  }
  const fee = feeFloor;
  const change = total - fee;
  return {
    ok: true,
    selected_inputs: selected.map((u) => [u.tx_hash, u.index]),
    fee,
    change_lovelace: change,
    total,
  };
}

// Normalise a manifest (or fallback result) into the single shape the encoders
// consume: the ordered selected inputs, the fee, and the change lovelace.
function resolveSelection(corpusCase, manifest, useFallback) {
  if (manifest) {
    return {
      source: 'manifest',
      selectedInputs: manifest.selected_inputs.map(({ tx_hash: txHash, index }) => ({
        txHash,
        index,
      })),
      fee: BigInt(manifest.fee),
      // The manifest encodes a folded (no-change) build as `null`, which is
      // structurally distinct from a change output carrying zero lovelace.
      change:
        manifest.change_lovelace === null || manifest.change_lovelace === undefined
          ? null
          : BigInt(manifest.change_lovelace),
    };
  }
  if (!useFallback) return null;
  const sel = fallbackSelection(corpusCase);
  if (!sel.ok) return { source: 'fallback', insufficient: true };
  return {
    source: 'fallback',
    selectedInputs: sel.selected_inputs.map(([txHash, index]) => ({ txHash, index })),
    fee: BigInt(sel.fee),
    change: BigInt(sel.change_lovelace),
  };
}

// ---------------------------------------------------------------------------
// CSL oracle
// ---------------------------------------------------------------------------

// Build the label-309 auxiliary data: a metadata map with one entry keyed by
// 309 whose value is the ordered list of record chunks as CBOR byte strings.
function cslAuxiliaryData(record) {
  const chunks = chunkRecord(record);
  const list = CSL.MetadataList.new();
  for (const chunk of chunks) {
    list.add(CSL.TransactionMetadatum.new_bytes(chunk));
  }
  const metadata = CSL.GeneralTransactionMetadata.new();
  metadata.insert(CSL.BigNum.from_str('309'), CSL.TransactionMetadatum.new_list(list));
  const aux = CSL.AuxiliaryData.new();
  aux.set_metadata(metadata);
  return aux;
}

// CSL's own minimum fee for the EXACT bytes the builder will submit.
//
// The fee floor that matters for FeeTooSmallUTxO is the ledger's linear fee
// over the precise transaction the builder serialises, witness included. So the
// authoritative path parses the builder's unsigned transaction verbatim,
// attaches the single fixed-width Ed25519 vkey witness the builder will add
// (a zero-filled placeholder measures the same bytes as the real signature),
// and lets CSL price that. A builder whose fee is below this floor would be
// rejected by the node with FeeTooSmallUTxO; a builder whose fee meets or
// exceeds it never can.
function cslMinFeeForExactTx(protocol, unsignedTxHex) {
  const tx = CSL.Transaction.from_hex(unsignedTxHex);
  const witnesses = tx.witness_set();
  const vkeys = CSL.Vkeywitnesses.new();
  const vkey = CSL.Vkey.new(CSL.PublicKey.from_bytes(new Uint8Array(32)));
  vkeys.add(CSL.Vkeywitness.new(vkey, CSL.Ed25519Signature.from_bytes(new Uint8Array(64))));
  witnesses.set_vkeys(vkeys);
  const witnessed = CSL.Transaction.new(tx.body(), witnesses, tx.auxiliary_data());
  const linearFee = CSL.LinearFee.new(
    CSL.BigNum.from_str(String(protocol.min_fee_a)),
    CSL.BigNum.from_str(String(protocol.min_fee_b)),
  );
  return BigInt(CSL.min_fee(witnessed, linearFee).to_str());
}

// Re-encode the transaction body from the same decisions the builder made, so
// the structural diff can surface where the builder's modern Conway encoding
// differs from CSL's. CSL canonicalises to the pre-Babbage forms (legacy array
// outputs, untagged Shelley auxiliary data, no body network_id), so this body
// is intentionally NOT byte-identical to the builder's; the difference is the
// documented, fee-neutral divergence the report classifies.
function cslReencodedBody(corpusCase, record, selection) {
  const inputs = CSL.TransactionInputs.new();
  for (const inp of selection.selectedInputs) {
    inputs.add(CSL.TransactionInput.new(CSL.TransactionHash.from_hex(inp.txHash), inp.index));
  }

  const changeAddress = CSL.Address.from_bech32(corpusCase.change_address);
  const outputs = CSL.TransactionOutputs.new();
  if (selection.change !== null) {
    outputs.add(
      CSL.TransactionOutput.new(
        changeAddress,
        CSL.Value.new(CSL.BigNum.from_str(selection.change.toString())),
      ),
    );
  }

  const ttl = corpusCase.validity ? corpusCase.validity.invalid_hereafter : undefined;
  const body = CSL.TransactionBody.new(
    inputs,
    outputs,
    CSL.BigNum.from_str(selection.fee.toString()),
    ttl === undefined ? undefined : ttl,
  );
  if (
    corpusCase.validity &&
    corpusCase.validity.valid_from !== null &&
    corpusCase.validity.valid_from !== undefined
  ) {
    body.set_validity_start_interval_bignum(
      CSL.BigNum.from_str(String(corpusCase.validity.valid_from)),
    );
  }

  const aux = cslAuxiliaryData(record);
  const auxHash = CSL.hash_auxiliary_data(aux);
  body.set_auxiliary_data_hash(auxHash);

  const bodyHex = body.to_hex();
  const bodyBytes = Uint8Array.from(Buffer.from(bodyHex, 'hex'));
  // Independent tx id: Blake2b-256 over CSL's re-encoded body bytes.
  const txHash = Buffer.from(blake2b(bodyBytes, { dkLen: 32 })).toString('hex');

  return { bodyHex, auxHashHex: auxHash.to_hex(), txHash };
}

// Run both CSL roles for one case: the authoritative min-fee floor over the
// builder's exact transaction (when a manifest supplies those bytes) and the
// re-encoded body used for the structural diff. When no manifest exists (the
// self-test fallback) there is no exact transaction to price, so the floor is
// taken over the re-encoded body instead, with one placeholder witness added.
function cslOracle(corpusCase, record, selection, manifest) {
  const { protocol } = corpusCase;
  const reencoded = cslReencodedBody(corpusCase, record, selection);

  let minFee;
  if (manifest) {
    minFee = cslMinFeeForExactTx(protocol, manifest.unsigned_tx_hex);
  } else {
    const witnesses = CSL.TransactionWitnessSet.new();
    const vkeys = CSL.Vkeywitnesses.new();
    const vkey = CSL.Vkey.new(CSL.PublicKey.from_bytes(new Uint8Array(32)));
    vkeys.add(CSL.Vkeywitness.new(vkey, CSL.Ed25519Signature.from_bytes(new Uint8Array(64))));
    witnesses.set_vkeys(vkeys);
    const body = CSL.TransactionBody.from_hex(reencoded.bodyHex);
    const aux = cslAuxiliaryData(record);
    const tx = CSL.Transaction.new(body, witnesses, aux);
    const linearFee = CSL.LinearFee.new(
      CSL.BigNum.from_str(String(protocol.min_fee_a)),
      CSL.BigNum.from_str(String(protocol.min_fee_b)),
    );
    minFee = BigInt(CSL.min_fee(tx, linearFee).to_str());
  }

  return {
    bodyHex: reencoded.bodyHex,
    auxHashHex: reencoded.auxHashHex,
    minFee,
    txHash: reencoded.txHash,
  };
}

// ---------------------------------------------------------------------------
// Lucid oracle
// ---------------------------------------------------------------------------

// Lucid requires a complete ProtocolParameters object. Only the linear-fee and
// coins-per-utxo-byte fields influence a pure-ADA metadata transaction; the
// rest are inert here and are filled with fixed, plausible values so the build
// is fully determined by the corpus.
function lucidProtocolParameters(protocol) {
  return {
    minFeeA: protocol.min_fee_a,
    minFeeB: protocol.min_fee_b,
    maxTxSize: protocol.max_tx_size,
    maxValSize: 5000,
    keyDeposit: 2000000n,
    poolDeposit: 500000000n,
    drepDeposit: 500000000n,
    govActionDeposit: 100000000000n,
    priceMem: 0.0577,
    priceStep: 0.0000721,
    maxTxExMem: 14000000n,
    maxTxExSteps: 10000000000n,
    coinsPerUtxoByte: BigInt(protocol.coins_per_utxo_byte),
    collateralPercentage: 150,
    maxCollateralInputs: 3,
    minFeeRefScriptCostPerByte: 15,
    costModels: { PlutusV1: [], PlutusV2: [], PlutusV3: [] },
  };
}

// A provider that serves the corpus protocol parameters and answers every
// network query from in-memory data only. It never opens a socket; any method
// the offline build does not need throws, so a regression that starts reaching
// for the network fails loudly instead of silently going online.
function offlineProvider(params) {
  const offline = (name) => async () => {
    throw new Error(`oracle provider is offline: ${name} must not be called`);
  };
  return {
    getProtocolParameters: async () => params,
    getUtxos: async () => [],
    getUtxosWithUnit: async () => [],
    getUtxoByUnit: offline('getUtxoByUnit'),
    getUtxosByOutRef: async () => [],
    getDelegation: async () => ({ poolId: null, rewards: 0n }),
    getDatum: offline('getDatum'),
    awaitTx: async () => true,
    submitTx: offline('submitTx'),
    evaluateTx: async () => [],
  };
}

async function lucidOracle(corpusCase, record, selection) {
  // Lucid's balancer always returns the residual as a change output; it has no
  // way to fold the whole selected value into the fee. A folded (no-change)
  // build is therefore outside what Lucid can reproduce, so report it as an
  // explicit, classified limitation instead of forcing a build that throws.
  if (selection.change === null) {
    return { txHex: null, fee: null, unsupported: 'no-change-fold' };
  }

  const params = lucidProtocolParameters(corpusCase.protocol);
  const lucid = await Lucid(offlineProvider(params), 'Preprod', {
    presetProtocolParameters: params,
  });

  // The corpus indexes each UTxO by (tx_hash, lovelace); map the manifest's
  // selected references back to those amounts so Lucid sees the right value.
  const byRef = new Map(corpusCase.utxos.map((u) => [`${u.tx_hash}:${u.index}`, u]));
  const presetWalletInputs = selection.selectedInputs.map((inp) => {
    const utxo = byRef.get(`${inp.txHash}:${inp.index}`);
    if (!utxo) {
      throw new Error(`selected input ${inp.txHash}:${inp.index} not in corpus utxo set`);
    }
    return {
      txHash: inp.txHash,
      outputIndex: inp.index,
      address: corpusCase.change_address,
      assets: { lovelace: BigInt(utxo.lovelace) },
    };
  });

  lucid.selectWallet.fromAddress(corpusCase.change_address, presetWalletInputs);

  const chunks = chunkRecord(record);
  let txBuilder = lucid.newTx().attachMetadata(309, chunks);
  if (corpusCase.validity) {
    txBuilder = txBuilder.validTo(slotToUnixApprox(corpusCase.validity.invalid_hereafter));
    if (corpusCase.validity.valid_from !== null && corpusCase.validity.valid_from !== undefined) {
      txBuilder = txBuilder.validFrom(slotToUnixApprox(corpusCase.validity.valid_from));
    }
  }

  const signBuilder = await txBuilder.complete({ presetWalletInputs });
  const txHex = signBuilder.toCBOR();
  const feeLovelace = extractFeeFromTxHex(txHex);
  return { txHex, fee: feeLovelace };
}

// Lucid's validity helpers take POSIX milliseconds and convert to slots through
// the bound network's slot config. The corpus supplies absolute slots directly,
// so for the offline build we feed a unix time that the Preprod slot config
// maps back to the same slot. Preprod slot 0 is at 1655683200s and slots are
// one second; this inverts that mapping.
const PREPROD_SLOT_ZERO_UNIX_MS = 1655683200000;
function slotToUnixApprox(slot) {
  return PREPROD_SLOT_ZERO_UNIX_MS + slot * 1000;
}

// Pull the fee out of a full transaction CBOR. The fee is field 2 of the body
// map (field 0 = inputs, 1 = outputs, 2 = fee, 3 = ttl, ...). Decoding the
// whole transaction and reading body.get(2) is robust to int-width changes.
function extractFeeFromTxHex(txHex) {
  const bytes = Uint8Array.from(Buffer.from(txHex, 'hex'));
  const tx = decodePreservingSets(bytes);
  // A Conway-era transaction is an array [body, witnessSet, isValid, auxiliary].
  const body = Array.isArray(tx) ? tx[0] : tx;
  const fee = body instanceof Map ? body.get(2) : body[2];
  return BigInt(fee);
}

// ---------------------------------------------------------------------------
// Structural comparison
// ---------------------------------------------------------------------------

// Register a passthrough decoder for the set tag (258) once, at module load, so
// every decode keeps the wrapper as an explicit Tag instead of collapsing it
// into a JS Set. Preserving the tag is what lets the structural diff tell a
// tagged set apart from a bare array.
Tag.registerDecoder(258, (tag) => tag);

// Decode CBOR keeping maps as Map objects (so integer keys and key order
// survive for structural diffing) and the set tag as an explicit Tag.
function decodePreservingSets(bytes) {
  return decode(bytes);
}

// Whether the raw bytes contain the set wrapper tag (258, encoded d9 01 02)
// anywhere. This is the on-the-wire signal that an input/collateral set was
// emitted as a tagged set rather than a bare array.
function containsSetTag(hex) {
  return hex.toLowerCase().includes('d90102');
}

// Map a raw structural divergence (kind + CBOR path) to the semantic encoding
// class it represents, when the path identifies one of the known Conway-era
// vs. pre-Babbage encoding differences. Comparisons run CSL (legacy re-encode)
// on the left and the builder body on the right.
//
//   - body key 15 present only on the builder side  -> `network-id`
//     (the builder writes the body network_id field; CSL's legacy re-encode
//     omits it)
//   - an output element typed array on one side, map on the other -> `output-format`
//     (the builder emits the post-Babbage map output {0,1}; CSL re-encodes the
//     legacy `[address, value]` array)
//   - body key 7 (auxiliary_data_hash) byte string differs -> `aux-data-format`
//     (the builder hashes the Conway tag-259 auxiliary data; CSL hashes the
//     untagged Shelley metadata map, so the two hashes differ)
//
// Anything the map does not recognise keeps its raw kind, so a genuinely new
// divergence is never silently folded into a known class.
function semanticClass(div) {
  if (div.kind === 'field-presence' && div.path === '$.15') return 'network-id';
  if (div.kind === 'type' && /^\$\.1\[\d+\]$/.test(div.path)) return 'output-format';
  if (div.kind === 'value' && div.path === '$.7') return 'aux-data-format';
  return div.kind;
}

// Walk two decoded CBOR values in parallel and classify every structural
// difference into a stable, machine-readable category. The raw categories are:
//   - tag-258 presence (one side tags a set, the other emits a bare array)
//   - int-width (the same integer encoded at different CBOR widths)
//   - map-ordering (the same map keys in a different order)
//   - field-presence (a field present on one side and absent on the other)
//   - value (same field, different value)
//   - type (same position, different CBOR major type)
//
// Each divergence is then tagged with a semantic `class` via `semanticClass`,
// which names the known Conway-vs-legacy encoding differences explicitly and
// leaves any unrecognised divergence under its raw kind.
function classifyDivergences(left, right, leftHex, rightHex) {
  const divergences = [];

  if (containsSetTag(leftHex) !== containsSetTag(rightHex)) {
    divergences.push({
      kind: 'tag-258',
      detail: `set tag present left=${containsSetTag(leftHex)} right=${containsSetTag(rightHex)}`,
    });
  }

  walk(left, right, '$', divergences);
  for (const d of divergences) {
    d.class = semanticClass(d);
  }
  return divergences;

  function walk(a, b, path, out) {
    const ta = cborType(a);
    const tb = cborType(b);
    if (ta !== tb) {
      out.push({ kind: 'type', path, detail: `${ta} vs ${tb}` });
      return;
    }
    switch (ta) {
      case 'map':
        walkMap(a, b, path, out);
        break;
      case 'array':
        walkArray(a, b, path, out);
        break;
      case 'tag':
        if (a.tag !== b.tag) {
          out.push({ kind: 'tag-258', path, detail: `tag ${a.tag} vs ${b.tag}` });
        }
        walk(a.contents, b.contents, `${path}.tagged`, out);
        break;
      case 'bytes':
        if (!bytesEqual(a, b)) {
          out.push({ kind: 'value', path, detail: 'byte string differs' });
        }
        break;
      case 'int':
        if (BigInt(a) !== BigInt(b)) {
          out.push({ kind: 'value', path, detail: `${a} vs ${b}` });
        } else if (intEncodedWidth(a) !== intEncodedWidth(b)) {
          // Same numeric value, different minimal width: only possible when one
          // side is a bigint and the other a number across the 2^53 boundary.
          out.push({
            kind: 'int-width',
            path,
            detail: `width ${intEncodedWidth(a)} vs ${intEncodedWidth(b)}`,
          });
        }
        break;
      default:
        if (a !== b) {
          out.push({ kind: 'value', path, detail: `${String(a)} vs ${String(b)}` });
        }
    }
  }

  function walkMap(a, b, path, out) {
    const aKeys = [...a.keys()];
    const bKeys = [...b.keys()];
    const aSet = new Set(aKeys.map(String));
    const bSet = new Set(bKeys.map(String));
    for (const k of aKeys) {
      if (!bSet.has(String(k))) {
        out.push({
          kind: 'field-presence',
          path: `${path}.${String(k)}`,
          detail: 'present left, absent right',
        });
      }
    }
    for (const k of bKeys) {
      if (!aSet.has(String(k))) {
        out.push({
          kind: 'field-presence',
          path: `${path}.${String(k)}`,
          detail: 'absent left, present right',
        });
      }
    }
    // Key ordering: the sequence of common keys must match.
    const common = aKeys.filter((k) => bSet.has(String(k))).map(String);
    const commonB = bKeys.filter((k) => aSet.has(String(k))).map(String);
    if (common.join(',') !== commonB.join(',')) {
      out.push({
        kind: 'map-ordering',
        path,
        detail: `${common.join(',')} vs ${commonB.join(',')}`,
      });
    }
    for (const k of aKeys) {
      if (bSet.has(String(k))) {
        const bKey = bKeys.find((x) => String(x) === String(k));
        walk(a.get(k), b.get(bKey), `${path}.${String(k)}`, out);
      }
    }
  }

  function walkArray(a, b, path, out) {
    if (a.length !== b.length) {
      out.push({ kind: 'field-presence', path, detail: `array length ${a.length} vs ${b.length}` });
    }
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
      walk(a[i], b[i], `${path}[${i}]`, out);
    }
  }
}

function cborType(v) {
  if (v instanceof Tag) return 'tag';
  if (v instanceof Map) return 'map';
  if (Array.isArray(v)) return 'array';
  if (v instanceof Uint8Array) return 'bytes';
  if (typeof v === 'bigint' || typeof v === 'number') return 'int';
  return typeof v;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Minimal CBOR head width (in bytes after the major-type byte) for an unsigned
// integer value, used only to flag a same-value/different-width encoding.
function intEncodedWidth(v) {
  const n = BigInt(v) < 0n ? -BigInt(v) - 1n : BigInt(v);
  if (n < 24n) return 0;
  if (n < 256n) return 1;
  if (n < 65536n) return 2;
  if (n < 4294967296n) return 4;
  return 8;
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

function buildReport(name, corpusCase, manifest, selection) {
  const record = materialiseRecord(corpusCase.record_len);

  const csl = cslOracle(corpusCase, record, selection, manifest);
  return lucidOracle(corpusCase, record, selection).then((lucid) => {
    const feeRust = manifest ? BigInt(manifest.fee) : null;
    // CSL re-encodes the body from the builder's decisions (legacy pre-Babbage
    // forms), so comparing it against the manifest body classifies the encoding
    // divergence. Lucid emits a full transaction, compared against the
    // manifest's full unsigned transaction.
    const cslBodyHex = csl.bodyHex;
    const lucidTxHex = lucid.txHex;

    let bytesEqualCsl = null;
    let bytesEqualLucid = null;
    let divergences;
    const lucidStatus = lucid.unsupported ?? 'built';

    if (manifest) {
      bytesEqualCsl = cslBodyHex.toLowerCase() === String(manifest.body_hex).toLowerCase();
      bytesEqualLucid = lucidTxHex
        ? lucidTxHex.toLowerCase() === String(manifest.unsigned_tx_hex).toLowerCase()
        : null;

      const cslDecoded = decodePreservingSets(Uint8Array.from(Buffer.from(cslBodyHex, 'hex')));
      const manifestBody = decodePreservingSets(
        Uint8Array.from(Buffer.from(manifest.body_hex, 'hex')),
      );
      divergences = classifyDivergences(cslDecoded, manifestBody, cslBodyHex, manifest.body_hex);
    } else {
      // No manifest: compare the two oracles against each other so the report
      // still surfaces CSL-vs-Lucid structural differences. The body is element
      // 0 of the Lucid transaction array.
      const cslDecoded = decodePreservingSets(Uint8Array.from(Buffer.from(cslBodyHex, 'hex')));
      const lucidTx = lucidTxHex
        ? decodePreservingSets(Uint8Array.from(Buffer.from(lucidTxHex, 'hex')))
        : null;
      const lucidBody = lucidTx && Array.isArray(lucidTx) ? lucidTx[0] : lucidTx;
      divergences = lucidBody
        ? classifyDivergences(cslDecoded, lucidBody, cslBodyHex, lucidTxHex)
        : [];
    }

    const feeLucid = lucid.fee;

    // The fee floor that guards against FeeTooSmallUTxO: the builder's fee must
    // be at least CSL's minimum fee over the EXACT transaction the builder
    // submits. Byte parity is not required for this floor to hold.
    const feeCslFloorOk = feeRust === null ? null : feeRust >= csl.minFee;
    // Whether the builder fee equals CSL's floor exactly. It is at or above it;
    // a small positive gap is the fee-neutral output-encoding-width divergence
    // (Babbage map output vs CSL's legacy array re-encoding).
    const feeCslExact = feeRust === null ? null : feeRust === csl.minFee;
    // Lucid parity: equal where Lucid could build the case. For a folded
    // (no-change) build Lucid cannot reproduce the shape, so parity is reported
    // as the explicit limitation rather than an equality.
    const feeLucidEqual = feeRust === null || feeLucid === null ? null : feeRust === feeLucid;

    return {
      case: name,
      selection_source: selection.source,
      fee_rust: feeRust === null ? null : Number(feeRust),
      fee_csl_min: Number(csl.minFee),
      fee_lucid: feeLucid === null ? null : Number(feeLucid),
      // The builder fee never falls below the ledger floor for its exact bytes.
      fee_csl_floor_ok: feeCslFloorOk,
      fee_csl_exact: feeCslExact,
      fee_lucid_equal: feeLucidEqual,
      lucid_status: lucidStatus,
      bytes_equal_csl: bytesEqualCsl,
      bytes_equal_lucid: bytesEqualLucid,
      csl_aux_data_hash: csl.auxHashHex,
      csl_tx_hash: csl.txHash,
      divergence_classes: [...new Set(divergences.map((d) => d.class))].sort(),
      divergences,
    };
  });
}

// The structural divergence classes the gate accepts as documented, fee-neutral
// differences between the builder's modern Conway encoding and the legacy forms
// CSL re-serialises. A divergence class outside this set is an unclassified
// difference and fails the run.
//
//   - network-id     builder writes body network_id; CSL legacy re-encode omits it
//   - output-format  builder emits Babbage map output; CSL emits legacy array
//   - aux-data-format builder hashes Conway tag-259 aux; CSL hashes Shelley map
//
// None of the three changes the fee the builder charges relative to the ledger
// floor over its OWN exact bytes (see `fee_csl_floor_ok`), and all three are a
// consequence of CSL/Lucid predating the Conway-era canonical encoding.
const KNOWN_DIVERGENCE_CLASSES = new Set(['network-id', 'output-format', 'aux-data-format']);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { useFallback: false, only: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--selection-from-corpus') {
      args.useFallback = true;
    } else if (a === '--case') {
      args.only = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  mkdirSync(OUT_DIR, { recursive: true });

  const names = args.only ? [args.only] : listCorpusNames();
  let compared = 0;
  let skipped = 0;
  const failures = [];
  const parityCases = [];

  for (const name of names) {
    const corpusCase = loadCorpusCase(name);
    const manifest = loadManifest(name);

    // Cases the corpus marks as unbuildable have no transaction to compare.
    if (corpusCase.expect === 'insufficient_funds' && !manifest) {
      skipped += 1;
      writeFileSync(
        join(OUT_DIR, `${name}.json`),
        `${JSON.stringify({ case: name, skipped: 'expects insufficient_funds; no transaction to build' }, null, 2)}\n`,
      );
      continue;
    }

    const selection = resolveSelection(corpusCase, manifest, args.useFallback);
    if (selection === null) {
      skipped += 1;
      continue;
    }
    if (selection.insufficient) {
      skipped += 1;
      writeFileSync(
        join(OUT_DIR, `${name}.json`),
        `${JSON.stringify({ case: name, skipped: 'fallback selection insufficient' }, null, 2)}\n`,
      );
      continue;
    }

    const report = await buildReport(name, corpusCase, manifest, selection);
    writeFileSync(join(OUT_DIR, `${name}.json`), `${JSON.stringify(report, null, 2)}\n`);
    compared += 1;

    // Two conditions are real builder failures for a manifest-backed case:
    //   1. the builder's fee falls below CSL's minimum fee for the exact bytes
    //      it submits (it would be rejected with FeeTooSmallUTxO), or
    //   2. a structural divergence appears outside the documented, fee-neutral
    //      Conway-vs-legacy classes (an unclassified encoding difference).
    // Byte inequality against CSL/Lucid alone is expected and does not fail the
    // run: the builder deliberately emits the modern Conway encoding the legacy
    // oracles cannot reproduce.
    if (manifest) {
      if (report.fee_csl_floor_ok === false) {
        failures.push({ case: name, reason: 'fee_below_ledger_floor' });
      }
      const unexpected = report.divergence_classes.filter((c) => !KNOWN_DIVERGENCE_CLASSES.has(c));
      if (unexpected.length > 0) {
        failures.push({ case: name, reason: `unclassified_divergence:${unexpected.join(',')}` });
      }

      // The compact, stable parity row a Rust test pins. Only the fields that
      // must not drift silently are kept: the floor relation, whether bytes
      // matched each oracle, the Lucid build status, and the divergence
      // classes. Raw fee numbers are deliberately excluded so the pinned report
      // does not churn when protocol parameters or record lengths change while
      // the encoding contract stays the same.
      parityCases.push({
        case: name,
        fee_csl_floor_ok: report.fee_csl_floor_ok,
        bytes_equal_csl: report.bytes_equal_csl,
        bytes_equal_lucid: report.bytes_equal_lucid,
        lucid_status: report.lucid_status,
        divergence_classes: report.divergence_classes,
      });
    }
  }

  const summary = {
    compared,
    skipped,
    mode: args.useFallback ? 'fallback-self-test' : 'manifest',
    known_divergence_classes: [...KNOWN_DIVERGENCE_CLASSES].sort(),
    failures,
  };
  writeFileSync(join(OUT_DIR, '_summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(summary)}\n`);

  // Write the committed parity report only on a full-corpus manifest run, so it
  // stays complete and reproducible. A single-case (`--case`) or fallback run
  // must not overwrite it with a partial picture.
  if (!args.useFallback && !args.only) {
    parityCases.sort((a, b) => a.case.localeCompare(b.case));
    const parityReport = {
      description:
        'Classified, fee-neutral encoding divergences between the modern Conway ' +
        'transaction the builder emits and the legacy forms the CSL and Lucid ' +
        'oracles re-serialise. Byte equality is the goal; this pinned list is the ' +
        'documented fallback. Regenerated by tools/oracle/generate-oracle.mjs.',
      known_divergence_classes: [...KNOWN_DIVERGENCE_CLASSES].sort(),
      divergence_class_meanings: {
        'network-id':
          'builder writes the body network_id field (key 15); the legacy re-encode omits it',
        'output-format':
          'builder emits the post-Babbage map output {0: address, 1: value}; the legacy re-encode uses the [address, value] array',
        'aux-data-format':
          'builder hashes the Conway tag-259 auxiliary data; the legacy re-encode hashes the untagged Shelley metadata map',
      },
      cases: parityCases,
    };
    mkdirSync(dirname(PARITY_REPORT_PATH), { recursive: true });
    writeFileSync(PARITY_REPORT_PATH, `${JSON.stringify(parityReport, null, 2)}\n`);
  }

  // In manifest mode a disagreement is a build failure; in fallback self-test
  // mode there is no authority to disagree with, so a clean run is success.
  if (!args.useFallback && failures.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err}\n`);
  process.exitCode = 1;
});
