// Golden-vector generator for the ANS-104 data-item format.
//
// This script drives the reference JavaScript implementation
// (@dha-team/arbundles + arweave-js) to emit a set of signed data items and a
// batch of deep-hash known-answer tests. The Rust `ans104` crate is validated
// against these vectors: it must reproduce the same canonical bytes (tag Avro
// frame, deep-hash digest, owner, framing/layout) and verify the reference
// signatures.
//
// Run from this directory with the pinned dependencies installed:
//
//   npm install
//   npm run generate
//
// Determinism: the script reuses a committed test key, so the owner, tag Avro
// frames, deep-hash digests, layout sizes, and item ids derived from those are
// reproducible across runs. The RSA-PSS signatures are NOT: PSS is randomized
// (a fresh salt per signature), so `signature_hex` and any value derived from
// the signature (`id_b64url`) are per-run snapshots. The Rust side therefore
// VERIFIES signatures (recompute deep-hash, check RSA-PSS against the embedded
// owner) rather than byte-comparing them, while byte-comparing everything that
// is stable.

import { mkdir, writeFile, readFile, access } from 'node:fs/promises';
import {
  createHash,
  createPublicKey,
  constants as cryptoConstants,
  verify as nodeVerify,
} from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import Arweave from 'arweave';
import b64urlModule from 'base64url';

// arbundles' package root entry pulls in its `file` submodule, which requires
// `axios` (only used for the file-backed data-item helpers we do not touch).
// Import the specific submodules directly so the generator needs nothing beyond
// the two pinned dependencies.
import { createRequire } from 'node:module';

// arbundles' `exports` map rewrites a `./*` subpath to `./*.js`, so an ESM
// `import` of a concrete `.js` file resolves to `*.js.js` and fails. Load the
// CJS submodules through a CommonJS require, which resolves the extensionless
// subpaths correctly.
const require = createRequire(import.meta.url);
const { createData } = require('@dha-team/arbundles/build/node/cjs/src/ar-data-create');
const { DataItem, MAX_TAG_BYTES } = require('@dha-team/arbundles/build/node/cjs/src/DataItem');
const { serializeTags } = require('@dha-team/arbundles/build/node/cjs/src/tags');
const { deepHash } = require('@dha-team/arbundles/build/node/cjs/src/deepHash');
const { ArweaveSigner } = require('@dha-team/arbundles/build/node/cjs/src/signing/index');

const base64url = b64urlModule.default ?? b64urlModule;

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, '..', 'tests', 'vectors');
const JWK_PATH = join(VECTORS_DIR, 'test-jwk.json');

const ARBUNDLES_VERSION = '1.0.4';
const ARWEAVE_VERSION = '1.15.7';

// Constant, clock-free timestamp string used in the gateway-tag vector. Using a
// literal keeps the vector reproducible: a real `Date.now()` would change every
// run and break byte-stable comparison of the tag Avro frame and deep-hash.
const FIXED_CREATED_AT = '1750000000';

const hex = (buf) => Buffer.from(buf).toString('hex');
const sha256 = (buf) => createHash('sha256').update(buf).digest();

// Deterministic payload bytes shared by both sides: b[i] = (i*7 + 13) mod 256.
function deterministicData(len) {
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    out[i] = (i * 7 + 13) & 0xff;
  }
  return out;
}

const ZERO_TARGET = deterministicData(32); // arbitrary fixed 32-byte target
const ZERO_ANCHOR = (() => {
  // A fixed 32-byte anchor distinct from the target so the two are
  // distinguishable in the deep-hash. Anchors are raw bytes in arbundles.
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) out[i] = (i * 5 + 1) & 0xff;
  return out;
})();

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

// Load the committed throwaway test JWK, generating and writing it once if it
// does not yet exist. The key is valueless and exists only to produce
// deterministic owner/layout bytes across runs.
async function loadOrCreateJwk(arweave) {
  if (await exists(JWK_PATH)) {
    return JSON.parse(await readFile(JWK_PATH, 'utf8'));
  }
  const jwk = await arweave.wallets.generate();
  await writeFile(JWK_PATH, JSON.stringify(jwk, null, 2) + '\n');
  return jwk;
}

// Determine the RSA-PSS salt length the reference signer actually emitted, by
// attempting verification against each candidate. arweave-js signs with Node's
// default (max) salt length and verifies with auto-detect; recording the
// observed value documents what the Rust verifier must accept.
function detectSaltLength(modulusN, message, signature) {
  const publicKeyPem = jwkModulusToPem(modulusN);
  // Max salt for RSA-4096 + SHA-256: 512 - 32 - 2 = 478.
  for (const saltLength of [478, 32, 0]) {
    const ok = nodeVerify(
      'sha256',
      message,
      {
        key: publicKeyPem,
        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      },
      signature,
    );
    if (ok) return saltLength;
  }
  return null;
}

function jwkModulusToPem(n) {
  const keyObject = createPublicKey({
    key: { kty: 'RSA', n, e: 'AQAB' },
    format: 'jwk',
  });
  return keyObject.export({ type: 'spki', format: 'pem' });
}

// Build, sign, self-verify, and serialize one data item; return its sidecar
// metadata plus the raw signed bytes.
async function buildVector(name, { tags, target, anchor, data }, signer, ownerHex) {
  const opts = { tags };
  if (target) opts.target = base64url.encode(target);
  if (anchor) opts.anchor = anchor; // raw bytes; arbundles does Buffer.from(anchor)

  const item = createData(data, signer, opts);
  await item.sign(signer);

  const bin = Buffer.from(item.getRaw());

  // Independently recompute the signed deep-hash so the sidecar records the
  // exact message digest the signature covers.
  const deepHashDigest = Buffer.from(
    await deepHash([
      Buffer.from('dataitem'),
      Buffer.from('1'),
      Buffer.from(item.signatureType.toString()),
      item.rawOwner,
      item.rawTarget,
      item.rawAnchor,
      item.rawTags,
      item.rawData,
    ]),
  );

  const signature = Buffer.from(item.rawSignature);
  const tagsAvro = serializeTags(tags ?? []);
  const saltLen = detectSaltLength(signer.jwk.n, deepHashDigest, signature);

  // Self-check: the reference implementation must accept its own item, and the
  // id must be SHA-256(signature).
  const valid = await DataItem.verify(bin);
  if (!valid) throw new Error(`reference verify() rejected vector '${name}'`);
  const expectedId = base64url.encode(sha256(signature));
  if (item.id !== expectedId) {
    throw new Error(`id mismatch for vector '${name}': ${item.id} != ${expectedId}`);
  }

  const sidecar = {
    generator_versions: {
      '@dha-team/arbundles': ARBUNDLES_VERSION,
      arweave: ARWEAVE_VERSION,
    },
    sig_type: item.signatureType,
    owner_hex: ownerHex,
    target_hex: target ? hex(target) : null,
    anchor_hex: anchor ? hex(anchor) : null,
    tags: (tags ?? []).map((t) => ({ name: t.name, value: t.value })),
    tags_avro_hex: hex(tagsAvro),
    data_len: data.length,
    data_sha256_hex: hex(sha256(data)),
    signature_hex: hex(signature),
    id_b64url: item.id,
    deep_hash_hex: hex(deepHashDigest),
    raw_len: bin.length,
    salt_len: saltLen,
  };

  await writeFile(join(VECTORS_DIR, `${name}.bin`), bin);
  await writeFile(join(VECTORS_DIR, `${name}.json`), JSON.stringify(sidecar, null, 2) + '\n');
  return { name, bin, item };
}

// Construct a single tag whose serialized Avro frame is exactly `targetBytes`
// long. The Avro frame is: writeLong(1) [block count, 1 byte] ++ writeString(name)
// ++ writeString(value) ++ writeLong(0) [terminator, 1 byte]. Each writeString
// is writeLong(byteLen) ++ bytes. For small lengths writeLong is a single byte.
// We fix the name and grow the value until the frame hits the target.
function tagsForExactAvroLength(targetBytes) {
  const name = 'k';
  // Search for a value length whose full frame equals targetBytes.
  for (let valueLen = 1; valueLen <= targetBytes; valueLen++) {
    const value = 'v'.repeat(valueLen);
    const frame = serializeTags([{ name, value }]);
    if (frame.length === targetBytes) {
      return [{ name, value }];
    }
    if (frame.length > targetBytes) break;
  }
  throw new Error(`could not size a single tag to exactly ${targetBytes} Avro bytes`);
}

async function main() {
  await mkdir(VECTORS_DIR, { recursive: true });
  const arweave = Arweave.init({});
  const jwk = await loadOrCreateJwk(arweave);
  const signer = new ArweaveSigner(jwk);
  const ownerHex = hex(signer.publicKey);

  const written = [];

  // --- Tag-shape vectors ---------------------------------------------------

  // empty_tags: serializeTags([]) must yield a zero-length frame.
  {
    const emptyFrame = serializeTags([]);
    if (emptyFrame.length !== 0) {
      throw new Error(`serializeTags([]) expected 0 bytes, got ${emptyFrame.length}`);
    }
    written.push(
      await buildVector('empty_tags', { tags: [], data: deterministicData(64) }, signer, ownerHex),
    );
  }

  // minimal_gateway_tags: the tag set a gateway typically attaches, with fixed
  // literal values (no clock reads).
  {
    const tags = [
      { name: 'App-Name', value: 'Label-309-Gateway' },
      { name: 'App-Version', value: '1' },
      { name: 'Unix-Time', value: FIXED_CREATED_AT },
      { name: 'Content-Type', value: 'application/octet-stream' },
    ];
    written.push(
      await buildVector(
        'minimal_gateway_tags',
        { tags, data: deterministicData(128) },
        signer,
        ownerHex,
      ),
    );
  }

  // unicode_tags: multi-byte UTF-8 in both names and values.
  {
    const tags = [
      { name: 'Søk', value: 'verdi' },
      { name: '名前', value: '値' },
      { name: 'emoji', value: '🔐🜂' },
      { name: 'Ω', value: 'λ→μ' },
    ];
    written.push(
      await buildVector('unicode_tags', { tags, data: deterministicData(96) }, signer, ownerHex),
    );
  }

  // tag_bytes_4096_boundary: a tag list whose Avro frame is exactly
  // MAX_TAG_BYTES (4096) long, the largest the format accepts.
  {
    const tags = tagsForExactAvroLength(MAX_TAG_BYTES);
    const frame = serializeTags(tags);
    if (frame.length !== MAX_TAG_BYTES) {
      throw new Error(`boundary frame is ${frame.length}, expected ${MAX_TAG_BYTES}`);
    }
    written.push(
      await buildVector(
        'tag_bytes_4096_boundary',
        { tags, data: deterministicData(32) },
        signer,
        ownerHex,
      ),
    );
  }

  // tag_bytes_4097_reject: one byte over the limit. The reference rejects this
  // at two points; record the observed failure rather than emitting a .bin.
  {
    const tags = tagsForExactAvroLength(MAX_TAG_BYTES); // 4096-byte frame...
    // ...grow the value by one byte to push the frame to 4097.
    tags[0].value = tags[0].value + 'v';
    let serializeError = null;
    try {
      serializeTags(tags);
    } catch (e) {
      serializeError = e;
    }

    // Also confirm the parse-side guard: a hand-built binary whose declared tag
    // byte count exceeds MAX_TAG_BYTES is rejected by DataItem.verify().
    const verifyRejects = await buildOversizeTagBinaryAndCheckRejected(signer);

    const sidecar = {
      generator_versions: {
        '@dha-team/arbundles': ARBUNDLES_VERSION,
        arweave: ARWEAVE_VERSION,
      },
      description:
        'A tag list whose serialized Avro frame is 4097 bytes (one over MAX_TAG_BYTES). ' +
        'The reference implementation rejects it, so no signed .bin is emitted. ' +
        'serialize_error is thrown by serializeTags() when the frame overflows its ' +
        'fixed MAX_TAG_BYTES buffer; verify_rejects_oversize_tag_bytes records that ' +
        'DataItem.verify() returns false for a binary whose declared tag byte count ' +
        'exceeds MAX_TAG_BYTES.',
      max_tag_bytes: MAX_TAG_BYTES,
      attempted_avro_len: MAX_TAG_BYTES + 1,
      serialize_error_name: serializeError ? serializeError.constructor.name : null,
      serialize_error_message: serializeError ? serializeError.message : null,
      verify_rejects_oversize_tag_bytes: verifyRejects,
    };
    if (!serializeError) {
      throw new Error('expected serializeTags to throw on a 4097-byte frame');
    }
    if (!verifyRejects) {
      throw new Error('expected DataItem.verify() to reject an oversize tag byte count');
    }
    await writeFile(
      join(VECTORS_DIR, 'tag_bytes_4097_reject.json'),
      JSON.stringify(sidecar, null, 2) + '\n',
    );
  }

  // --- Target / anchor presence vectors ------------------------------------

  written.push(
    await buildVector(
      'target_only',
      { tags: [], target: ZERO_TARGET, data: deterministicData(48) },
      signer,
      ownerHex,
    ),
  );
  written.push(
    await buildVector(
      'anchor_only',
      { tags: [], anchor: ZERO_ANCHOR, data: deterministicData(48) },
      signer,
      ownerHex,
    ),
  );
  written.push(
    await buildVector(
      'target_and_anchor',
      {
        tags: [],
        target: ZERO_TARGET,
        anchor: ZERO_ANCHOR,
        data: deterministicData(48),
      },
      signer,
      ownerHex,
    ),
  );
  written.push(
    await buildVector('neither', { tags: [], data: deterministicData(48) }, signer, ownerHex),
  );

  // --- Data-length boundary vectors ----------------------------------------

  for (const len of [0, 1, 511, 512, 100000]) {
    written.push(
      await buildVector(
        `data_${len}`,
        { tags: [], data: deterministicData(len) },
        signer,
        ownerHex,
      ),
    );
  }

  // --- Deep-hash known-answer tests ----------------------------------------

  await writeDeepHashKats();

  // --- Self-check pass: reload every .bin and confirm verify()+id ----------

  await selfCheck(written);

  console.log(`Generated ${written.length} signed vectors + deep-hash KATs in ${VECTORS_DIR}`);
}

// Hand-build a data-item binary whose tag-byte-count field declares more than
// MAX_TAG_BYTES, and confirm DataItem.verify() rejects it. Returns true on the
// expected rejection.
async function buildOversizeTagBinaryAndCheckRejected(signer) {
  // Start from a valid signed item, then overwrite its declared tag byte count
  // with a value above MAX_TAG_BYTES. verify() guards on this before parsing.
  const item = createData(deterministicData(8), signer, { tags: [{ name: 'k', value: 'v' }] });
  await item.sign(signer);
  const bin = Buffer.from(item.getRaw());

  // Locate the tags-start by replaying the layout: 2 + sigLen + ownerLen, then
  // skip target presence (1) and anchor presence (1); both are absent here.
  const sigLen = 512;
  const ownerLen = 512;
  let tagsStart = 2 + sigLen + ownerLen;
  tagsStart += bin[tagsStart] === 1 ? 33 : 1; // target presence byte
  tagsStart += bin[tagsStart] === 1 ? 33 : 1; // anchor presence byte

  // The 8-byte little-endian tag-byte-count lives at tagsStart + 8.
  const oversize = MAX_TAG_BYTES + 1;
  bin.writeUInt32LE(oversize & 0xffffffff, tagsStart + 8);
  bin.writeUInt32LE(0, tagsStart + 12);

  const valid = await DataItem.verify(bin);
  return valid === false;
}

async function writeDeepHashKats() {
  const oneKib = deterministicData(1024);

  const kats = [
    {
      name: 'empty_blob',
      shape: 'blob',
      input_hex: '',
      deep_hash_hex: hex(await deepHash(Buffer.alloc(0))),
    },
    {
      name: 'hello_blob',
      shape: 'blob',
      input_hex: hex(Buffer.from('hello')),
      deep_hash_hex: hex(await deepHash(Buffer.from('hello'))),
    },
    {
      name: 'kib_blob',
      shape: 'blob',
      input_hex: hex(oneKib),
      deep_hash_hex: hex(await deepHash(oneKib)),
    },
    {
      name: 'empty_list',
      shape: 'list',
      children: [],
      deep_hash_hex: hex(await deepHash([])),
    },
    {
      name: 'ab_list',
      shape: 'list',
      children: [
        { shape: 'blob', input_hex: hex(Buffer.from('a')) },
        { shape: 'blob', input_hex: hex(Buffer.from('b')) },
      ],
      deep_hash_hex: hex(await deepHash([Buffer.from('a'), Buffer.from('b')])),
    },
    {
      name: 'nested_list',
      shape: 'list',
      children: [
        { shape: 'list', children: [{ shape: 'blob', input_hex: hex(Buffer.from('a')) }] },
        {
          shape: 'list',
          children: [
            { shape: 'blob', input_hex: hex(Buffer.from('b')) },
            { shape: 'blob', input_hex: hex(Buffer.from('c')) },
          ],
        },
      ],
      deep_hash_hex: hex(
        await deepHash([[Buffer.from('a')], [Buffer.from('b'), Buffer.from('c')]]),
      ),
    },
  ];

  const doc = {
    generator_versions: {
      '@dha-team/arbundles': ARBUNDLES_VERSION,
      arweave: ARWEAVE_VERSION,
    },
    hash: 'SHA-384',
    description:
      'Known-answer tests for the ANS-104 recursive deep-hash. A blob hashes as ' +
      "H(H('blob'||ascii(len)) || H(blob)); a list of length n folds each child " +
      "into an accumulator seeded with H('list'||ascii(n)). input_hex is the leaf " +
      'blob bytes; children are nested deep-hash items. deep_hash_hex is the 48-byte ' +
      'SHA-384 digest.',
    kats,
  };
  await writeFile(join(VECTORS_DIR, 'deep-hash-kats.json'), JSON.stringify(doc, null, 2) + '\n');
}

async function selfCheck(written) {
  for (const { name, bin } of written) {
    const reloaded = new DataItem(Buffer.from(bin));
    const ok = await DataItem.verify(reloaded.getRaw());
    if (!ok) throw new Error(`self-check: reloaded '${name}' failed verify()`);

    const sidecar = JSON.parse(await readFile(join(VECTORS_DIR, `${name}.json`), 'utf8'));
    if (reloaded.id !== sidecar.id_b64url) {
      throw new Error(
        `self-check: reloaded '${name}' id ${reloaded.id} != sidecar ${sidecar.id_b64url}`,
      );
    }
    // The reloaded id must equal SHA-256(signature) base64url.
    const expectedId = base64url.encode(sha256(reloaded.rawSignature));
    if (reloaded.id !== expectedId) {
      throw new Error(`self-check: '${name}' id is not SHA-256(signature)`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
