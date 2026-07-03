// Cross-check a Rust-signed format-2 transaction against arweave-js internals.
//
// Reads the JSON the `sign_tx_v2_to_json` example prints (plus `_payload_hex`) on
// stdin, then independently, using arweave-js's own merkle/deepHash/crypto
// modules: recomputes the data_root from the payload, verifies the RSA-PSS
// signature over the format-2 deep-hash, and recomputes the id as SHA-256 of the
// signature. Prints a JSON verdict, exit 0 on full agreement.

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const merkle = require('arweave/node/lib/merkle');
const deepHash = require('arweave/node/lib/deepHash').default;
const NodeDriver = require('arweave/node/lib/crypto/node-driver').default;
const utils = require('arweave/node/lib/utils');

const crypto = new NodeDriver();
const b64UrlToBuffer = utils.b64UrlToBuffer;
const bufferTob64Url = utils.bufferTob64Url;
const stringToBuffer = utils.stringToBuffer;

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (buf += c));
    process.stdin.on('end', () => resolve(buf));
    process.stdin.on('error', reject);
  });
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function main() {
  const tx = JSON.parse(await readStdin());
  const payload = hexToBytes(tx._payload_hex);

  // 1) data_root recomputed from the payload via arweave-js merkle chunking.
  const rootBuf = await merkle.computeRootHash(payload);
  const computedRoot = bufferTob64Url(rootBuf);
  const rootMatches = computedRoot === tx.data_root;

  // 2) format-2 signature data (deep hash) over the canonical field list, then
  //    RSA-PSS verify against the owner public key.
  const tagList = (tx.tags || []).map((t) => [b64UrlToBuffer(t.name), b64UrlToBuffer(t.value)]);
  const signatureData = await deepHash([
    stringToBuffer(String(tx.format)),
    b64UrlToBuffer(tx.owner),
    b64UrlToBuffer(tx.target || ''),
    stringToBuffer(tx.quantity || '0'),
    stringToBuffer(tx.reward),
    tx.last_tx ? b64UrlToBuffer(tx.last_tx) : new Uint8Array(0),
    tagList,
    stringToBuffer(tx.data_size),
    b64UrlToBuffer(tx.data_root),
  ]);
  const sigBytes = b64UrlToBuffer(tx.signature);
  const sigValid = await crypto.verify(tx.owner, signatureData, sigBytes);

  // 3) id == sha256(signature) base64url.
  const idBytes = await crypto.hash(sigBytes);
  const computedId = bufferTob64Url(idBytes);
  const idMatches = computedId === tx.id;

  const verdict = {
    pass: rootMatches && sigValid && idMatches,
    data_root_matches: rootMatches,
    signature_valid: sigValid,
    id_matches: idMatches,
    computed_root: computedRoot,
    tx_root: tx.data_root,
    computed_id: computedId,
    tx_id: tx.id,
  };
  console.log(JSON.stringify(verdict, null, 2));
  process.exit(verdict.pass ? 0 : 1);
}

main().catch((err) => {
  console.error(String(err && err.stack ? err.stack : err));
  process.exit(2);
});
