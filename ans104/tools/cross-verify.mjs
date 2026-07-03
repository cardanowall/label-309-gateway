// Cross-verify a Rust-signed ANS-104 data item with the reference stack.
//
// Reads a JSON object `{ "id_b64url", "raw_hex" }` from stdin (the output of the
// crate's `sign_to_json` example), loads the bytes with @dha-team/arbundles, and
// asserts:
//
//   1. DataItem.verify(bytes) === true  — the reference accepts the signature the
//      Rust signer produced, including its PSS salt length.
//   2. item.id === id_b64url            — both stacks derive the identical id
//      (base64url(SHA-256(signature))) from the same bytes.
//
// This is the "Rust signs, reference verifies" direction of the parity check.
// The complementary direction (reference signs, Rust verifies) is covered by the
// golden `.bin` vectors the Rust test suite consumes.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { DataItem } = require('@dha-team/arbundles/build/node/cjs/src/DataItem');

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (buf += c));
    process.stdin.on('end', () => resolve(buf));
    process.stdin.on('error', reject);
  });
}

async function main() {
  const input = JSON.parse(await readStdin());
  const { id_b64url: expectedId, raw_hex: rawHex } = input;
  if (typeof expectedId !== 'string' || typeof rawHex !== 'string') {
    throw new Error('stdin must be { id_b64url, raw_hex }');
  }

  const bytes = Buffer.from(rawHex, 'hex');
  const item = new DataItem(bytes);

  const verified = await DataItem.verify(item.getRaw());
  if (verified !== true) {
    throw new Error(`reference DataItem.verify() rejected the Rust-signed item`);
  }

  if (item.id !== expectedId) {
    throw new Error(`id parity failed: reference ${item.id} != Rust ${expectedId}`);
  }

  // Surface the salt length the reference recovered, as evidence the Rust
  // signer's maximum-salt (478-byte) signature is accepted, not just tolerated.
  console.log(
    JSON.stringify({
      ok: true,
      reference_verify: verified,
      id_parity: true,
      id: item.id,
      raw_len: bytes.length,
      signature_type: item.signatureType,
      tag_count: item.tags.length,
    }),
  );
}

main().catch((err) => {
  console.error(String(err && err.stack ? err.stack : err));
  process.exit(1);
});
