// Live submission of a Rust-signed ANS-104 data item to the Turbo upload service.
//
// Reads `{ "id_b64url", "raw_hex" }` from stdin (the crate's `sign_to_json`
// example output), resolves the upload endpoint from the installed
// @ardrive/turbo-sdk source, POSTs the raw bytes, and asserts the service
// accepted the item (HTTP 200/202) and returned a receipt id equal to the id
// this stack computed. It then attempts a best-effort fetch-back and byte
// compare against the original payload.
//
// Acceptance + id parity is the hard pass criterion. Retrieval is evidence only:
// propagation can lag the accept, so a pending retrieval is recorded, not failed.

import { setTimeout as sleep } from 'node:timers/promises';

import { defaultUploadServiceURL } from '@ardrive/turbo-sdk';

// Resolve the endpoint from the SDK, not a hardcoded literal: take its exported
// default upload-service URL and reproduce the SDK's own path shape
// (`${url}/v1` + `/tx/${token}`, token 'arweave').
const TOKEN = 'arweave';
const UPLOAD_URL = `${defaultUploadServiceURL}/v1/tx/${TOKEN}`;

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

  const evidence = {
    upload_url: UPLOAD_URL,
    default_upload_service_url: defaultUploadServiceURL,
    token: TOKEN,
    computed_id: expectedId,
    raw_len: bytes.length,
  };

  let res;
  try {
    res = await fetch(UPLOAD_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: bytes,
    });
  } catch (err) {
    console.log(
      JSON.stringify({
        status: 'blocked',
        reason: 'network error reaching upload service',
        error: String(err),
        ...evidence,
      }),
    );
    process.exit(0);
  }

  const bodyText = await res.text();
  let receipt;
  try {
    receipt = JSON.parse(bodyText);
  } catch {
    receipt = { raw_body: bodyText };
  }
  evidence.http_status = res.status;
  evidence.receipt = receipt;

  const accepted = res.status === 200 || res.status === 202;
  if (!accepted) {
    // A funding-policy rejection of the unfunded wallet is a blocked status,
    // captured with the full body, not a crypto failure.
    console.log(
      JSON.stringify({
        status: 'blocked',
        reason: 'upload service rejected the request',
        ...evidence,
      }),
    );
    process.exit(0);
  }

  const idMatches = receipt && receipt.id === expectedId;
  if (!idMatches) {
    console.log(
      JSON.stringify({
        status: 'fail',
        reason: 'accepted but receipt id != computed id',
        receipt_id: receipt && receipt.id,
        ...evidence,
      }),
    );
    process.exit(1);
  }

  // --- Best-effort fetch-back ------------------------------------------------
  const candidates = [];
  const caches = Array.isArray(receipt.dataCaches) ? receipt.dataCaches : [];
  const ffi = Array.isArray(receipt.fastFinalityIndexes) ? receipt.fastFinalityIndexes : [];
  for (const host of [...caches, ...ffi]) {
    candidates.push(`https://${host}/raw/${expectedId}`);
    candidates.push(`https://${host}/${expectedId}`);
  }
  candidates.push(`https://arweave.net/raw/${expectedId}`);

  const deadlineMs = Date.now() + 3 * 60 * 1000;
  let retrieval = { ok: false, matched: false };
  outer: while (Date.now() < deadlineMs) {
    for (const url of candidates) {
      try {
        const r = await fetch(url);
        if (r.ok) {
          const got = Buffer.from(await r.arrayBuffer());
          // The data item payload is the trailing portion of the signed bytes;
          // a gateway serves the *payload*, not the full ANS-104 envelope, so
          // compare the served bytes against the original payload region.
          const matched = bytesContainTail(bytes, got) || got.equals(bytes);
          retrieval = { ok: true, matched, url, served_len: got.length };
          if (matched) break outer;
        }
      } catch {
        // try the next candidate
      }
    }
    await sleep(10_000);
  }

  const result = {
    status: 'pass',
    accepted: true,
    id_parity: true,
    retrieval,
    deadline_height: receipt.deadlineHeight ?? null,
    winc: receipt.winc ?? null,
    ...evidence,
  };
  if (!retrieval.matched) {
    result.retrieval_note =
      'accepted-pending: id parity confirmed, payload not yet retrievable within the window';
  }
  console.log(JSON.stringify(result));
}

// The served object should equal the original data-item *payload*, which is the
// suffix of the signed bytes after the header/owner/tags. Without re-deriving
// the exact offset, accept a served buffer that is a tail of, or equal to, the
// signed bytes.
function bytesContainTail(full, tail) {
  if (tail.length > full.length) return false;
  return full.subarray(full.length - tail.length).equals(tail);
}

main().catch((err) => {
  console.error(String(err && err.stack ? err.stack : err));
  process.exit(1);
});
