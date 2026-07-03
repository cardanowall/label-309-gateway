// Conformance: drive the PUBLISHED TypeScript SDK against a running gateway.
//
// Pins @cardanowall/sdk-ts to the exact released version (a normal npm install,
// not a workspace link) so a drift in the gateway's wire shape surfaces as a
// deserialize failure in the real published client a third party would install.
//
// Usage (the live conformance gate runs this after booting the gateway and
// seeding a tenant directly in the database):
//
//   GATEWAY_BASE_URL=http://127.0.0.1:PORT \
//   GATEWAY_CONFORMANCE_API_KEY=<seeded key> \
//   node sdk-ts-flows.mjs
//
// The API key is seeded by the Rust orchestrator (conformance::seed_tenant); this
// script receives it via the environment and never prints it. Every flow uses the
// published deserializers, so a wire regression throws here.

import { Label309Client, encodePoeRecord } from '@cardanowall/sdk-ts';

const baseUrl = process.env.GATEWAY_BASE_URL;
const apiKey = process.env.GATEWAY_CONFORMANCE_API_KEY;

if (!baseUrl || !apiKey) {
  console.error(
    'set GATEWAY_BASE_URL and GATEWAY_CONFORMANCE_API_KEY for the live conformance run',
  );
  process.exit(2);
}

/** Assert a condition, exiting non-zero with a message on failure. */
function check(condition, message) {
  if (!condition) {
    console.error(`ts-sdk conformance FAILED: ${message}`);
    process.exit(1);
  }
}

const client = new Label309Client({ baseUrl, apiKey });

// --- Read flows: the balance and the list envelope decode. ---
// `account.balance()` re-maps the wire `balance_usd_micros` to `balanceUsdMicros`.
const balance0 = await client.account.balance();
check(typeof balance0.balanceUsdMicros === 'string', 'balanceUsdMicros must be a decimal string');

// `records.list()` returns the raw wire envelope (snake_case fields).
const page = await client.records.list();
check(page.object === 'list', 'records list envelope must carry object: "list"');

// --- Quote: the published QuoteResponse requires amount + currency (the exact
// fields M7 adds). A missing field throws in the SDK's decoder. ---
// The TS encoder takes `hashes` as an object map { alg: digestBytes }, the same
// canonical `{ alg: digest }` shape the wire format uses.
const record = encodePoeRecord({
  v: 1,
  items: [{ hashes: { 'sha2-256': new Uint8Array(32).fill(0xd4) } }],
});
const quote = await client.poe.quote({
  recordBytes: record.length,
  recipientCount: 0,
  fileBytesTotal: 0,
});
check(typeof quote.quote_id === 'string' && quote.quote_id.length > 0, 'quote carries an id');
check(quote.currency === 'USD', `quote currency must be USD, got ${quote.currency}`);
check(quote.amount === '1250000', `quote amount must be the priced total, got ${quote.amount}`);

// --- Publish (fresh): 202, dedup_hit === false, one debit. ---
const fresh = await client.poe.publish({ record, quoteId: quote.quote_id });
check(fresh.dedup_hit === false, 'a fresh publish is 202 (dedup_hit === false)');
check(typeof fresh.id === 'string' && fresh.id.startsWith('poe_'), 'publish returns a wire id');
check(fresh.items_count === 1, 'the record has one content item');
check(
  fresh.conformance_profile === 'core',
  `an open unsigned record is the core profile, got ${fresh.conformance_profile}`,
);
check(
  fresh.balance_after_usd_micros === '48750000',
  `balance debited once, got ${fresh.balance_after_usd_micros}`,
);

// --- Re-publish identical bytes with a NEW quote: 200, dedup_hit === true,
// no second debit. ---
const quote2 = await client.poe.quote({
  recordBytes: record.length,
  recipientCount: 0,
  fileBytesTotal: 0,
});
const dup = await client.poe.publish({ record, quoteId: quote2.quote_id });
check(dup.dedup_hit === true, 're-publishing identical bytes is 200 (dedup_hit === true)');
check(dup.id === fresh.id, "the dedup hit returns the prior record's id");
check(
  dup.balance_after_usd_micros === '48750000',
  `the dedup hit charges nothing more, got ${dup.balance_after_usd_micros}`,
);

// --- Balance read confirms the single debit through the published decoder. ---
const balance1 = await client.account.balance();
check(
  balance1.balanceUsdMicros === '48750000',
  `the published balance decoder agrees with the publish response, got ${balance1.balanceUsdMicros}`,
);

console.log('ts-sdk conformance: quote/publish/dedup/balance flows green');
