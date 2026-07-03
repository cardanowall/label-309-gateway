# Security Policy

The Label 309 gateway is the open-source backend that publishes Proof-of-Existence
records to Cardano and serves the account-blind records feed. Operators run it
with real funds, real keys, and real user data, so we take reports seriously and
ask that they be handled responsibly.

## Scope

This repository holds the **gateway server**: the `gateway` binary and the
`gateway-core` engine (chain, storage, ledger, pricing, events, webhook, wallet,
runtime, maintenance, and the two HTTP planes), the `cardano-poe-tx` transaction
builder, the `ans104` Arweave bundler, and the `conformance` harness.

In scope for a report here:

- A flaw that lets an unauthenticated or wrongly-scoped caller reach a data-plane
  or control-plane operation they should not, or that lets one tenant read or
  affect another's records, balance, or credentials.
- A spend or funds-handling flaw: a publish or upload charged incorrectly, a
  refund issued when the transaction is on chain, an overdraft that should have
  been refused, or key material (the operator keyring, an Arweave JWK) exposed.
- A weakening of the outbound egress guard (the SSRF / deny-host policy on the
  webhook and storage paths).
- A record indexed into the shared feed that a standalone verifier would reject —
  a divergence between what the engine writes and what the standard defines.

Out of scope here (report it in the relevant repository instead):

- A flaw or ambiguity in the **standard** itself — report it in the `label-309`
  standard repository.
- A bug in the verification or cryptographic logic of the **SDK** — that lives in
  `label-309-rs` (and its byte-parity twins `label-309-ts` / `label-309-py`).

## Core security goals

A report is **high priority** if it undermines any of these guarantees:

- **Tenant isolation** — an operator, account, or credential can only reach what
  its scope grants; the shared records index is operator- and account-agnostic by
  design, never a cross-tenant leak.
- **Custody of funds and keys** — chain and storage spend is authorized, metered,
  and refused on overdraft; the operator keyring and storage keys never leave the
  process or land in a log.
- **Standalone verifiability** — every record the engine indexes verifies from the
  transaction metadata alone, with no trust in this server.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the *Security* tab -> *Report a vulnerability*).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can:

- A clear description of the issue and the security property it breaks.
- The exact location — crate, module, route, or migration — and a minimal
  reproduction.
- The impact and, if you have one, a suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue, and credit you unless you prefer otherwise.
- Because the gateway is **pre-1.0**, there are no long-term-supported released
  versions yet; fixes land on the current line.

Thank you for helping keep Label 309 trustworthy.
