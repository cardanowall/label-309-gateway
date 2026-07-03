# Contributing to the Label 309 gateway

Thank you for your interest in improving the **Label 309 gateway** — the
open-source backend for **Proof of Existence (PoE)** anchored on the Cardano
blockchain. It owns the whole publish pipeline for an operator who runs it: the
Cardano transaction build/submit/confirm path, Arweave storage, the on-chain
records index, the balance ledger, pricing, and the data + control HTTP planes.

This server is **pre-1.0**. Its SemVer covers the configuration, the two HTTP
planes, and the database migrations together; treat any change to those as a
compatibility surface.

All contributions are made under the terms in [Licensing](#licensing) and the
[Developer Certificate of Origin](#developer-certificate-of-origin-dco).

---

## What belongs in this repository

This repository is the **gateway server** and its supporting crates (the
transaction builder, the Arweave bundler, the conformance harness). Bug fixes,
performance work, new operator surface, and server-specific issues belong here.

What does **not** belong here:

- **Changes to the wire format, grammar, schemas, registries, or the conformance
  vectors** belong in the `label-309` standard repository. The gateway must index
  records that a standalone verifier accepts; a divergence is a bug in the
  gateway, not the standard.
- **Verification or cryptographic logic** lives in the Label 309 SDK (the
  `cardanowall` crate, from `label-309-rs`). The gateway consumes the published SDK;
  fix verifier/crypto bugs there, not by re-implementing here.

If you are unsure, open an issue here and ask.

---

## Building and testing

A recent stable Rust toolchain and a reachable PostgreSQL are all you need; the
crates use `rustls` for TLS (no OpenSSL).

The engine's integration tests are gated behind the `pg-tests` feature and talk
to a real database. The harness owns its own test database — it admin-connects to
`postgres` and creates its database itself — so you only supply reachable
credentials through `GATEWAY_TEST_DATABASE_URL`:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --workspace --all-features

# Postgres-backed suites (the conformance harness, which drives published
# artifacts over the network, is excluded from the default run):
export GATEWAY_TEST_DATABASE_URL=postgres://USER:PASS@localhost:5432/gateway_test
cargo test --workspace --exclude conformance --all-features
```

CI runs exactly these against a Postgres service. A pull request must pass them.

### The pallas version line

The Cardano crates (`pallas-*`) have two parallel release lines on crates.io; the
workspace pins the 1.x line, and CI asserts every resolved pallas crate is 1.x.
Do not loosen those pins without moving the whole family together.

---

## Pull request checklist

- [ ] The change is in the right repository (this server vs. the standard vs. the
      SDK).
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, and the test suite pass.
- [ ] New behaviour is covered by a test; a schema change ships with a migration.
- [ ] No conformance vector was edited to force a test to pass.
- [ ] Every commit is signed off (see DCO below).

---

## Style and house rules

- Keep the server **operator-agnostic and vendor-neutral**: configuration drives
  network, keys, pricing, and storage; do not wire in a single hosted service.
- A record the engine indexes must verify standalone. When you touch the indexer
  or the transaction builder, keep the on-chain bytes something the published SDK
  verifier accepts.
- Cite only stable, public references — RFCs, CIPs at a permanent address,
  NIST/FIPS publications, BIPs, and the like.

---

## Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin**. There is **no CLA**.

The DCO is a lightweight attestation that you have the right to submit your
contribution under the project's license. You make it by adding a
`Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically with `git commit -s`. The name and email must be real and
match the commit author. By signing off, you certify the statements in the
Developer Certificate of Origin, version 1.1:

> **Developer Certificate of Origin, Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

---

## Licensing

By contributing, you agree that your contributions are licensed under the
project's **Apache License 2.0** (see [`LICENSE`](LICENSE)).

---

## Code of Conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before contributing.

## Security

Do not report security-impacting issues through public issues or pull requests.
Follow the private process in our [Security Policy](SECURITY.md).
