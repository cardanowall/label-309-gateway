# Test fixtures

`test-signing-seed.hex` is a **test-only** 32-byte Ed25519 seed (all `0x01`
bytes). It exists so signed-transaction bytes are deterministic across test
runs. It is not a real key, controls no funds, and must never be used to sign a
mainnet transaction.

`corpus/` holds the shared build-scenario inputs consumed both by this crate's
tests and by an out-of-tree oracle. See `corpus/README.md`.

`corpus/rust-out/` holds machine-readable selection manifests emitted by the
manifest test (gated behind `POE_EMIT_MANIFESTS=1`); the directory is created on
demand and its contents are regenerated, not hand-edited.
