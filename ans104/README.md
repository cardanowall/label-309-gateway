# ans104

Pure-Rust construction, signing, and verification of [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md)
data items (the bundled-data-item format used to post content to Arweave). The
crate builds a data item from owner key, target, anchor, tags, and payload;
computes the ANS-104 deep-hash over that structure; signs the deep-hash with
RSA-PSS (the `arweave` signature type, a 4096-bit RSA key); and verifies an
existing item by recomputing the deep-hash and checking the signature against
the embedded owner.

It has no network dependency and no Arweave-client coupling: it produces and
checks the canonical data-item bytes, and leaves submission to the caller. The
deep-hash and tag (Avro) encodings are implemented directly against the
ANS-104 specification so the output is byte-compatible with other conforming
implementations.
