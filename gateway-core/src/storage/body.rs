//! Streaming reconstruction of a pre-signed ANS-104 data item into an HTTP body.
//!
//! A data item is, on the wire, a bounded prefix (the signature type, signature,
//! owner key, target/anchor frames, and the tag block) followed by the raw payload
//! bytes. The prefix is small and reconstructed in memory from the persisted
//! [`SignedEnvelope`] plus the owner key; the payload may be many gigabytes and is
//! streamed straight off the durable staged file. So a POST body carries the
//! prefix as its first chunk and then the staged file in bounded reads, and the
//! resident set never grows with the file size. Because the signature already
//! commits (via the deep-hash) to exactly those parts, the streamed body is
//! byte-identical to the once-signed item, which is what lets a retry re-POST
//! without re-signing.

use std::path::Path;

use ans104::{reconstruct_prefix, SignedEnvelope};
use futures_util::stream::{self, Stream, StreamExt};
use tokio::io::AsyncReadExt;

use crate::storage::backend::StorageError;

/// The largest single read issued against the staged file while streaming it.
///
/// Bounds the streaming loop's working set: the body is emitted in chunks of at
/// most this many bytes regardless of the file size, so a multi-gigabyte upload
/// POSTs with a fixed buffer rather than one allocation the size of the file.
pub(crate) const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Build the chunk stream that reconstructs a data item: the prefix first, then
/// the staged file in bounded reads.
///
/// Separated from [`streamed_data_item_body`] so the streaming behaviour can be
/// asserted directly (a multi-gigabyte file is reconstructed in bounded chunks)
/// without standing up an HTTP body. Each item is a `Result<Vec<u8>, io::Error>`,
/// which `reqwest::Body::wrap_stream` accepts.
fn data_item_chunk_stream(
    prefix: Vec<u8>,
    file: tokio::fs::File,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> + Send {
    let prefix_stream = stream::once(async move { Ok::<Vec<u8>, std::io::Error>(prefix) });
    let file_stream = stream::unfold(file, |mut file| async move {
        let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(buf), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    prefix_stream.chain(file_stream)
}

/// Build a streamed POST body for a pre-signed data item.
///
/// The first chunk is the reconstructed prefix (validated against the signature
/// type by [`reconstruct_prefix`]); every subsequent chunk is a bounded read of the
/// staged content at `staged_path`. The body owns the prefix and a file handle, so
/// the caller can hand it to `reqwest` directly; the staged file is opened here and
/// read lazily as the request is sent.
///
/// Returns [`StorageError::Build`] if the envelope or owner is malformed (a wrong
/// signature or owner length), and [`StorageError::Io`] if the staged file cannot
/// be opened.
pub async fn streamed_data_item_body(
    envelope: &SignedEnvelope,
    owner: &[u8],
    staged_path: &Path,
) -> Result<reqwest::Body, StorageError> {
    let prefix = reconstruct_prefix(envelope, owner)
        .map_err(|e| StorageError::Build(format!("reconstructing data-item prefix: {e}")))?;

    let file = tokio::fs::File::open(staged_path)
        .await
        .map_err(|e| StorageError::Io(format!("opening staged file: {e}")))?;

    Ok(reqwest::Body::wrap_stream(data_item_chunk_stream(
        prefix, file,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use ans104::{SignedEnvelope, RSA_4096_LEN, SIGNATURE_TYPE_ARWEAVE};

    /// A synthetic envelope whose framing lengths are valid (so `reconstruct_prefix`
    /// accepts it) without standing up a real signer. The signature is not verified
    /// here — this module's job is the byte-exact reconstruction of prefix ‖ payload,
    /// and the envelope's only structural requirements are the signature/owner
    /// lengths and a decodable (here empty) tag block.
    fn synthetic_envelope() -> (SignedEnvelope, Vec<u8>) {
        let signature = vec![0xABu8; RSA_4096_LEN];
        let owner = vec![0xCDu8; RSA_4096_LEN];
        let id = [0x11u8; 32];
        let envelope = SignedEnvelope {
            signature_type: SIGNATURE_TYPE_ARWEAVE,
            signature,
            id,
            id_b64url: ans104::base64url::encode(&id),
            target: None,
            anchor: None,
            tag_bytes: Vec::new(),
        };
        (envelope, owner)
    }

    /// Collect a chunk stream into one buffer (test-only — production streams it
    /// straight into the request body and never materialises it).
    async fn collect_chunks<S>(stream: S) -> Vec<u8>
    where
        S: Stream<Item = Result<Vec<u8>, std::io::Error>>,
    {
        futures_util::pin_mut!(stream);
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.expect("chunk io error"));
        }
        out
    }

    #[tokio::test]
    async fn reconstruction_is_prefix_then_staged_payload() {
        let (envelope, owner) = synthetic_envelope();
        let payload: Vec<u8> = (0..200_003u32).map(|i| (i % 251) as u8).collect();

        let mut staged = tempfile::NamedTempFile::new().expect("temp file");
        staged.write_all(&payload).expect("write staged");
        staged.flush().expect("flush staged");

        let prefix = reconstruct_prefix(&envelope, &owner).expect("prefix");
        let file = tokio::fs::File::open(staged.path()).await.expect("open");
        let reconstructed = collect_chunks(data_item_chunk_stream(prefix.clone(), file)).await;

        // The streamed body is exactly the bounded prefix followed by the verbatim
        // staged payload: the prefix carries the framing the signature commits to,
        // and the payload is the `data` element the deep-hash covered.
        let mut expected = prefix;
        expected.extend_from_slice(&payload);
        assert_eq!(reconstructed, expected, "streamed reconstruction diverged");
    }

    #[tokio::test]
    async fn large_payload_streams_in_bounded_chunks() {
        // A payload far larger than one read buffer must reconstruct with the
        // largest chunk bounded by STREAM_CHUNK_BYTES, so the resident set does not
        // grow with the file size.
        let (envelope, owner) = synthetic_envelope();
        let chunk = STREAM_CHUNK_BYTES;
        let payload_len = chunk * 40 + 7; // ~2.5 MiB, many reads, an odd tail.
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();

        let mut staged = tempfile::NamedTempFile::new().expect("temp file");
        staged.write_all(&payload).expect("write staged");
        staged.flush().expect("flush staged");

        let prefix = reconstruct_prefix(&envelope, &owner).expect("prefix");
        let file = tokio::fs::File::open(staged.path()).await.expect("open");

        let body_stream = data_item_chunk_stream(prefix.clone(), file);
        futures_util::pin_mut!(body_stream);
        let mut largest_after_prefix = 0usize;
        let mut total = Vec::new();
        let mut idx = 0usize;
        while let Some(chunk_res) = body_stream.next().await {
            let bytes = chunk_res.expect("chunk");
            // The first item is the prefix; every later item is a bounded file read.
            if idx > 0 {
                largest_after_prefix = largest_after_prefix.max(bytes.len());
            }
            total.extend_from_slice(&bytes);
            idx += 1;
        }

        assert!(
            largest_after_prefix <= STREAM_CHUNK_BYTES,
            "a payload chunk of {largest_after_prefix} bytes exceeded the {STREAM_CHUNK_BYTES}-byte read ceiling"
        );
        assert!(
            idx > 40,
            "the payload should have streamed across many reads, saw {idx} chunks"
        );
        let mut expected = prefix;
        expected.extend_from_slice(&payload);
        assert_eq!(total, expected, "streamed reconstruction diverged");
    }

    #[tokio::test]
    async fn missing_staged_file_is_an_io_error_not_a_panic() {
        let (envelope, owner) = synthetic_envelope();
        let missing = std::path::Path::new("/nonexistent/staged/file.stage");
        let err = streamed_data_item_body(&envelope, &owner, missing)
            .await
            .expect_err("a missing staged file is an error");
        assert!(matches!(err, StorageError::Io(_)), "got {err:?}");
    }
}
