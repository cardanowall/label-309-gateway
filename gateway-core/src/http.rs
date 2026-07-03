//! Capped reads of external-provider HTTP response bodies.
//!
//! A direct `reqwest` `.json()` / `.text()` buffers the WHOLE response body into
//! memory before the caller sees a byte, so a hostile or compromised provider
//! (Koios, Blockfrost, Turbo, the payment service, an Arweave node) that answers
//! with a multi-gigabyte body — or a small body with a huge declared
//! `Content-Length` — can drive the process out of memory. Every external-provider
//! body read routes through the readers here instead: they reject an over-ceiling
//! declared length up front, stream the body into a bounded buffer with a hard
//! byte ceiling (failing with a typed error the instant the ceiling is crossed),
//! and only then deserialize from the bounded bytes.
//!
//! The ceiling is a caller-chosen class, not a single global constant, because a
//! legitimate body's size depends on the endpoint:
//!
//! - [`JSON_BODY_CEILING`] (8 MiB) — the general provider-JSON class: Koios /
//!   Blockfrost list, status, info, tip, and block reads; Turbo receipts; the
//!   payment service's info / balance / fund-registration bodies. These are all
//!   small in practice; 8 MiB is generous headroom that also covers the largest
//!   legitimate JSON body the scan requests — a batched `/tx_cbor` (up to ~70
//!   transactions, each a Cardano transaction bounded by the ledger's ~16 KiB
//!   `maxTxSize`, rendered as hex) — with several times the room it needs.
//! - [`DIAGNOSTIC_BODY_CEILING`] (64 KiB) — an error/diagnostic body read only to
//!   quote back in a log or error message. The caller truncates further for the
//!   message; this ceiling bounds the READ so a hostile 4xx/5xx body cannot OOM
//!   us before the truncation runs.
//!
//! The cap is applied to the DECOMPRESSED stream (reqwest decompresses
//! transparently), so a compression bomb whose compressed size slips under the
//! declared-length check is still caught mid-stream.

/// The general provider-JSON body ceiling: 8 MiB. Covers every provider JSON read
/// the engine makes, including a batched `/tx_cbor` of ledger-max transactions,
/// with generous headroom while still refusing a runaway body.
pub const JSON_BODY_CEILING: usize = 8 * 1024 * 1024;

/// The diagnostic/error body ceiling: 64 KiB. An error body is read only to quote
/// in a message; this bounds the read so a hostile error body cannot OOM us.
pub const DIAGNOSTIC_BODY_CEILING: usize = 64 * 1024;

/// A capped body read that refused or could not complete.
#[derive(Debug, thiserror::Error)]
pub enum CappedBodyError {
    /// The response declared a `Content-Length` above the ceiling: refused before
    /// a single body byte was read.
    #[error("response declared {declared} bytes, over the {ceiling}-byte ceiling")]
    DeclaredTooLarge {
        /// The declared `Content-Length`.
        declared: u64,
        /// The ceiling it exceeded.
        ceiling: usize,
    },
    /// The streamed body grew past the ceiling: refused mid-stream, so an
    /// unbounded or chunked-encoding body (no declared length) is still capped.
    #[error("response body exceeded the {ceiling}-byte ceiling")]
    StreamTooLarge {
        /// The ceiling the stream exceeded.
        ceiling: usize,
    },
    /// A transport failure while streaming the body.
    #[error("reading response body: {0}")]
    Transport(String),
    /// The bounded bytes did not decode into the expected type.
    #[error("decoding response body: {0}")]
    Decode(String),
}

/// Read a response body into a bounded buffer, never exceeding `ceiling` bytes.
///
/// Rejects an over-ceiling declared `Content-Length` before reading anything, then
/// streams the body chunk by chunk, failing with [`CappedBodyError::StreamTooLarge`]
/// the instant the accumulated size would cross the ceiling (so a body with no
/// declared length, or one whose real size exceeds a smaller declared length, is
/// still bounded).
pub async fn read_capped_bytes(
    mut response: reqwest::Response,
    ceiling: usize,
) -> std::result::Result<Vec<u8>, CappedBodyError> {
    if let Some(declared) = response.content_length() {
        if declared > ceiling as u64 {
            return Err(CappedBodyError::DeclaredTooLarge { declared, ceiling });
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| CappedBodyError::Transport(e.to_string()))?
    {
        if buf.len().saturating_add(chunk.len()) > ceiling {
            return Err(CappedBodyError::StreamTooLarge { ceiling });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a response body capped at `ceiling`, then deserialize it as JSON.
pub async fn read_capped_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    ceiling: usize,
) -> std::result::Result<T, CappedBodyError> {
    let bytes = read_capped_bytes(response, ceiling).await?;
    serde_json::from_slice(&bytes).map_err(|e| CappedBodyError::Decode(e.to_string()))
}

/// Read a response body capped at `ceiling`, then decode it as (lossy) UTF-8 text.
pub async fn read_capped_text(
    response: reqwest::Response,
    ceiling: usize,
) -> std::result::Result<String, CappedBodyError> {
    let bytes = read_capped_bytes(response, ceiling).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read an error/diagnostic body to quote in a log or error message, bounded at
/// [`DIAGNOSTIC_BODY_CEILING`] and never failing: a transport error yields what
/// was read so far, and an over-ceiling body yields its bounded prefix (the
/// caller truncates further for the message). The point is that quoting a hostile
/// provider's error body can never OOM the process.
pub async fn read_diagnostic_body(mut response: reqwest::Response) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < DIAGNOSTIC_BODY_CEILING {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = DIAGNOSTIC_BODY_CEILING - buf.len();
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the ceiling mid-chunk
                }
            }
            _ => break, // end of body, or a transport error: return what we have
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-shot loopback server that answers a single request with the
    /// given status line, optional explicit `Content-Length`, and body bytes.
    async fn spawn_once(
        status_line: &'static str,
        declared_len: Option<usize>,
        body: Vec<u8>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let len = declared_len.unwrap_or(body.len());
            let header = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.flush().await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_normal_json_body_parses_within_the_ceiling() {
        let body = serde_json::json!({ "ok": true, "n": 7 }).to_string();
        let url = spawn_once("HTTP/1.1 200 OK", None, body.into_bytes()).await;
        let resp = reqwest::get(&url).await.expect("request");
        let value: serde_json::Value = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .expect("a small body parses");
        assert_eq!(value["n"], 7);
    }

    #[tokio::test]
    async fn a_declared_over_ceiling_length_is_refused_before_reading() {
        // A tiny real body but a declared Content-Length far over the ceiling: the
        // read is refused up front on the header alone.
        let url = spawn_once("HTTP/1.1 200 OK", Some(50_000_000), b"{}".to_vec()).await;
        let resp = reqwest::get(&url).await.expect("request");
        let err = read_capped_json::<serde_json::Value>(resp, 1024)
            .await
            .expect_err("an over-ceiling declared length is refused");
        assert!(
            matches!(
                err,
                CappedBodyError::DeclaredTooLarge {
                    declared: 50_000_000,
                    ceiling: 1024
                }
            ),
            "expected a declared-too-large refusal, got {err:?}"
        );
    }

    /// Spawn a one-shot server that answers with a chunked-transfer-encoded body
    /// (NO `Content-Length`), so the declared-length gate cannot fire and only the
    /// streaming cap bounds the body. This is the shape the streaming cap defends:
    /// chunked encoding, or a compression bomb whose declared/compressed size is
    /// small but whose decoded stream is large.
    async fn spawn_chunked(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(header.as_bytes()).await;
            // One HTTP chunk carrying the whole body, then the terminating chunk.
            let _ = socket
                .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                .await;
            let _ = socket.write_all(&body).await;
            let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
            let _ = socket.flush().await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_body_streaming_past_the_ceiling_is_refused_mid_stream() {
        // A chunked body (no Content-Length) larger than the ceiling: the
        // declared-length gate cannot fire, so only the streaming cap can catch it.
        let ceiling = 1024usize;
        let url = spawn_chunked(vec![b'a'; 4096]).await;
        let resp = reqwest::get(&url).await.expect("request");
        let err = read_capped_bytes(resp, ceiling)
            .await
            .expect_err("a body past the ceiling is refused mid-stream");
        assert!(
            matches!(err, CappedBodyError::StreamTooLarge { ceiling: 1024 }),
            "expected a stream-too-large refusal, got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_ceiling_is_accepted() {
        let ceiling = 1024usize;
        let body = vec![b'x'; ceiling];
        let url = spawn_once("HTTP/1.1 200 OK", None, body).await;
        let resp = reqwest::get(&url).await.expect("request");
        let bytes = read_capped_bytes(resp, ceiling)
            .await
            .expect("a body exactly at the ceiling is accepted");
        assert_eq!(bytes.len(), ceiling);
    }

    #[tokio::test]
    async fn a_diagnostic_body_is_bounded_and_never_fails() {
        // A hostile error body far over the diagnostic ceiling yields only its
        // bounded prefix, never an error and never the whole body.
        let body = vec![b'z'; DIAGNOSTIC_BODY_CEILING * 4];
        let url = spawn_once("HTTP/1.1 500 Internal Server Error", None, body).await;
        let resp = reqwest::get(&url).await.expect("request");
        let text = read_diagnostic_body(resp).await;
        assert_eq!(
            text.len(),
            DIAGNOSTIC_BODY_CEILING,
            "the diagnostic read is bounded at its ceiling"
        );
    }
}
