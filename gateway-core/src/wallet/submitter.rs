//! Transaction submission behind a trait, with a non-production stub.
//!
//! [`Submitter`] is the seam between the wallet machinery and the chain: it takes
//! the signed transaction bytes that go on the wire, plus the transaction id the
//! builder already computed, and reports whether the network accepted them. The
//! real Koios submitter lands with the chain-submission work; until then
//! [`StubSubmitter`] simulates acceptance so the apply-change-locally path can be
//! exercised end to end against Postgres.
//!
//! Passing the transaction id alongside the signed bytes keeps the stub free of a
//! CBOR decoder: the signing step already produced the body hash, and a real
//! submitter would cross-check the id the node echoes against this value rather
//! than recompute it. The trait therefore never has to re-parse the transaction
//! it was handed.
//!
//! The stub carries a hard production guard: constructing it under a
//! production/mainnet config is an error, so a stub can never be wired into a
//! deployment that signs real mainnet transactions. This preserves the invariant
//! that simulated acceptance only ever happens on a test network.

use super::config::Network;
use crate::{Error, Result};

/// The outcome of submitting a signed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The network accepted the transaction; it is now in the mempool. Carries
    /// the 32-byte transaction id the submit applies its local change against.
    Accepted {
        /// The accepted transaction's id.
        tx_hash: [u8; 32],
    },
    /// The network rejected the transaction outright (a deterministic failure,
    /// e.g. a script/ledger error). The lease may be released without a
    /// re-query because the input was definitively not consumed.
    Rejected {
        /// The provider's rejection reason.
        reason: String,
    },
    /// The submit's result is unknown (transport error, timeout): the input may
    /// or may not have been consumed. The lease holder MUST re-query the chain
    /// before releasing the UTxO, never release blindly.
    Ambiguous {
        /// What went wrong, for diagnostics.
        detail: String,
    },
}

/// Submit a signed transaction to the network.
///
/// Implementations are the only component that talks to a submission endpoint.
/// The trait is the seam the wallet path builds, signs, and then submits
/// through, so the path itself is testable against a stub with no network.
///
/// `signed_tx` is the fully witnessed CBOR that goes on the wire; `tx_hash` is
/// the transaction id the builder computed when it signed, supplied so the
/// implementation reports it without re-decoding the transaction.
pub trait Submitter: Send + Sync {
    /// Submit the fully signed transaction bytes, identified by `tx_hash`.
    fn submit(
        &self,
        signed_tx: &[u8],
        tx_hash: [u8; 32],
    ) -> impl std::future::Future<Output = Result<SubmitOutcome>> + Send;
}

/// A non-production submitter that simulates acceptance.
///
/// Returns [`SubmitOutcome::Accepted`] with the transaction id the caller signed,
/// so the apply-change-locally path runs end to end without a real network. It
/// can only be constructed on a test network: [`StubSubmitter::new`] is a hard
/// error under a production config.
#[derive(Debug)]
pub struct StubSubmitter {
    network: Network,
}

impl StubSubmitter {
    /// Construct a stub submitter, refusing under a production config.
    ///
    /// Returns [`Error::Config`] when `network.is_production()` so a stub can
    /// never simulate acceptance on mainnet.
    pub fn new(network: Network) -> Result<Self> {
        if network.is_production() {
            return Err(Error::Config(
                "the stub submitter cannot be constructed on the production network".to_string(),
            ));
        }
        Ok(Self { network })
    }

    /// The network this stub is pinned to (always a test network).
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }
}

impl Submitter for StubSubmitter {
    async fn submit(&self, signed_tx: &[u8], tx_hash: [u8; 32]) -> Result<SubmitOutcome> {
        // The signed bytes are what a real submitter would put on the wire; the
        // stub does not need to parse them, only to confirm a non-empty
        // transaction was handed over before simulating acceptance.
        debug_assert!(
            !signed_tx.is_empty(),
            "a submit must carry the signed transaction bytes"
        );
        let _ = self.network;
        Ok(SubmitOutcome::Accepted { tx_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_accepts_with_the_supplied_tx_hash() {
        let stub = StubSubmitter::new(Network::Preprod).expect("preprod stub constructs");
        let tx_hash = [0x5a_u8; 32];
        let outcome = stub
            .submit(&[0x84, 0xa0, 0xf5, 0xf6], tx_hash)
            .await
            .expect("stub submit");
        assert_eq!(
            outcome,
            SubmitOutcome::Accepted { tx_hash },
            "the stub echoes the id the caller signed so apply-change-locally can run"
        );
    }

    #[test]
    fn stub_refuses_construction_on_mainnet() {
        let err = StubSubmitter::new(Network::Mainnet)
            .expect_err("a stub must never be constructible on the production network");
        assert!(
            matches!(err, Error::Config(_)),
            "the production guard is a configuration error, got {err:?}"
        );
    }

    #[test]
    fn stub_constructs_on_every_test_network() {
        for network in [Network::Preprod, Network::Preview] {
            let stub = StubSubmitter::new(network)
                .unwrap_or_else(|_| panic!("a stub must construct on {}", network.as_str()));
            assert_eq!(stub.network(), network);
        }
    }
}
