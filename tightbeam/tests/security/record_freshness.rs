//! # Record nonce and content-key reuse threat
//!
//! ## Weakness
//! An AEAD record that reuses a nonce under one content key, or a content key
//! across records, lets an observer relate two ciphertexts and, for GCM,
//! recover the authentication key.
//!
//! ## Attack
//! A passive observer in the relay keeps the sealed records that a client
//! sends on an established HPKE session, and compares the wrapped content key
//! and the GCM nonce of two consecutive records.
//!
//! ## Expected control
//! Each record MUST draw a fresh content key and a fresh nonce, and wrap the
//! content key under the session key (RFC 5084 §3.2), so no two records share
//! either value.
//!
//! ## References
//! - CWE-323: Reusing a Nonce, Key Pair in Encryption <https://cwe.mitre.org/data/definitions/323.html>
//! - NIST SP 800-38D §8: IV/nonce uniqueness requirements for GCM
//! - RFC 5084 §3.2: AES-GCM in CMS <https://datatracker.ietf.org/doc/html/rfc5084#section-3.2>

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio"
))]

use tightbeam::testing::TestFrame;
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope};

use crate::common::result::TestResult;
use crate::common::security::ServerMaterials;
use crate::security::common::{fresh_values, sealed_record, Direction, HandshakeBackendKind};
use crate::security::live::{FrameSlot, LiveHandshake, LiveOutcome};

/// The first sealed record of the client, after its two handshake frames.
const FIRST_RECORD: FrameSlot = FrameSlot { direction: Direction::ClientToServer, ordinal: 3 };

/// The second sealed record of the client.
const SECOND_RECORD: FrameSlot = FrameSlot { direction: Direction::ClientToServer, ordinal: 4 };

/// A request that carries an empty test frame.
fn plain_request() -> TransportEnvelope {
	TransportEnvelope::new_request(TestFrame::v0(None, None))
}

/// Two consecutive records of one session carry two wrapped content keys and
/// two nonces.
#[tokio::test]
async fn consecutive_records_draw_a_fresh_content_key_and_nonce() -> TestResult {
	let link = LiveHandshake::new(HandshakeBackendKind::Hpke, ServerMaterials::fixed());
	let LiveOutcome { client, server, relay } = link.run().await?;
	let (mut reader, _) = server?.into_split()?;
	let (_, mut writer) = client?.into_split()?;
	writer.write_envelope(plain_request()).await?;
	writer.write_envelope(plain_request()).await?;
	reader.read_envelope().await?;
	reader.read_envelope().await?;

	let first = fresh_values(&sealed_record(relay.frame(FIRST_RECORD)?)?)?;
	let second = fresh_values(&sealed_record(relay.frame(SECOND_RECORD)?)?)?;
	assert_ne!(first.0, second.0);
	assert_ne!(first.1, second.1);
	Ok(())
}
