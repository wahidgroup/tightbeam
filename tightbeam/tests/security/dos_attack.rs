//! # Denial-of-service (oversized message) threat
//!
//! ## Weakness
//! A server that processes attacker-sized handshake messages without an
//! up-front bound lets a single request exhaust its memory and CPU.
//!
//! ## Attack
//! A peer sends a server of each enabled backend (HPKE, CMS) a handshake
//! message whose header declares one octet more than 16 KiB, before any
//! handshake round.
//!
//! ## Expected control
//! The read of a handshake-phase message runs under the 16 KiB handshake
//! ceiling (`DEFAULT_HANDSHAKE_MAX_WIRE`), so the server MUST refuse the
//! message on its header, by its size (`SizeExceeded`), before it reads the
//! content.
//!
//! ## References
//! - CWE-400: Uncontrolled Resource Consumption <https://cwe.mitre.org/data/definitions/400.html>
//! - CWE-770: Allocation of Resources Without Limits or Throttling
//!   <https://cwe.mitre.org/data/definitions/770.html>
//! - CAPEC-130: Excessive Allocation <https://capec.mitre.org/data/definitions/130.html>

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::{MessageIO, TransportError, TransportFailure},
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{expectation_failure, HandshakeBackendKind, ServerMaterials, BACKEND_COUNT_U32};

pub(crate) const DOS_GENERATE_OVERSIZED: Urn<'static> =
	tightbeam::urn!("test", "event:dos-attack/dos-generate-oversized");
pub(crate) const DOS_INJECT_OVERSIZED: Urn<'static> = tightbeam::urn!("test", "event:dos-attack/dos-inject-oversized");
pub(crate) const DOS_OVERSIZED_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:dos-attack/dos-oversized-rejected");

/// The size ceiling of a handshake message (16 KiB) in the transport layer.
const HANDSHAKE_MAX_SIZE: usize = 16 * 1024;

tb_assert_spec! {
	pub DosAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DOS_GENERATE_OVERSIZED, exactly!(BACKEND_COUNT_U32)),
			(DOS_INJECT_OVERSIZED, exactly!(BACKEND_COUNT_U32)),
			(DOS_OVERSIZED_REJECTED, exactly!(BACKEND_COUNT_U32), equals!(true))
		]
	}
}

tb_process_spec! {
	pub DosAttackProcess,
	events {
		observable {

			DOS_GENERATE_OVERSIZED,
			DOS_INJECT_OVERSIZED,
			DOS_OVERSIZED_REJECTED
		}
		hidden { }
	}
	states {
		Idle => { DOS_GENERATE_OVERSIZED => OversizedReady },
		OversizedReady => { DOS_INJECT_OVERSIZED => Injected },
		Injected => { DOS_OVERSIZED_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "DoS attack: oversized handshake message rejection" }
}

tb_scenario! {
	name: dos_attack,
	config: ScenarioConfig::builder()
		.with_spec(DosAttackSpec::latest())
		.with_csp(DosAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			DosAttackScenario::run((trace.into(),)).await
		}
	}
}

/// A handshake message one octet past the cap: the header of a SEQUENCE of
/// `HANDSHAKE_MAX_SIZE + 1` octets, then that content.
fn oversized_message() -> Vec<u8> {
	let length = HANDSHAKE_MAX_SIZE + 1;
	let declared = u16::try_from(length).expect("the length fits two octets").to_be_bytes();
	let header = [0x30, 0x82, declared[0], declared[1]];
	[header.as_slice(), &vec![0u8; length]].concat()
}

/// Send `message` to the server at `addr` in one burst, as a peer before its
/// first handshake round.
async fn send(addr: SocketAddr, message: Vec<u8>) -> Result<(), TightBeamError> {
	let mut stream = TcpStream::connect(addr).await?;
	stream.write_all(&message).await?;
	Ok(())
}

job! {
	name: DosAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();

		for kind in HandshakeBackendKind::all() {
			// 1. Generate a handshake message one octet past the cap.
			let oversized = oversized_message();

			trace.event(DOS_GENERATE_OVERSIZED)?;

			// 2. Send it to a server of the backend, which reads it before any
			//    handshake round, under the handshake ceiling.
			let (listener, addr) = kind.bind_listener(&materials).await?;
			let sender = tokio::spawn(send(addr, oversized));
			let (mut server, _) = listener.accept().await?;

			trace.event(DOS_INJECT_OVERSIZED)?;

			// 3. The cap refuses the message on its header, by its size.
			let read = server.read_envelope_bytes().await;
			let refused = matches!(read, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
			trace.event_with(DOS_OVERSIZED_REJECTED, &[], refused)?;

			// 4. The sender wrote the whole message while the server held the connection.
			sender.await.map_err(|_| expectation_failure("the sender panicked"))??;
		}

		Ok(())
	}
}
