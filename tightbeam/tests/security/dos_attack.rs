//! # Denial-of-service (oversized message) threat
//!
//! ## Weakness
//! A server that processes attacker-sized handshake messages without an
//! up-front bound lets a single request exhaust its memory and CPU.
//!
//! ## Attack
//! A peer sends a server of each enabled backend (HPKE, CMS) the header of a
//! handshake message that declares one octet more than 16 KiB, before any
//! handshake round, and holds the link open with no content.
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

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use tightbeam::{
	constants::DEFAULT_HANDSHAKE_MAX_WIRE,
	exactly,
	instrumentation::events,
	job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::{EncryptedMessageIO, TransportError, TransportFailure},
	urn::Urn,
	TightBeamError,
};

use crate::common::poll::within_hang_guard;
use crate::common::security::ServerMaterials;
use crate::security::common::HandshakeBackendKind;

pub(crate) const DOS_GENERATE_OVERSIZED: Urn<'static> =
	tightbeam::urn!("test", "event:dos-attack/dos-generate-oversized");
pub(crate) const DOS_INJECT_OVERSIZED: Urn<'static> = tightbeam::urn!("test", "event:dos-attack/dos-inject-oversized");

tb_assert_spec! {
	pub DosAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DOS_GENERATE_OVERSIZED, exactly!(1)),
			(DOS_INJECT_OVERSIZED, exactly!(1)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("SizeExceeded"))
		]
	}
}

tb_process_spec! {
	pub DosAttackProcess,
	events {
		observable {

			DOS_GENERATE_OVERSIZED,
			DOS_INJECT_OVERSIZED,
			events::TRANSPORT_ENVELOPE_REFUSED
		}
		hidden { }
	}
	states {
		Idle => { DOS_GENERATE_OVERSIZED => OversizedReady },
		OversizedReady => { DOS_INJECT_OVERSIZED => Injected },
		Injected => { events::TRANSPORT_ENVELOPE_REFUSED => Idle }
	}
	terminal { Idle }
	annotations { description: "DoS attack: oversized handshake message rejection" }
}

tb_scenario! {
	name: dos_attack_hpke,
	config: ScenarioConfig::builder()
		.with_spec(DosAttackSpec::latest())
		.with_csp(DosAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			DosAttackScenario::run((trace.into(), HandshakeBackendKind::Hpke)).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: dos_attack_cms,
	config: ScenarioConfig::builder()
		.with_spec(DosAttackSpec::latest())
		.with_csp(DosAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			DosAttackScenario::run((trace.into(), HandshakeBackendKind::Cms)).await
		}
	}
}

/// The header of a handshake message one octet past the cap: a SEQUENCE of
/// `DEFAULT_HANDSHAKE_MAX_WIRE + 1` octets.
fn oversized_header() -> [u8; 4] {
	let length = DEFAULT_HANDSHAKE_MAX_WIRE + 1;
	let declared = u16::try_from(length).expect("the length fits two octets").to_be_bytes();
	[0x30, 0x82, declared[0], declared[1]]
}

job! {
	name: DosAttackScenario,
	async fn run((trace, kind): (Arc<TraceCollector>, HandshakeBackendKind)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::fixed();

		// 1. Generate the header of a handshake message one octet past the cap.
		let oversized = oversized_header();

		trace.event(DOS_GENERATE_OVERSIZED)?;

		// 2. Send it to a server of the backend, which reads it before any
		//    handshake round, under the handshake ceiling, and files its
		//    refusal in the scenario trace. The peer sends no content and holds
		//    its link open, so a reader that waits for the content hangs.
		let (listener, addr) = kind.bind_listener(&materials).await?;
		let mut peer = TcpStream::connect(addr).await?;
		peer.write_all(&oversized).await?;

		let (server, _) = listener.accept().await?;
		let mut server = server.with_trace(trace.share());

		trace.event(DOS_INJECT_OVERSIZED)?;

		// 3. The cap refuses the message on its header, by its size.
		let read = within_hang_guard(server.collect_step(), "the server waited for the content").await;
		assert!(matches!(read, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))));
		drop(peer);

		Ok(())
	}
}
