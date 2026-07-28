//! Simple servlet test for ServletConf pattern with workers

use std::sync::Arc;

use tightbeam::{
	colony::servlet::ServletConf,
	compose,
	compress::ZstdCompression,
	crypto::{
		aead::{Aes256Gcm, Aes256GcmOid, KeyInit},
		common::Key,
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey},
	},
	decode,
	der::Sequence,
	exactly,
	policy::{GatePolicy, SessionContext, TransitStatus},
	servlet, tb_assert_spec, tb_scenario,
	testing::{create_test_signing_key, ClientEnv, ServletEnv, SetupEnv},
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
	utils::urn::Urn,
	worker, Beamable, Frame, TightBeamError,
};

pub(crate) const DOUBLER_PROCESS: Urn<'static> = Urn::new("test", "event:servlet/doubler-process");
pub(crate) const SECURE_FRAME_CLEARTEXT: Urn<'static> = Urn::new("test", "event:servlet/secure-frame-cleartext");
pub(crate) const SECURE_RECEIVE: Urn<'static> = Urn::new("test", "event:servlet/secure-receive");
pub(crate) const SERVLET_RECEIVE: Urn<'static> = Urn::new("test", "event:servlet/servlet-receive");
pub(crate) const SERVLET_RESPOND: Urn<'static> = Urn::new("test", "event:servlet/servlet-respond");
pub(crate) const SQUARER_PROCESS: Urn<'static> = Urn::new("test", "event:servlet/squarer-process");
pub(crate) const VERIFY_DOUBLED: Urn<'static> = Urn::new("test", "event:servlet/verify-doubled");
pub(crate) const VERIFY_FINAL_RESULT: Urn<'static> = Urn::new("test", "event:servlet/verify-final-result");
pub(crate) const VERIFY_SECURE_DOUBLED: Urn<'static> = Urn::new("test", "event:servlet/verify-secure-doubled");
pub(crate) const VERIFY_SQUARED: Urn<'static> = Urn::new("test", "event:servlet/verify-squared");

// ============================================================================
// Messages
// ============================================================================

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcResponse {
	pub doubled: u32,
	pub squared: u32,
	pub final_result: u32, // Uses config multiplier on sum
}

// ============================================================================
// Workers
// ============================================================================

// Worker 1: Doubler (no config)
worker! {
	name: DoublerWorker<CalcRequest, Result<u32, TightBeamError>>,
	handle: |input, trace| async move {
		trace.event(DOUBLER_PROCESS)?;
		Ok(input.value * 2)
	}
}

// Worker 2: Squarer (with config)
worker! {
	name: SquarerWorker<CalcRequest, Result<u32, TightBeamError>>,
	config: {
		add_offset: u32,
	},
	handle: |input, trace, config| async move {
		trace.event(SQUARER_PROCESS)?;
		Ok(input.value * input.value + config.add_offset)
	}
}

// ============================================================================
// Servlet
// ============================================================================

// Define the servlet's environment config
#[derive(Clone)]
pub struct CalcServletConf {
	pub squarer_offset: u32,
	pub final_multiplier: u32,
	pub value: u32,
}

servlet! {
	/// Simple test servlet that USES config and workers
	pub CalcServlet<CalcRequest, EnvConfig = CalcServletConf>,
	protocol: TokioListener,
	handle: |request, frame, ctx| async move {
		let trace = ctx.trace();
		let config: &CalcServletConf = ctx.env_config()?;

		trace.event(SERVLET_RECEIVE)?;

		// Process with both workers in parallel via context
		let request_arc = Arc::new(request);
		let (doubled_result, squared_result) = tokio::join!(
			ctx.relay::<DoublerWorker>(Arc::clone(&request_arc)),
			ctx.relay::<SquarerWorker>(Arc::clone(&request_arc))
		);

		let doubled = doubled_result??;
		let squared = squared_result??;

		// USE THE CONFIG to compute final result
		let sum = doubled + squared;
		let final_result = sum * config.final_multiplier;

		trace.event(SERVLET_RESPOND)?;

		Ok(Some(compose! {
			V0: id: b"calc-response-id",
				message: CalcResponse { doubled, squared, final_result }
		}?))
	}
}

// ============================================================================
// Tests with tb_scenario!
// ============================================================================

tb_assert_spec! {
	pub CalcServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVLET_RECEIVE, exactly!(1)),
			(DOUBLER_PROCESS, exactly!(1)),
			(SQUARER_PROCESS, exactly!(1)),
			(SERVLET_RESPOND, exactly!(1)),
			(VERIFY_DOUBLED, exactly!(1), equals!(10u32)),
			(VERIFY_SQUARED, exactly!(1), equals!(35u32)),
			(VERIFY_FINAL_RESULT, exactly!(1), equals!(135u32))
		]
	}
}

tb_scenario! {
	name: test_servlet_conf_with_workers,
	spec: CalcServletSpec,
	environment Servlet {
		context: CalcServletConf {
			squarer_offset: 10,
			final_multiplier: 3,
			value: 5,
		},
		start: |SetupEnv { trace, context: config }| async move {
			let trace = Arc::new(trace);
			let doubler = DoublerWorker::new(());
			let squarer = SquarerWorker::new(SquarerWorkerConf {
				add_offset: config.squarer_offset
			});

			let servlet_conf = ServletConf::<TokioListener, CalcRequest>::builder()
				.with_config(config)
				.with_worker(doubler)
				.with_worker(squarer)
				.build();

			CalcServlet::start(trace, Some(servlet_conf)).await
		},
		setup: |ClientEnv { addr, .. }| async move {
			let builder = ClientBuilder::<TokioListener>::builder().build();
			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |ServletEnv { trace, mut client, context: config }| async move {
			let request = compose! {
				V0: id: b"calc-request-id",
					message: CalcRequest { value: config.value }
			}?;

			let response_frame = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = decode(&response_frame.message)?;

			trace.event_with(VERIFY_DOUBLED, &[], response.doubled)?;
			trace.event_with(VERIFY_SQUARED, &[], response.squared)?;
			trace.event_with(VERIFY_FINAL_RESULT, &[], response.final_result)?;

			Ok(())
		}
	}
}

// ============================================================================
// Typed delivery of the full feature stack: signed + encrypted + compressed
// + digested wire frames, normalized in place before the handler runs
// ============================================================================

fn shared_cipher() -> Aes256Gcm {
	Aes256Gcm::new(&Key::<Aes256Gcm>::from([0x5A; 32]))
}

/// Verifies nonrepudiation over the wire frame -- still ciphertext -- before
/// the typed prologue decrypts it in place.
struct SignatureGate {
	verifying_key: Secp256k1VerifyingKey,
}

impl GatePolicy for SignatureGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::PermissionDenied;
		};

		if frame.verify::<Secp256k1Signature, Sha3_256>(&self.verifying_key).is_ok() {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}
}

servlet! {
	/// Typed servlet whose signed, encrypted, compressed inbound frames are
	/// verified by the collector gate, then decrypted and decompressed in
	/// place by the capabilities configured via `with_message_decryptor` and
	/// `with_message_inflator`
	pub SecureCalcServlet<CalcRequest, EnvConfig = CalcServletConf>,
	protocol: TokioListener,
	handle: |request, frame, ctx| async move {
		let trace = ctx.trace();
		trace.event(SECURE_RECEIVE)?;
		trace.event_with(SECURE_FRAME_CLEARTEXT,
			&[],
			u32::from(frame.metadata.confidentiality.is_none() && frame.metadata.compactness.is_none()),
		)?;

		let doubled = request.value * 2;
		Ok(Some(compose! {
			V0: id: b"secure-calc-response-id",
				message: CalcResponse { doubled, squared: 0, final_result: 0 }
		}?))
	}
}

tb_assert_spec! {
	pub SecureCalcServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SECURE_RECEIVE, exactly!(1)),
			(SECURE_FRAME_CLEARTEXT, exactly!(1), equals!(1u32)),
			(VERIFY_SECURE_DOUBLED, exactly!(1), equals!(14u32))
		]
	}
}

tb_scenario! {
	name: test_typed_servlet_full_feature_stack,
	spec: SecureCalcServletSpec,
	environment Servlet {
		context: CalcServletConf {
			squarer_offset: 0,
			final_multiplier: 1,
			value: 7,
		},
		start: |SetupEnv { trace, context: config }| async move {
			let trace = Arc::new(trace);
			let verifying_key = *create_test_signing_key().verifying_key();
			let servlet_conf = ServletConf::<TokioListener, CalcRequest>::builder()
				.with_config(config)
				.with_collector_gate(SignatureGate { verifying_key })
				.with_message_decryptor(shared_cipher())
				.with_message_inflator(ZstdCompression::default())
				.build();

			SecureCalcServlet::start(trace, Some(servlet_conf)).await
		},
		setup: |ClientEnv { addr, .. }| async move {
			let builder = ClientBuilder::<TokioListener>::builder().build();
			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |ServletEnv { trace, mut client, context: config }| async move {
			let request = compose! {
				V2: id: b"secure-calc-request-id",
					order: 1u64,
					message: CalcRequest { value: config.value },
					compactness: ZstdCompression::default(),
					confidentiality<Aes256GcmOid, _>: shared_cipher(),
					nonrepudiation<Secp256k1Signature, _>: create_test_signing_key(),
					message_integrity<Sha3_256>: [],
					frame_integrity: type Sha3_256
			}?;

			let response_frame = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = decode(&response_frame.message)?;

			trace.event_with(VERIFY_SECURE_DOUBLED, &[], response.doubled)?;

			Ok(())
		}
	}
}
