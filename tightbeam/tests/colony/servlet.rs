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
	policy::{GatePolicy, TransitStatus},
	servlet, tb_assert_spec, tb_scenario,
	testing::{create_test_signing_key, ClientEnv, ServletEnv, SetupEnv},
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
	worker, Beamable, Frame, TightBeamError,
};

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
		trace.event(CalcServletSpec::doubler_process)?;
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
		trace.event(CalcServletSpec::squarer_process)?;
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

		trace.event(CalcServletSpec::servlet_receive)?;

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

		trace.event(CalcServletSpec::servlet_respond)?;

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
		gate: Accepted,
		assertions: [
			(servlet_receive, exactly!(1)),
			(doubler_process, exactly!(1)),
			(squarer_process, exactly!(1)),
			(servlet_respond, exactly!(1)),
			(verify_doubled, exactly!(1), equals!(10u32)),
			(verify_squared, exactly!(1), equals!(35u32)),
			(verify_final_result, exactly!(1), equals!(135u32))
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

			trace.event_with(CalcServletSpec::verify_doubled, &[], response.doubled)?;
			trace.event_with(CalcServletSpec::verify_squared, &[], response.squared)?;
			trace.event_with(CalcServletSpec::verify_final_result, &[], response.final_result)?;

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
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		if frame.verify::<Secp256k1Signature, Sha3_256>(&self.verifying_key).is_ok() {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
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
		trace.event(SecureCalcServletSpec::secure_receive)?;
		trace.event_with(SecureCalcServletSpec::secure_frame_cleartext,
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
		gate: Accepted,
		assertions: [
			(secure_receive, exactly!(1)),
			(secure_frame_cleartext, exactly!(1), equals!(1u32)),
			(verify_secure_doubled, exactly!(1), equals!(14u32))
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

			trace.event_with(SecureCalcServletSpec::verify_secure_doubled, &[], response.doubled)?;

			Ok(())
		}
	}
}
