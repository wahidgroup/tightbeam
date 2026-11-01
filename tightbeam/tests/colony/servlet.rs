//! The servlet tests of the `ServletConfig` pattern with workers.

use std::sync::Arc;

use tightbeam::{
	builder::TypeBuilder,
	colony::{hive::ServletBox, servlet::ServletConfig},
	compose,
	compress::ZstdCompression,
	crypto::{
		hash::Sha3_256,
		key::Aes256GcmKeyProvider,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	der::Sequence,
	exactly,
	instrumentation::events,
	servlet, tb_assert_spec, tb_scenario,
	testing::{
		fixtures::TestTrace, ClientEnv, ScenarioConfig, ServletEnv, SetupEnv, TestCertificate, TestIdentity, TestKey,
	},
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, TransportError, TransportFailure},
	urn::Urn,
	worker, Beamable, Frame, TightBeamError, Version,
};

use crate::colony::tracker_at;
use crate::common::result::TestResult;
use crate::common::security::{fixed_signing_key, SignatureGate};

pub(crate) const DOUBLER_PROCESS: Urn<'static> = tightbeam::urn!("test", "event:servlet/doubler-process");
pub(crate) const SQUARER_PROCESS: Urn<'static> = tightbeam::urn!("test", "event:servlet/squarer-process");

// The request and response messages

/// The request whose `value` the calc servlets double.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcRequest {
	/// The number the servlet doubles, which the [`CalcServlet`] also squares.
	pub value: u32,
}

/// The reply of a calc servlet. The [`CalcServlet`] computes each field, and
/// the other servlets set `doubled` alone.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcResponse {
	/// Twice the request's `value`.
	pub doubled: u32,
	/// The square of the request's `value` plus the squarer offset.
	pub squared: u32,
	/// The sum of `doubled` and `squared` times the config multiplier.
	pub final_result: u32,
}

// Workers

// Worker 1: the doubler, with no config.
worker! {
	name: DoublerWorker<CalcRequest, Result<u32, TightBeamError>>,
	handle: |input, trace| async move {
		trace.event(DOUBLER_PROCESS)?;
		Ok(input.value * 2)
	}
}

// Worker 2: the squarer, with a config.
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

// Servlet

// The environment config of the servlet.
#[derive(Clone)]
pub struct CalcServletConfig {
	pub squarer_offset: u32,
	pub final_multiplier: u32,
	pub value: u32,
}

servlet! {
	/// A test servlet that uses its config and both workers.
	pub CalcServlet<CalcRequest, EnvConfig = CalcServletConfig>,
	protocol: TokioListener,
	handle: |request, frame, ctx| async move {
		let config: &CalcServletConfig = ctx.env_config();

		// The context relays the request to both workers in parallel.
		let request_arc = Arc::new(request);
		let (doubled_result, squared_result) = tokio::join!(
			ctx.relay::<DoublerWorker>(Arc::clone(&request_arc)),
			ctx.relay::<SquarerWorker>(Arc::clone(&request_arc))
		);

		let doubled = doubled_result??;
		let squared = squared_result??;

		// The config multiplier scales the sum into the final result.
		let sum = doubled + squared;
		let final_result = sum * config.final_multiplier;

		Ok(Some(compose! {
			V0: id: b"calc-response-id",
				message: CalcResponse { doubled, squared, final_result }
		}?))
	}
}

// Scenarios under `tb_scenario!`

tb_assert_spec! {
	pub CalcServletSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HANDLER_ENTER, exactly!(1)),
			(DOUBLER_PROCESS, exactly!(1)),
			(SQUARER_PROCESS, exactly!(1)),
			(events::HANDLER_EXIT, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_servlet_conf_with_workers,
	config: ScenarioConfig::builder()
		.with_spec(CalcServletSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Servlet {
		context: CalcServletConfig {
			squarer_offset: 10,
			final_multiplier: 3,
			value: 5,
		},
		start: |SetupEnv { trace, context: config }| async move {
			let trace = Arc::new(trace);
			let doubler = DoublerWorker::new(());
			let squarer = SquarerWorker::new(SquarerWorkerConfig {
				add_offset: config.squarer_offset
			});

			let servlet_conf = ServletConfig::<TokioListener, CalcRequest>::builder()
				.with_config(config)
				.with_worker(doubler)
				.with_worker(squarer)
				.allow_cleartext()
				.build();

			CalcServlet::start(trace, servlet_conf).await
		},
		setup: |ClientEnv { addr, .. }| async move {
			let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |ServletEnv { mut client, context: config, .. }| async move {
			let request = compose! {
				V0: id: b"calc-request-id",
					message: CalcRequest { value: config.value }
			}?;

			let response_frame = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = response_frame.decode_message()?;

			assert_eq!(response.doubled, 10, "the doubler doubles 5");
			assert_eq!(response.squared, 35, "the squarer squares 5 and adds its offset");
			assert_eq!(response.final_result, 135, "the servlet multiplies the sum by its config");

			Ok(())
		}
	}
}

// Typed delivery of the full feature stack: signed, encrypted, compressed, and
// digested wire frames, which the prologue normalizes in place before the
// handler runs.

fn shared_cipher() -> Aes256GcmKeyProvider {
	let cipher = Aes256GcmKeyProvider::new(vec![0x5A; 32], b"tb/test/servlet/kek/v1".to_vec());
	cipher.expect("32 octets is the key of AES-256 key wrap")
}

/// The config of a [`SecureCalcServlet`] over `config`. Its collector gate
/// admits the signature of [`TestKey::insecure_fixed_signing`], and it holds
/// the decryptor and the inflator of a [`secure_calc_frame`].
fn secure_calc_conf(
	config: Arc<CalcServletConfig>,
) -> ServletConfig<TokioListener, CalcRequest, DefaultCryptoProvider, CalcServletConfig> {
	let signer = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	ServletConfig::<TokioListener, CalcRequest>::builder()
		.with_config(config)
		.with_collector_gate(SignatureGate::of(signer))
		.with_message_decryptor(shared_cipher())
		.with_message_inflator(ZstdCompression::default())
		.allow_cleartext()
		.build()
}

/// A request of `value` that is compressed, encrypted, signed by `signer`, and
/// digested over its message and its frame.
fn secure_calc_frame(value: u32, signer: Secp256k1SigningKey) -> Frame {
	let frame = compose! {
		V2: id: b"secure-calc-request-id",
			order: 1u64,
			message: CalcRequest { value },
			compactness: ZstdCompression::default(),
			confidentiality: shared_cipher(),
			nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signer),
			message_integrity<Sha3_256>: [],
			frame_integrity: type Sha3_256
	};

	frame.expect("a full-stack request composes")
}

/// A [`secure_calc_frame`] that carries the signature of another frame of the
/// signer that the collector gate admits, so its `sid` names that signer and
/// its signature fails over its own bytes.
fn frame_under_a_transplanted_signature() -> Frame {
	let donor = secure_calc_frame(7, TestKey::insecure_fixed_signing());
	let signature = donor.nonrepudiation().cloned().expect("a signed frame holds its signature");
	let mut forged = secure_calc_frame(8, TestKey::insecure_fixed_signing());
	forged.attach_signer_info(signature).expect("a V2 frame takes a signature");
	forged
}

servlet! {
	/// A typed servlet whose collector gate verifies its signed, encrypted, and
	/// compressed inbound frames. The capabilities of `with_message_decryptor`
	/// and `with_message_inflator` then decrypt and decompress them in place.
	pub SecureCalcServlet<CalcRequest, EnvConfig = CalcServletConfig>,
	protocol: TokioListener,
	handle: |request, _frame, _ctx| async move {
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
		assertions: [
			(events::HANDLER_ENTER, exactly!(1)),
			(events::CRYPTO_STEP, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_typed_servlet_full_feature_stack,
	config: ScenarioConfig::builder()
		.with_spec(SecureCalcServletSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Servlet {
		context: CalcServletConfig {
			squarer_offset: 0,
			final_multiplier: 1,
			value: 7,
		},
		start: |SetupEnv { trace, context: config }| async move {
			let trace = Arc::new(trace);
			SecureCalcServlet::start(trace, secure_calc_conf(config)).await
		},
		setup: |ClientEnv { addr, .. }| async move {
			let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |ServletEnv { mut client, context: config, .. }| async move {
			let request = secure_calc_frame(config.value, TestKey::insecure_fixed_signing());

			let response_frame = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = response_frame.decode_message()?;
			assert_eq!(response.doubled, 14, "the secure servlet doubles 7");

			Ok(())
		}
	}
}

/// What a [`SecureCalcServlet`] does with `frame`: whether the client reads
/// `PermissionDenied`, then the counts of gate refusals and of handler entries
/// on the trace of the servlet.
async fn gated_calc_outcome(frame: Frame) -> (bool, usize, usize) {
	let trace = Arc::new(TestTrace::with_detail(true));
	let config = Arc::new(CalcServletConfig { squarer_offset: 0, final_multiplier: 1, value: 7 });
	let servlet = SecureCalcServlet::start(Arc::clone(&trace), secure_calc_conf(config)).await;
	let servlet = servlet.expect("a cleartext servlet starts on a free port");
	let connector = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
	let client = connector.connect(*servlet.addr()).await;
	let mut client = client.expect("a client connects to a started servlet");

	let outcome = client.emit(frame, None).await;
	servlet.stop();

	let denied = matches!(
		outcome,
		Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))
	);
	(
		denied,
		trace.recorded(events::GATE_REJECT),
		trace.recorded(events::HANDLER_ENTER),
	)
}

// The collector gate verifies each frame while its body is ciphertext, so a
// frame whose signature fails stops ahead of the typed prologue and the
// handler.
tightbeam::tb_cases! {
	async fn a_collector_gate_refuses_a_frame(frame: Frame) {
		assert_eq!(gated_calc_outcome(frame).await, (true, 1, 0));
	}
	cases {
		/// The certificate of the signature names a key outside the gate.
		signed_under_another_key => secure_calc_frame(7, fixed_signing_key(0x02)),
		/// The signature names the signer of the gate, over another frame.
		under_the_signature_of_another_frame => frame_under_a_transplanted_signature(),
	}
}

servlet! {
	/// A servlet that echoes each frame, under a configured load gauge.
	GaugedServlet<CalcRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: raw |frame, _ctx| async move {
		Ok(Some(frame))
	}
}

/// A `servlet!` servlet reports the load of the gauge its configuration
/// installed, which the hive reads when it scales.
#[tokio::test]
async fn a_servlet_declared_with_servlet_reports_the_load_of_its_gauge() -> TestResult {
	let gauge = tracker_at(tightbeam::bps!(2500));
	let builder = ServletConfig::<TokioListener, CalcRequest>::builder().with_utilization(gauge);
	let config = builder.allow_cleartext().build();
	let servlet = GaugedServlet::start(Arc::new(TraceCollector::default()), config).await?;

	let reported = ServletBox::utilization(&servlet);
	servlet.stop();
	assert_eq!(reported, Some(tightbeam::bps!(2500)));
	Ok(())
}

/// A request whose type requires V2 or later. Its DER is the DER of
/// [`CalcRequest`].
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(min_version = "V2")]
pub struct RecentCalcRequest {
	/// The number the servlet doubles.
	pub value: u32,
}

servlet! {
	/// A typed servlet whose input requires V2 or later.
	RecentCalcServlet<RecentCalcRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |request, _frame, _ctx| async move {
		let doubled = request.value * 2;
		Ok(Some(compose! {
			V0: id: b"recent-calc-response-id",
				message: CalcResponse { doubled, squared: 0, final_result: 0 }
		}?))
	}
}

/// Sends one [`CalcRequest`] of 7 in a frame of `version` to a fresh
/// [`RecentCalcServlet`] over a cleartext client, stops the servlet, and
/// returns the outcome of the exchange.
async fn emit_to_recent_calc(version: Version) -> Result<Option<Frame>, TransportError> {
	let builder = ServletConfig::<TokioListener, RecentCalcRequest>::builder();
	let config = builder.allow_cleartext().build();
	let servlet = RecentCalcServlet::start(Arc::new(TraceCollector::default()), config).await;
	let servlet = servlet.expect("a cleartext servlet starts on a free port");
	let connector = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
	let client = connector.connect(*servlet.addr()).await;
	let mut client = client.expect("a client connects to a started servlet");

	let request = version.compose().with_id(b"recent-calc-request-id");
	let request = request.with_message(CalcRequest { value: 7 }).build();
	let request = request.expect("a request frame of any version builds");

	let outcome = client.emit(request, None).await;
	servlet.stop();
	outcome
}

/// A V0 frame is below the V2 minimum of the input type, so the typed arm of
/// `servlet!` refuses it before the handler runs. The servlet reports the
/// refusal to the client as an internal failure.
#[tokio::test]
async fn a_typed_servlet_refuses_a_frame_below_the_minimum_of_its_input() {
	let outcome = emit_to_recent_calc(Version::V0).await;
	assert!(matches!(
		outcome,
		Err(TransportError::OperationFailed(TransportFailure::Internal))
	));
}

/// A V2 frame meets the V2 minimum of the input type, so the typed arm of
/// `servlet!` decodes it and the handler answers. It runs the servlet of the
/// refusal above, so a fault of the decode or of the handler fails here.
#[tokio::test]
async fn a_typed_servlet_answers_a_frame_at_the_minimum_of_its_input() -> TestResult {
	let answered = emit_to_recent_calc(Version::V2).await?;
	let response = answered.map(|frame| frame.decode_message::<CalcResponse>()).transpose()?;
	assert_eq!(response, Some(CalcResponse { doubled: 14, squared: 0, final_result: 0 }));
	Ok(())
}
