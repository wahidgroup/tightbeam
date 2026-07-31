#![allow(unused_imports)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tightbeam::asn1::{DigestInfo, MessagePriority};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::colony::servlet::{Servlet, ServletConfig};
use tightbeam::crypto::{
	hash::Sha3_256,
	key::{Secp256k1KeyProvider, SigningKeyProvider, SigningKeySpec},
	x509::CertificateSpec,
};
use tightbeam::der::ValueOrd;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::policy::PolicyConfig;
use tightbeam::prelude::*;
use tightbeam::testing::ScenarioConfig;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::{RestartLinearBackoff, RestartPolicy, RetryAction};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::ClientBuilder;
use tightbeam::transport::ConnectionBuilder;
use tightbeam::transport::{MessageEmitter, Protocol, TransportResult};
use tightbeam::Beamable;
use tightbeam::{at_least, between, exactly, present, server, servlet, tb_assert_spec, tb_scenario};
use tightbeam::{utils, Frame, TightBeamError, Version};

use crate::common::x509::create_test_cert_with_key;

use tightbeam::utils::urn::Urn;

pub(crate) const ADAPTIVE_BEHAVIOR: Urn<'static> = Urn::new("test", "event:zero-queue/adaptive-behavior");
pub(crate) const CHAIN_VALID: Urn<'static> = Urn::new("test", "event:zero-queue/chain-valid");
pub(crate) const DEDUP_KEPT: Urn<'static> = Urn::new("test", "event:zero-queue/dedup-kept");
pub(crate) const DEDUP_SKIPPED: Urn<'static> = Urn::new("test", "event:zero-queue/dedup-skipped");
pub(crate) const EMIT_WORK: Urn<'static> = Urn::new("test", "event:zero-queue/emit-work");
pub(crate) const LAG_TIP: Urn<'static> = Urn::new("test", "event:zero-queue/lag-tip");
pub(crate) const THROTTLE_ENGAGED: Urn<'static> = Urn::new("test", "event:zero-queue/throttle-engaged");
pub(crate) const PRIORITY_RESPECTED: Urn<'static> = Urn::new("test", "event:zero-queue/priority-respected");
pub(crate) const REPLAY_ATTEMPT: Urn<'static> = Urn::new("test", "event:zero-queue/replay-attempt");
pub(crate) const RESPONSE_READY: Urn<'static> = Urn::new("test", "event:zero-queue/response-ready");
pub(crate) const WORKER_COMMIT: Urn<'static> = Urn::new("test", "event:zero-queue/worker-commit");
pub(crate) const WORKER_FAN_OUT_0: Urn<'static> = Urn::new("test", "event:zero-queue/worker-fan-out-0");
pub(crate) const WORKER_FAN_OUT_1: Urn<'static> = Urn::new("test", "event:zero-queue/worker-fan-out-1");

const QUEUE_TAG: &str = "queue-free";
const WORKER_0_TAG: &str = "worker:0";
const WORKER_1_TAG: &str = "worker:1";

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct WorkOrder {
	#[cfg_attr(feature = "derive", beam(bytes))]
	payload: Vec<u8>,
}

impl WorkOrder {
	fn new(payload: impl AsRef<[u8]>) -> Self {
		Self { payload: payload.as_ref().to_vec() }
	}
}

impl AsRef<[u8]> for WorkOrder {
	fn as_ref(&self) -> &[u8] {
		self.payload.as_slice()
	}
}

#[derive(Clone)]
struct WorkId(Arc<[u8]>);

impl WorkId {
	fn new(value: &str) -> Self {
		Self(Arc::from(value.as_bytes()))
	}

	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

#[derive(Clone)]
struct WorkFrameSpec {
	order: u64,
	payload: Vec<u8>,
	priority: MessagePriority,
}

impl WorkFrameSpec {
	fn to_message(&self) -> WorkOrder {
		WorkOrder::new(&self.payload)
	}
}

struct WorkBatch {
	work_id: WorkId,
	next_order: u64,
	entries: Vec<WorkFrameSpec>,
}

impl WorkBatch {
	fn new(work_id: WorkId, start_order: u64) -> Self {
		Self { work_id, next_order: start_order, entries: Vec::new() }
	}

	fn push(&mut self, payload: &[u8], priority: MessagePriority) {
		let entry = WorkFrameSpec { order: self.next_order, payload: payload.to_vec(), priority };
		self.next_order += 1;
		self.entries.push(entry);
	}

	fn entries(&self) -> &[WorkFrameSpec] {
		&self.entries
	}

	fn work_id(&self) -> &WorkId {
		&self.work_id
	}
}

fn build_frame(
	work_id: &WorkId,
	spec: &WorkFrameSpec,
	previous_hash: Option<DigestInfo>,
) -> Result<(Frame, DigestInfo), TightBeamError> {
	let mut builder = FrameBuilder::<WorkOrder>::from(Version::V2)
		.with_id(work_id.as_bytes())
		.with_order(spec.order)
		.with_message(spec.to_message())
		.with_priority(spec.priority);

	if let Some(parent) = previous_hash {
		builder = builder.with_previous_hash(parent);
	}

	builder = builder.with_message_hasher::<Sha3_256>([]);

	let frame = builder.build()?;
	let digest = utils::digest::<Sha3_256>(&frame.message)?;
	Ok((frame, digest))
}

#[derive(Clone)]
struct ChainState {
	trace: Arc<TraceCollector>,
	state: Arc<Mutex<ChainInner>>,
}

struct ChainInner {
	last_order: Option<u64>,
	last_digest: Option<DigestInfo>,
}

impl ChainState {
	fn new(trace: Arc<TraceCollector>) -> Self {
		Self {
			trace,
			state: Arc::new(Mutex::new(ChainInner { last_order: None, last_digest: None })),
		}
	}

	fn record(&self, frame: &Frame) -> Result<(), TightBeamError> {
		let mut guard = self.state.lock().expect("chain state mutex not poisoned");
		let expected = guard.last_digest.to_owned();
		let actual = frame.metadata.previous_frame.as_ref();
		let prev_ok = match (expected.as_ref(), actual) {
			(None, None) => true,
			(Some(expected_digest), Some(actual_digest)) => expected_digest.value_cmp(actual_digest).is_ok(),
			(None, Some(_)) | (Some(_), None) => false,
		};

		let order_ok = guard.last_order.is_none_or(|prev| frame.metadata.order > prev);
		let valid = prev_ok && order_ok;

		self.trace.event_with(CHAIN_VALID, &[QUEUE_TAG], valid)?;

		if valid {
			guard.last_order = Some(frame.metadata.order);
			let digest = utils::digest::<Sha3_256>(&frame.message)?;
			guard.last_digest = Some(digest);

			self.trace.event_with(LAG_TIP, &[QUEUE_TAG], 0u64)?;
		}

		Ok(())
	}
}

type SeenSet = Arc<Mutex<BTreeSet<(Vec<u8>, u64)>>>;

#[derive(Clone)]
struct DedupBook {
	trace: Arc<TraceCollector>,
	seen: SeenSet,
}

impl DedupBook {
	fn new(trace: Arc<TraceCollector>) -> Self {
		Self { trace, seen: Arc::new(Mutex::new(BTreeSet::new())) }
	}

	fn record(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		let key = (frame.metadata.id.to_owned(), frame.metadata.order);
		let mut guard = self.seen.lock().expect("seen-set mutex not poisoned");

		let inserted = guard.insert(key);
		if inserted {
			self.trace.event_with(DEDUP_KEPT, &[QUEUE_TAG], true)?;
		} else {
			self.trace.event_with(DEDUP_SKIPPED, &[QUEUE_TAG], true)?;
		}

		Ok(inserted)
	}
}

#[derive(Clone)]
struct PriorityLedger {
	trace: Arc<TraceCollector>,
}

impl PriorityLedger {
	fn new(trace: Arc<TraceCollector>) -> Self {
		Self { trace }
	}

	fn assign(&self, frame: &Frame) -> Result<u8, TightBeamError> {
		let priority = frame.metadata.priority.unwrap_or(MessagePriority::Standard);
		let worker = if priority >= MessagePriority::LowLatency {
			0
		} else {
			1
		};
		let tag = if worker == 0 {
			WORKER_0_TAG
		} else {
			WORKER_1_TAG
		};
		let label = if worker == 0 {
			WORKER_FAN_OUT_0
		} else {
			WORKER_FAN_OUT_1
		};

		self.trace.event_with(label, vec![QUEUE_TAG, tag], worker)?;

		let respected = if priority >= MessagePriority::LowLatency {
			worker == 0
		} else {
			worker == 1
		};

		self.trace.event_with(PRIORITY_RESPECTED, &[QUEUE_TAG], respected)?;
		Ok(worker)
	}
}

#[derive(Clone, Default)]
struct BackPressureStats {
	throttled: Arc<Mutex<BTreeSet<u64>>>,
}

impl BackPressureStats {
	fn mark_throttled(&self, order: u64) -> bool {
		let mut guard = self.throttled.lock().expect("throttle mutex not poisoned");
		if guard.contains(&order) {
			false
		} else {
			guard.insert(order);
			true
		}
	}
}

#[derive(Clone)]
struct AdaptiveGate {
	stats: Arc<BackPressureStats>,
	trace: Arc<TraceCollector>,
}

impl AdaptiveGate {
	fn new(stats: Arc<BackPressureStats>, trace: Arc<TraceCollector>) -> Self {
		Self { stats, trace }
	}
}

impl GatePolicy for AdaptiveGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::Ok;
		};

		// Throttle Standard-or-lower priority frames on first encounter
		// Subsequent attempts (same order) will be accepted
		let priority = frame.metadata.priority.unwrap_or(MessagePriority::Standard);
		if priority <= MessagePriority::HighThroughput && self.stats.mark_throttled(frame.metadata.order) {
			// Emit trace event for test verification
			let _ = self.trace.event_with(THROTTLE_ENGAGED, &[QUEUE_TAG], true);
			TransitStatus::ResourceExhausted
		} else {
			TransitStatus::Ok
		}
	}
}

#[derive(Clone)]
struct QueueHarness {
	trace: Arc<TraceCollector>,
	chain: ChainState,
	dedup: DedupBook,
	priority: PriorityLedger,
}

impl QueueHarness {
	fn new(trace: Arc<TraceCollector>) -> Self {
		Self {
			chain: ChainState::new(Arc::clone(&trace)),
			dedup: DedupBook::new(Arc::clone(&trace)),
			priority: PriorityLedger::new(Arc::clone(&trace)),
			trace,
		}
	}

	fn handle(&self, frame: &Frame) -> Result<(), TightBeamError> {
		if !self.dedup.record(frame)? {
			return Ok(());
		}

		self.chain.record(frame)?;

		let worker = self.priority.assign(frame)?;

		self.trace.event_with(WORKER_COMMIT, &[QUEUE_TAG], worker as u64)?;
		self.trace.event_with(RESPONSE_READY, &[QUEUE_TAG], frame.metadata.order)?;
		Ok(())
	}
}

fn default_batch() -> WorkBatch {
	let mut batch = WorkBatch::new(WorkId::new("queue-free::work"), 1);
	batch.push(b"critical-order", MessagePriority::Expedited);
	batch.push(b"normal-scan", MessagePriority::Standard);
	batch.push(b"high-followup", MessagePriority::LowLatency);

	batch
}

servlet! {
	QueueServlet<WorkOrder, EnvConfig = BackPressureStats>,
	protocol: TokioListener,
	handle: |_msg, frame, ctx| async move {
		let trace = ctx.trace();

		// Process the frame - collector gate handles back-pressure automatically
		let harness = QueueHarness::new(Arc::clone(trace));
		harness.handle(&frame)?;

		Ok(None)
	}
}

tb_assert_spec! {
	pub QueueFreeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: [QUEUE_TAG],
		assertions: [
			(LAG_TIP, present!(), equals!(0u64)),
			(PRIORITY_RESPECTED, at_least!(1), equals!(true)),
			(WORKER_FAN_OUT_0, at_least!(1), equals!(0u8), tags: [WORKER_0_TAG]),
			(WORKER_FAN_OUT_1, at_least!(1), equals!(1u8), tags: [WORKER_1_TAG]),
			(THROTTLE_ENGAGED, present!(), equals!(true)),
			(ADAPTIVE_BEHAVIOR, at_least!(1))
		]
	}
}

tb_scenario! {
	name: queue_free_system,
	spec: QueueFreeSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			let stats = Arc::new(BackPressureStats::default());
			let adaptive_gate = AdaptiveGate::new(Arc::clone(&stats), Arc::clone(&trace));

			let servlet_conf = ServletConfig::<TokioListener, WorkOrder>::builder()
				.with_config(Arc::clone(&stats))
				.with_collector_gate(adaptive_gate)
				.build();

			QueueServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			let (client_cert, client_key) = create_test_cert_with_key("CN=Test Client", 365)?;

			let key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(client_key));
			let certificate = CertificateSpec::Built(Box::new(client_cert));
			let restart_policy = RestartLinearBackoff::new(3, 50, 1, None);

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_client_identity(certificate, key_provider)?
				.with_restart(restart_policy)
				.build();

			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let trace = Arc::new(env.trace);
			let mut client = env.client;

			let batch = default_batch();
			let mut prev_hash: Option<DigestInfo> = None;
			for (index, spec) in batch.entries().iter().enumerate() {
				trace.event_with(EMIT_WORK, &[QUEUE_TAG], spec.order)?;
				let (frame, digest) = match build_frame(batch.work_id(), spec, prev_hash) {
					Ok(result) => result,
					Err(err) => {
						eprintln!("build_frame error for order {}: {err:?}", spec.order);
						return Err(err);
					}
				};

				prev_hash = Some(digest);

				trace.event_with(ADAPTIVE_BEHAVIOR, &[QUEUE_TAG], spec.order)?;

				if index == 1 {
					// For the second frame, emit it then immediately replay it
					// Server will throttle on first attempt, restart policy will retry
					client.emit(frame.to_owned(), None).await?;
					trace.event_with(REPLAY_ATTEMPT, &[QUEUE_TAG], frame.metadata.order)?;
					client.emit(frame, None).await?;
				} else {
					// Server-side adaptive gate will throttle Normal+ priority frames
					// Restart policy will automatically retry throttled frames
					client.emit(frame, None).await?;
				}
			}

			Ok(())
		}
	}
}
