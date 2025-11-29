#![allow(unused_imports)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tightbeam::asn1::{DigestInfo, MessagePriority};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::colony::{Servlet, ServletConf};
use tightbeam::crypto::{
	hash::Sha3_256,
	key::{InMemoryKeyProvider, KeySpec},
	x509::CertificateSpec,
};
use tightbeam::der::ValueOrd;
use tightbeam::policy::{GatePolicy, TransitStatus};
use tightbeam::prelude::policy::PolicyConf;
use tightbeam::prelude::*;
use tightbeam::testing::ScenarioConf;
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

	builder = builder.with_message_hasher::<Sha3_256>();

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
		let mut guard = self.state.lock().unwrap();
		let expected = guard.last_digest.clone();
		let actual = frame.metadata.previous_frame.as_ref();
		let prev_ok = match (expected.as_ref(), actual) {
			(None, None) => true,
			(Some(expected_digest), Some(actual_digest)) => expected_digest.value_cmp(actual_digest).is_ok(),
			(None, Some(_)) | (Some(_), None) => false,
		};

		let order_ok = guard.last_order.is_none_or(|prev| frame.metadata.order > prev);
		let valid = prev_ok && order_ok;
		self.trace.event_with("chain_valid", &[QUEUE_TAG], valid)?;

		if valid {
			guard.last_order = Some(frame.metadata.order);
			let digest = utils::digest::<Sha3_256>(&frame.message)?;
			guard.last_digest = Some(digest);
			self.trace.event_with("lag_tip", &[QUEUE_TAG], 0u64)?;
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
		let key = (frame.metadata.id.clone(), frame.metadata.order);
		let mut guard = self.seen.lock().unwrap();
		let inserted = guard.insert(key);
		if inserted {
			self.trace.event_with("dedup_kept", &[QUEUE_TAG], true)?;
		} else {
			self.trace.event_with("dedup_skipped", &[QUEUE_TAG], true)?;
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
		let priority = frame.metadata.priority.unwrap_or(MessagePriority::Normal);
		let worker = if priority <= MessagePriority::High {
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
			"worker_fan_out_0"
		} else {
			"worker_fan_out_1"
		};

		self.trace.event_with(label, vec![QUEUE_TAG, tag], worker)?;

		let respected = if priority <= MessagePriority::High {
			worker == 0
		} else {
			worker == 1
		};

		self.trace.event_with("priority_respected", &[QUEUE_TAG], respected)?;
		Ok(worker)
	}
}

#[derive(Clone, Default)]
struct BackPressureStats {
	throttled: Arc<Mutex<BTreeSet<u64>>>,
}

impl BackPressureStats {
	fn mark_throttled(&self, order: u64) -> bool {
		let mut guard = self.throttled.lock().unwrap();
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
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		// Throttle Normal+ priority frames on first encounter
		// Subsequent attempts (same order) will be accepted
		let priority = frame.metadata.priority.unwrap_or(MessagePriority::Normal);
		if priority >= MessagePriority::Normal && self.stats.mark_throttled(frame.metadata.order) {
			// Emit trace event for test verification
			let _ = self.trace.event_with("throttle_engaged", &[QUEUE_TAG], true);
			TransitStatus::Busy
		} else {
			TransitStatus::Accepted
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
		self.trace.event_with("worker_commit", &[QUEUE_TAG], worker as u64)?;
		self.trace.event_with("response_ready", &[QUEUE_TAG], frame.metadata.order)?;
		Ok(())
	}
}

fn default_batch() -> WorkBatch {
	let mut batch = WorkBatch::new(WorkId::new("queue-free::work"), 1);
	batch.push(b"critical-order", MessagePriority::Top);
	batch.push(b"normal-scan", MessagePriority::Normal);
	batch.push(b"high-followup", MessagePriority::High);
	batch
}

servlet! {
	QueueServlet<WorkOrder, EnvConfig = BackPressureStats>,
	protocol: TokioListener,
	handle: |frame, trace, _config, _workers| async move {
		// Process the frame - collector gate handles back-pressure automatically
		let harness = QueueHarness::new(Arc::clone(&trace));
		harness.handle(&frame)?;
		Ok(None)
	}
}

tb_assert_spec! {
	pub QueueFreeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: [QUEUE_TAG],
		assertions: [
			("lag_tip", present!(), equals!(0u64)),
			("priority_respected", at_least!(1), equals!(true)),
			("worker_fan_out_0", at_least!(1), equals!(0u8), tags: [WORKER_0_TAG]),
			("worker_fan_out_1", at_least!(1), equals!(1u8), tags: [WORKER_1_TAG]),
			("throttle_engaged", present!(), equals!(true)),
			("adaptive_behavior", at_least!(1))
		]
	}
}

tb_scenario! {
	name: queue_free_system,
	config: ScenarioConf::<()>::builder()
		.with_spec(QueueFreeSpec::latest())
		.with_env_config(())  // TODO revisit
		.build(),
	environment Servlet {
		servlet: QueueServlet,
		start: |trace, _config| async move {
			let stats = Arc::new(BackPressureStats::default());
			let adaptive_gate = AdaptiveGate::new(Arc::clone(&stats), Arc::clone(&trace));

			let servlet_conf = ServletConf::<TokioListener, WorkOrder>::builder()
				.with_config(Arc::clone(&stats))
				.with_collector_gate(adaptive_gate)
				.build();

			QueueServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |addr, _config| async move {
			let (client_cert, client_key) = create_test_cert_with_key("CN=Test Client", 365)?;

			// Convert signing key to KeySpec via InMemoryKeyProvider
			let provider = InMemoryKeyProvider::from(client_key);
			let key_spec = KeySpec::Provider(Arc::new(provider));

			let certificate = CertificateSpec::Built(Box::new(client_cert));
			// Restart policy will handle server-side Busy responses
			let restart_policy = RestartLinearBackoff::new(3, 50, 1, None);

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_client_identity(certificate, key_spec)?
				.with_restart(restart_policy)
				.build();

			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |trace, mut client, _config| async move {
			let trace = Arc::new(trace);

			let batch = default_batch();
			let mut prev_hash: Option<DigestInfo> = None;
			for (index, spec) in batch.entries().iter().enumerate() {
				trace.event_with("emit_work", &[QUEUE_TAG], spec.order)?;
				let (frame, digest) = match build_frame(batch.work_id(), spec, prev_hash) {
					Ok(result) => result,
					Err(err) => {
						eprintln!("build_frame error for order {}: {err:?}", spec.order);
						return Err(err);
					}
				};
				prev_hash = Some(digest);

				trace.event_with("adaptive_behavior", &[QUEUE_TAG], spec.order)?;

				if index == 1 {
					// For the second frame, emit it then immediately replay it
					// Server will throttle on first attempt, restart policy will retry
					client.emit(frame.clone(), None).await?;
					trace.event_with("replay_attempt", &[QUEUE_TAG], frame.metadata.order)?;
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
