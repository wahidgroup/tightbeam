use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tightbeam::asn1::{DigestInfo, MessagePriority};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::colony::servlet::{Servlet, ServletConfig};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::instrumentation::events;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::*;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::ClientBuilder;
use tightbeam::transport::ConnectionBuilder;
use tightbeam::Beamable;
use tightbeam::{exactly, servlet, tb_assert_spec, tb_scenario};
use tightbeam::{utils, Frame, TightBeamError, Version};

use tightbeam::urn::Urn;

pub(crate) const CHAIN_VALID: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/chain-valid");
pub(crate) const DEDUP_KEPT: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/dedup-kept");
pub(crate) const DEDUP_SKIPPED: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/dedup-skipped");
pub(crate) const LAG_TIP: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/lag-tip");
pub(crate) const PRIORITY_RESPECTED: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/priority-respected");
pub(crate) const RESPONSE_READY: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/response-ready");
pub(crate) const WORKER_COMMIT: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/worker-commit");
pub(crate) const WORKER_FAN_OUT_0: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/worker-fan-out-0");
pub(crate) const WORKER_FAN_OUT_1: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/worker-fan-out-1");

const QUEUE_TAG: &str = "queue-free";
const WORKER_0_TAG: &str = "worker:0";
const WORKER_1_TAG: &str = "worker:1";

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct WorkOrder {
	#[beam(bytes)]
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
	fn new(value: impl AsRef<str>) -> Self {
		let value = value.as_ref();
		Self(Arc::from(value.as_bytes()))
	}

	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// The client side of one chain of work frames.
///
/// Each frame takes the next order and links to the digest of the body of the
/// frame before it.
struct WorkChain {
	work_id: WorkId,
	next_order: u64,
	tip: Option<DigestInfo>,
}

impl WorkChain {
	fn new(work_id: WorkId) -> Self {
		Self { work_id, next_order: 1, tip: None }
	}

	/// The next frame of the chain, which carries `payload` at `priority`.
	fn next(&mut self, payload: impl AsRef<[u8]>, priority: MessagePriority) -> Frame {
		let mut builder = FrameBuilder::<WorkOrder>::from(Version::V2)
			.with_id(self.work_id.as_bytes())
			.with_order(self.next_order)
			.with_message(WorkOrder::new(payload))
			.with_priority(priority);

		if let Some(parent) = self.tip.take() {
			builder = builder.with_previous_hash(parent);
		}

		builder = builder.with_message_hasher::<Sha3_256>([]);

		let frame = builder.build().expect("a work frame builds");
		let digest = utils::digest::<Sha3_256>(frame.message()).expect("SHA3-256 digests a work body");

		self.next_order += 1;
		self.tip = Some(digest);

		frame
	}
}

#[derive(Default)]
struct ChainState {
	state: Mutex<ChainInner>,
}

#[derive(Default)]
struct ChainInner {
	last_order: Option<u64>,
	last_digest: Option<DigestInfo>,
}

impl ChainState {
	/// Records `frame` as the next link of the chain, and returns whether it
	/// links to the tip.
	fn record(&self, frame: &Frame, trace: &TraceCollector) -> Result<bool, TightBeamError> {
		let mut guard = self.state.lock().expect("chain state mutex not poisoned");
		let parent = frame.metadata().previous_frame();
		let prev_ok = guard.last_digest.as_ref() == parent;

		let order_ok = guard.last_order.is_none_or(|prev| frame.metadata().order() > prev);
		let valid = prev_ok && order_ok;

		trace.event_with(CHAIN_VALID, &[QUEUE_TAG], valid)?;

		if valid {
			guard.last_order = Some(frame.metadata().order());
			let digest = utils::digest::<Sha3_256>(frame.message())?;
			guard.last_digest = Some(digest);

			trace.event_with(LAG_TIP, &[QUEUE_TAG], ())?;
		}

		Ok(valid)
	}
}

#[derive(Default)]
struct DedupBook {
	seen: Mutex<BTreeSet<(Vec<u8>, u64)>>,
}

impl DedupBook {
	fn record(&self, frame: &Frame, trace: &TraceCollector) -> Result<bool, TightBeamError> {
		let key = (frame.metadata().id().to_owned(), frame.metadata().order());
		let mut guard = self.seen.lock().expect("seen-set mutex not poisoned");

		let inserted = guard.insert(key);
		if inserted {
			trace.event_with(DEDUP_KEPT, &[QUEUE_TAG], ())?;
		} else {
			trace.event_with(DEDUP_SKIPPED, &[QUEUE_TAG], ())?;
		}

		Ok(inserted)
	}
}

#[derive(Default)]
struct PriorityLedger;

impl PriorityLedger {
	fn assign(&self, frame: &Frame, trace: &TraceCollector) -> Result<u8, TightBeamError> {
		let priority = frame.metadata().priority().unwrap_or(MessagePriority::Standard);
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

		trace.event_with(label, vec![QUEUE_TAG, tag], worker)?;

		let respected = if priority >= MessagePriority::LowLatency {
			worker == 0
		} else {
			worker == 1
		};

		trace.event_with(PRIORITY_RESPECTED, &[QUEUE_TAG], respected)?;
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
}

impl AdaptiveGate {
	fn new(stats: Arc<BackPressureStats>) -> Self {
		Self { stats }
	}
}

impl GatePolicy for AdaptiveGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::Ok;
		};

		// The gate throttles a frame of `HighThroughput` or lower priority at
		// its first attempt and admits each later attempt of the same order.
		let priority = frame.metadata().priority().unwrap_or(MessagePriority::Standard);
		if priority <= MessagePriority::HighThroughput && self.stats.mark_throttled(frame.metadata().order()) {
			TransitStatus::ResourceExhausted
		} else {
			TransitStatus::Ok
		}
	}
}

/// The state of the queue-free application, which every call of the servlet
/// shares.
#[derive(Default)]
struct QueueHarness {
	chain: ChainState,
	dedup: DedupBook,
	priority: PriorityLedger,
}

impl QueueHarness {
	fn handle(&self, frame: &Frame, trace: &TraceCollector) -> Result<(), TightBeamError> {
		if !self.dedup.record(frame, trace)? {
			return Ok(());
		}

		self.chain.record(frame, trace)?;

		let worker = self.priority.assign(frame, trace)?;

		trace.event_with(WORKER_COMMIT, &[QUEUE_TAG], worker as u64)?;
		trace.event_with(RESPONSE_READY, &[QUEUE_TAG], frame.metadata().order())?;
		Ok(())
	}
}

servlet! {
	QueueServlet<WorkOrder, EnvConfig = QueueHarness>,
	protocol: TokioListener,
	handle: |_msg, frame, ctx| async move {
		let trace = &ctx.trace();

		// The collector gate applies back pressure ahead of the handler, so the
		// handler records the frame alone.
		let harness: &QueueHarness = ctx.env_config();
		harness.handle(&frame, trace)?;

		Ok(None)
	}
}

tb_assert_spec! {
	pub QueueFreeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::GATE_ACCEPT, exactly!(4), equals!(TransitStatus::Ok)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(DEDUP_KEPT, exactly!(3)),
			(DEDUP_SKIPPED, exactly!(1)),
			(CHAIN_VALID, exactly!(3), equals!(true)),
			(LAG_TIP, exactly!(3)),
			(PRIORITY_RESPECTED, exactly!(3), equals!(true)),
			(WORKER_FAN_OUT_0, exactly!(2), equals!(0u8), tags: [WORKER_0_TAG]),
			(WORKER_FAN_OUT_1, exactly!(1), equals!(1u8), tags: [WORKER_1_TAG]),
			(WORKER_COMMIT, exactly!(3)),
			(RESPONSE_READY, exactly!(3))
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
			let adaptive_gate = AdaptiveGate::new(stats);

			let servlet_conf = ServletConfig::<TokioListener, WorkOrder>::builder()
				.with_config(Arc::new(QueueHarness::default()))
				.with_collector_gate(adaptive_gate)
				.allow_cleartext()
				.build();

			QueueServlet::start(Arc::clone(&trace), servlet_conf).await
		},
		setup: |env| async move {
			// The servlet under test allows cleartext, so this link is
			// cleartext, and the scenario exercises back pressure over it.
			let restart_policy = RestartLinearBackoff::new(3, Duration::from_millis(50), 1, None);
			let builder = ClientBuilder::<TokioListener>::builder()
				.allow_cleartext()
				.with_restart(restart_policy)
				.build();

			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let mut client = env.client;
			let mut chain = WorkChain::new(WorkId::new("queue-free::work"));
			let critical = chain.next(b"critical-order", MessagePriority::Expedited);
			let scan = chain.next(b"normal-scan", MessagePriority::Standard);
			let followup = chain.next(b"high-followup", MessagePriority::LowLatency);

			client.emit(critical, None).await?;

			// The adaptive gate throttles the scan's first attempt, and the
			// restart policy retries it. The client replays the scan at once,
			// and the dedup book of the servlet skips the replay.
			client.emit(scan.to_owned(), None).await?;
			client.emit(scan, None).await?;

			client.emit(followup, None).await?;

			Ok(())
		}
	}
}

/// A chain refuses a frame that links to a parent other than its tip, though
/// the order of the frame follows the tip.
#[test]
fn a_frame_linked_to_another_parent_breaks_the_chain() -> Result<(), TightBeamError> {
	let trace = TraceCollector::default();
	let chain = ChainState::default();
	let mut ours = WorkChain::new(WorkId::new("queue-free::ours"));
	let mut theirs = WorkChain::new(WorkId::new("queue-free::theirs"));
	let first = ours.next(b"first", MessagePriority::Standard);
	theirs.next(b"their-first", MessagePriority::Standard);
	let linked_to_theirs = theirs.next(b"second", MessagePriority::Standard);
	chain.record(&first, &trace)?;

	let valid = chain.record(&linked_to_theirs, &trace)?;

	assert!(!valid, "the chain admitted a frame that links to another parent");
	Ok(())
}
