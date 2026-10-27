use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use tightbeam::asn1::{DigestInfo, MessagePriority};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::colony::servlet::{Servlet, ServletConfig};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::instrumentation::events;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::*;
use tightbeam::testing::FaultModel;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::ClientBuilder;
use tightbeam::transport::ConnectionBuilder;
use tightbeam::urn::Urn;
use tightbeam::Beamable;
use tightbeam::{exactly, servlet, tb_assert_spec, tb_scenario};
use tightbeam::{utils, Frame, TightBeamError, Version};

use crate::common::dedup::{ChainState, DedupBook, HarnessEvents};

pub(crate) const CHAIN_BROKEN: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/chain-broken");
pub(crate) const CHAIN_VALID: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/chain-valid");
pub(crate) const DEDUP_CACHE_HIT: Urn<'static> = tightbeam::urn!("test", "event:zero-queue/dedup-cache-hit");
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

/// The events of the queue harness.
struct QueueEvents;

impl HarnessEvents for QueueEvents {
	const TAG: &'static str = QUEUE_TAG;
	const DEDUP_KEPT: Urn<'static> = DEDUP_KEPT;
	const DEDUP_SKIPPED: Urn<'static> = DEDUP_SKIPPED;
	const DEDUP_CACHE_HIT: Urn<'static> = DEDUP_CACHE_HIT;
	const CHAIN_VALID: Urn<'static> = CHAIN_VALID;
	const CHAIN_BROKEN: Urn<'static> = CHAIN_BROKEN;
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
		// An insert leaves the set whole, so a poisoned lock holds a whole set.
		let mut guard = self.throttled.lock().unwrap_or_else(PoisonError::into_inner);
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
	chain: ChainState<QueueEvents>,
	dedup: DedupBook<QueueEvents, ()>,
	priority: PriorityLedger,
}

impl QueueHarness {
	/// Serves `frame` once. The book and the chain keep it once the ledger
	/// assigns its worker.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- the frame breaks the chain, or differs from the kept frame.
	/// - [`TightBeamError`] -- a lock is poisoned, or a trace record fails.
	fn handle(&self, frame: &Frame, trace: &TraceCollector) -> Result<(), TightBeamError> {
		// The lock of the book comes before the lock of the chain.
		let serve = || self.serve(frame, trace);
		self.dedup.answer(frame, trace, || self.chain.record(frame, trace, serve))
	}

	/// Assigns `frame` its worker, and records that its response is ready.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a trace record fails.
	fn serve(&self, frame: &Frame, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let worker = self.priority.assign(frame, trace)?;

		trace.event_with(WORKER_COMMIT, &[QUEUE_TAG], worker as u64)?;
		trace.event_with(RESPONSE_READY, &[QUEUE_TAG], frame.metadata().order())?;
		trace.event_with(LAG_TIP, &[QUEUE_TAG], ())?;
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
			(CHAIN_VALID, exactly!(3)),
			(CHAIN_BROKEN, exactly!(0)),
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

/// The first frame of one chain, and the second frame of another chain, which
/// follows the first in order and links to a parent other than it.
fn first_and_linked_to_theirs() -> (Frame, Frame) {
	let mut ours = WorkChain::new(WorkId::new("queue-free::ours"));
	let mut theirs = WorkChain::new(WorkId::new("queue-free::theirs"));
	let first = ours.next(b"first", MessagePriority::Standard);

	theirs.next(b"their-first", MessagePriority::Standard);

	let linked_to_theirs = theirs.next(b"second", MessagePriority::Standard);

	(first, linked_to_theirs)
}

/// The first two frames of one chain.
fn two_links() -> (Frame, Frame) {
	let mut chain = WorkChain::new(WorkId::new("queue-free::links"));

	let first = chain.next(b"first", MessagePriority::Standard);
	let second = chain.next(b"second", MessagePriority::Standard);
	(first, second)
}

/// A resend of a frame that breaks the chain meets the chain again.
#[test]
fn a_resent_frame_that_breaks_the_chain_meets_the_chain_again() -> Result<(), TightBeamError> {
	let trace = TraceCollector::default();
	let harness = QueueHarness::default();
	let (first, linked_to_theirs) = first_and_linked_to_theirs();

	harness.handle(&first, &trace)?;

	let refusal = harness.handle(&linked_to_theirs, &trace);
	let resend = harness.handle(&linked_to_theirs, &trace);
	assert!(refusal.is_err());
	assert!(matches!(resend, Err(TightBeamError::InvalidMetadata)));
	assert_eq!(trace.recorded(CHAIN_BROKEN), 2);
	Ok(())
}

/// A frame that breaks the chain is refused, and gets no worker.
#[test]
fn a_frame_that_breaks_the_chain_gets_no_worker() -> Result<(), TightBeamError> {
	let trace = TraceCollector::default();
	let harness = QueueHarness::default();
	let (first, linked_to_theirs) = first_and_linked_to_theirs();

	harness.handle(&first, &trace)?;

	let refusal = harness.handle(&linked_to_theirs, &trace);
	assert!(matches!(refusal, Err(TightBeamError::InvalidMetadata)));
	assert_eq!(trace.recorded(RESPONSE_READY), 1);
	Ok(())
}

/// A frame whose worker assignment fails is served on its resend.
#[test]
fn a_frame_whose_worker_assignment_fails_is_served_on_its_resend() -> Result<(), TightBeamError> {
	let fault = || TightBeamError::ChannelClosed;
	let model = FaultModel::default().with_event_fault(PRIORITY_RESPECTED, fault, tightbeam::bps!(5000));
	let trace = TraceCollector::new().with_fault_model(model);
	let harness = QueueHarness::default();
	let (first, second) = two_links();

	harness.handle(&first, &trace)?;

	let failed = harness.handle(&second, &trace);
	harness.handle(&second, &trace)?;
	assert!(matches!(failed, Err(TightBeamError::ChannelClosed)));
	assert_eq!(trace.recorded(RESPONSE_READY), 2);
	Ok(())
}
