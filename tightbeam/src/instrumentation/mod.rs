//! Instrumentation subsystem (feature = "instrument").
//!
//! Implements the normative event taxonomy and evidence artifact hashing
//! described in the README (Instrumentation Specification §9.1). This module
//! is completely independent from testing features; test layers MAY consume
//! emitted events when both `instrument` and their respective feature are
//! enabled. Production builds MAY enable `instrument` alone.
//!
//! Feature gating contract:
//! - When `instrument` is disabled all public APIs are no-ops and compile away.
//! - When enabled emission MUST be amortized O(1) and overflow MUST set a flag.
//!
//! This initial implementation provides a stable, deterministic hashing model
//! (SHA3-256) over a canonical byte representation (not yet full DER). A future
//! iteration will replace the internal encoder with a formal DER encoder.

#![allow(clippy::module_name_repetitions)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, crate::der::Enumerated)]
#[repr(u8)]
pub enum TbEventKind {
	Start = 0,
	End = 1,
	GateAccept = 2,
	GateReject = 3,
	RequestRecv = 4,
	ResponseSend = 5,
	AssertLabel = 6,
	AssertPayload = 7,
	HandlerEnter = 8,
	HandlerExit = 9,
	CryptoStep = 10,
	CompressStep = 11,
	RouteStep = 12,
	PolicyEval = 13,
	ProcessTransition = 14,
	ProcessHidden = 15,
	SeedStart = 16,
	SeedEnd = 17,
	StateExpand = 18,
	StatePrune = 19,
	DivergenceDetect = 20,
	RefusalSnapshot = 21,
	EnabledSetSample = 22,
	Warn = 23,
	Error = 24,
	// Timing events
	TimingWcet = 25,
	TimingDeadline = 26,
	TimingJitter = 27,
	TimingSlack = 28,
	// Fault events
	FaultInjected = 29,
	FaultRecovered = 30,
	FaultDetected = 31,
	// Schedulability events
	TaskRelease = 32,
	TaskComplete = 33,
	TaskMissedDeadline = 34,
	// Scheduler events
	SchedulerAllocate = 35,
	SchedulerRelease = 36,
	SchedulerBlocked = 37,
}
#[cfg(not(feature = "instrument"))]
pub mod stub {
	use super::*;

	use core::time::Duration;

	use crate::TightBeamError;

	#[derive(Clone, Debug)]
	pub struct TbEvent {
		pub seq: u32,
		pub kind: TbEventKind,
		pub label: Option<String>,
		pub payload_hash: Option<[u8; 32]>,
		pub duration_ns: Option<u64>,
		pub flags: u32,
		pub extras: Option<Vec<u8>>,
	}

	#[derive(Clone, Copy, Debug)]
	pub struct TbInstrumentationConfig {
		pub enable_payloads: bool,
		pub enable_internal_detail: bool,
		pub sample_enabled_sets: bool,
		pub sample_refusals: bool,
		pub divergence_heuristics: bool,
		pub max_events: u32,
		pub record_durations: bool,
	}

	impl Default for TbInstrumentationConfig {
		fn default() -> Self {
			Self {
				enable_payloads: false,
				enable_internal_detail: false,
				sample_enabled_sets: false,
				sample_refusals: false,
				divergence_heuristics: false,
				max_events: 1024,
				record_durations: false,
			}
		}
	}

	#[inline]
	pub fn emit_event(_event: TbEvent) -> core::result::Result<(), TightBeamError> {
		Ok(())
	}
	#[inline]
	pub fn is_active() -> bool {
		false
	}
	#[inline]
	pub fn finalize_trace() -> Option<()> {
		None
	}
}

#[cfg(feature = "instrument")]
pub mod active {
	use super::*;

	use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
	use std::sync::{Arc, Mutex, OnceLock};

	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::der::asn1::OctetString;
	use crate::TightBeamError;

	#[derive(Clone, Debug, crate::der::Sequence)]
	pub struct TbEvent {
		pub seq: u32,
		pub kind: TbEventKind,
		#[asn1(optional = "true")]
		pub label: Option<String>,
		#[asn1(optional = "true")]
		pub payload_hash: Option<[u8; 32]>,
		#[asn1(optional = "true")]
		pub duration_ns: Option<u64>,
		pub flags: u32,
		#[asn1(optional = "true")]
		pub extras: Option<Vec<u8>>,
	}

	#[derive(Clone, Copy, Debug)]
	pub struct TbInstrumentationConfig {
		pub enable_payloads: bool,
		pub enable_internal_detail: bool,
		pub sample_enabled_sets: bool,
		pub sample_refusals: bool,
		pub divergence_heuristics: bool,
		pub max_events: u32,
		pub record_durations: bool,
	}

	impl Default for TbInstrumentationConfig {
		fn default() -> Self {
			Self {
				enable_payloads: false,
				enable_internal_detail: false,
				sample_enabled_sets: false,
				sample_refusals: false,
				divergence_heuristics: false,
				max_events: 1024,
				record_durations: false,
			}
		}
	}

	static ACTIVE: AtomicBool = AtomicBool::new(false);
	static OVERFLOW: AtomicBool = AtomicBool::new(false);
	static SEQ: AtomicU32 = AtomicU32::new(0);
	static CONFIG: OnceLock<TbInstrumentationConfig> = OnceLock::new();
	static EVENTS: OnceLock<Arc<Mutex<Vec<TbEvent>>>> = OnceLock::new();

	/// Get next sequence number for event (thread-safe)
	pub fn next_seq() -> u32 {
		SEQ.fetch_add(1, Ordering::Relaxed)
	}

	pub fn init(cfg: TbInstrumentationConfig) -> Result<(), TightBeamError> {
		let _ = CONFIG.set(cfg);
		let _ = EVENTS.set(Arc::new(Mutex::new(Vec::new())));

		ACTIVE.store(true, Ordering::Relaxed);
		SEQ.store(0, Ordering::Relaxed);
		OVERFLOW.store(false, Ordering::Relaxed);

		Ok(())
	}

	#[inline]
	pub fn is_active() -> bool {
		ACTIVE.load(Ordering::Relaxed)
	}

	pub fn start_trace() {
		SEQ.store(0, Ordering::Relaxed);
		OVERFLOW.store(false, Ordering::Relaxed);
		if let Some(events) = EVENTS.get() {
			let mut events = events.lock().unwrap();
			events.clear();
		}

		let _ = emit(TbEventKind::Start, None, None, None, 0, None);
	}

	pub fn emit(
		kind: TbEventKind,
		label: Option<&str>,
		payload: Option<&[u8]>,
		duration_ns: Option<u64>,
		flags: u32,
		extras: Option<&[u8]>,
	) -> Result<(), TightBeamError> {
		if !is_active() {
			return Ok(());
		}

		let cfg = CONFIG.get().copied().unwrap_or_default();
		let seq = SEQ.fetch_add(1, Ordering::Relaxed);
		if let Some(events) = EVENTS.get() {
			let mut buf = events.lock().unwrap();
			if (buf.len() as u32) >= cfg.max_events {
				OVERFLOW.store(true, Ordering::Relaxed);
				return Ok(());
			}

			let payload_hash = if cfg.enable_payloads {
				payload.map(|p| {
					let mut hasher = Sha3_256::new();
					hasher.update(p);
					let out = hasher.finalize();
					let mut arr = [0u8; 32];
					arr.copy_from_slice(&out);
					arr
				})
			} else {
				None
			};

			buf.push(TbEvent {
				seq,
				kind,
				label: label.map(|l| l.to_string()),
				payload_hash,
				duration_ns: if cfg.record_durations {
					duration_ns
				} else {
					None
				},
				flags,
				extras: extras.map(|e| e.to_vec()),
			});
		}
		Ok(())
	}

	#[derive(Debug, Clone, crate::der::Sequence)]
	pub struct EvidenceArtifact {
		pub spec_hash: OctetString,
		pub trace_hash: OctetString,
		pub evidence_hash: OctetString,
		pub events: Vec<TbEvent>,
		pub overflow: bool,
	}

	impl EvidenceArtifact {
		pub fn finalize(spec_hash: [u8; 32]) -> Result<Self, TightBeamError> {
			let events = if let Some(events) = EVENTS.get() {
				events.lock().unwrap().clone()
			} else {
				Vec::new()
			};

			// Canonical byte representation (stable ordering) for trace hash
			let mut bytes = Vec::with_capacity(events.len() * 64);
			for ev in &events {
				bytes.extend_from_slice(&ev.seq.to_be_bytes());
				bytes.push(ev.kind as u8);
				match &ev.label {
					Some(l) => {
						let lb = l.as_bytes();
						bytes.extend_from_slice(&(lb.len() as u32).to_be_bytes());
						bytes.extend_from_slice(lb);
					}
					None => bytes.extend_from_slice(&0u32.to_be_bytes()),
				}
				match &ev.payload_hash {
					Some(ph) => bytes.extend_from_slice(ph),
					None => bytes.extend_from_slice(&[0u8; 32]),
				}
				bytes.extend_from_slice(&ev.flags.to_be_bytes());
				bytes.extend_from_slice(&ev.duration_ns.unwrap_or_default().to_be_bytes());
				match &ev.extras {
					Some(ex) => {
						bytes.extend_from_slice(&(ex.len() as u32).to_be_bytes());
						bytes.extend_from_slice(ex);
					}
					None => bytes.extend_from_slice(&0u32.to_be_bytes()),
				}
			}

			let mut h1 = Sha3_256::new();
			h1.update(&bytes);

			let trace_hash_vec = h1.finalize();
			let trace_hash = OctetString::new(trace_hash_vec.as_slice())?;

			let mut h2 = Sha3_256::new();
			h2.update(spec_hash);
			h2.update(trace_hash.as_bytes());

			let evidence_hash_vec = h2.finalize();
			let evidence_hash = OctetString::new(evidence_hash_vec.as_slice())?;
			let spec_hash_os = OctetString::new(spec_hash)?;

			Ok(Self {
				spec_hash: spec_hash_os,
				trace_hash,
				evidence_hash,
				events,
				overflow: OVERFLOW.load(Ordering::Relaxed),
			})
		}
	}

	pub fn end_trace() -> Result<EvidenceArtifact, TightBeamError> {
		let zero_spec = [0u8; 32];
		let _ = emit(TbEventKind::End, None, None, None, 0, None);
		EvidenceArtifact::finalize(zero_spec)
	}

	/// End trace using a real spec hash (preferred API once spec built).
	pub fn end_trace_with_spec(spec_hash: [u8; 32]) -> Result<EvidenceArtifact, TightBeamError> {
		let _ = emit(TbEventKind::End, None, None, None, 0, None);
		EvidenceArtifact::finalize(spec_hash)
	}

	#[macro_export]
	macro_rules! tb_instrument {
		($kind:ident $(, label = $label:expr )? $(, payload = $payload:expr )? $(, duration_ns = $dur:expr )? $(, flags = $flags:expr )? $(, extras = $extras:expr )? $(,)?) => {{
			if $crate::instrumentation::is_active() {
				let _ = $crate::instrumentation::emit(
					$crate::instrumentation::TbEventKind::$kind,
					{
						let mut __opt = None;
						$( __opt = Some($label); )?
						__opt
					},
					{
						let mut __opt = None;
						$( __opt = Some($payload); )?
						__opt
					},
					{
						let mut __opt = None;
						$( __opt = Some($dur); )?
						__opt
					},
					{
						let mut __f: u32 = 0;
						$( __f = $flags; )?
						__f
					},
					{
						let mut __opt = None;
						$( __opt = Some($extras); )?
						__opt
					},
				);
			}
		}};
	}
}

#[cfg(feature = "instrument")]
pub use active::*;
#[cfg(not(feature = "instrument"))]
pub use stub::*;
