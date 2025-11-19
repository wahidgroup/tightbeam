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

use crate::utils::urn::Urn;

/// Event kind URN constants for tightbeam instrumentation events
///
/// These constants provide convenient access to URNs for all event types.
/// Format: `urn:tightbeam:instrumentation:event/<event-name>`
pub mod events {
	use super::*;

	// Core lifecycle events
	pub const START: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/start");
	pub const END: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/end");

	// Gate events
	pub const GATE_ACCEPT: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/gate-accept");
	pub const GATE_REJECT: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/gate-reject");

	// Transport events
	pub const REQUEST_RECV: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/request-recv");
	pub const RESPONSE_SEND: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/response-send");

	// Assertion events
	pub const ASSERT_LABEL: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/assert-label");
	pub const ASSERT_PAYLOAD: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/assert-payload");

	// Handler events
	pub const HANDLER_ENTER: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/handler-enter");
	pub const HANDLER_EXIT: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/handler-exit");

	// Processing events
	pub const CRYPTO_STEP: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/crypto-step");
	pub const COMPRESS_STEP: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/compress-step");
	pub const ROUTE_STEP: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/route-step");
	pub const POLICY_EVAL: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/policy-eval");

	// Process events
	pub const PROCESS_TRANSITION: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/process-transition");
	pub const PROCESS_HIDDEN: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/process-hidden");

	// FDR/exploration events
	pub const SEED_START: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/seed-start");
	pub const SEED_END: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/seed-end");
	pub const STATE_EXPAND: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/state-expand");
	pub const STATE_PRUNE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/state-prune");
	pub const DIVERGENCE_DETECT: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/divergence-detect");
	pub const REFUSAL_SNAPSHOT: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/refusal-snapshot");
	pub const ENABLED_SET_SAMPLE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/enabled-set-sample");

	// Error events
	pub const WARN: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/warn");
	pub const ERROR: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/error");

	// Timing events
	pub const TIMING_WCET: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/timing-wcet");
	pub const TIMING_DEADLINE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/timing-deadline");
	pub const TIMING_JITTER: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/timing-jitter");
	pub const TIMING_SLACK: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/timing-slack");

	// Fault events
	pub const FAULT_INJECTED: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/fault-injected");
	pub const FAULT_RECOVERED: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/fault-recovered");
	pub const FAULT_DETECTED: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/fault-detected");

	// Schedulability events
	pub const TASK_RELEASE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/task-release");
	pub const TASK_COMPLETE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/task-complete");
	pub const TASK_MISSED_DEADLINE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/task-missed-deadline");

	// Scheduler events
	pub const SCHEDULER_ALLOCATE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/scheduler-allocate");
	pub const SCHEDULER_RELEASE: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/scheduler-release");
	pub const SCHEDULER_BLOCKED: Urn<'static> = Urn::new("tightbeam", "instrumentation:event/scheduler-blocked");
}

#[cfg(not(feature = "instrument"))]
pub mod stub {
	use super::*;

	use core::time::Duration;

	use crate::TightBeamError;

	#[derive(Clone, Debug)]
	pub struct TbEvent {
		pub seq: u32,
		pub urn: Urn<'static>,
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
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::der::asn1::OctetString;
	use crate::der::{Decode, Encode, FixedTag, Sequence, Tag};
	use crate::utils::urn::Urn;
	use crate::Beamable;
	use crate::TightBeamError;

	#[derive(Clone, Debug, PartialEq)]
	pub struct TbEvent {
		pub seq: u32,
		pub urn: Urn<'static>,
		pub label: Option<String>,
		pub payload_hash: Option<[u8; 32]>,
		pub duration_ns: Option<u64>,
		pub flags: u32,
		pub extras: Option<Vec<u8>>,
	}

	// Manual DER implementation: Sequence derive can't handle Urn<'static>
	// lifetime
	impl FixedTag for TbEvent {
		const TAG: Tag = Tag::Sequence;
	}

	impl crate::der::EncodeValue for TbEvent {
		fn value_len(&self) -> crate::der::Result<crate::der::Length> {
			let mut len = match self.seq.encoded_len() {
				Ok(l) => l,
				Err(e) => return Err(e),
			};

			// Encode Urn directly (it implements EncodeValue)
			len = match self.urn.encoded_len() {
				Ok(l) => (len + l)?,
				Err(e) => return Err(e),
			};

			if let Some(ref label) = self.label {
				len = match label.encoded_len() {
					Ok(l) => (len + l)?,
					Err(e) => return Err(e),
				};
			}
			if let Some(ref payload_hash) = self.payload_hash {
				let os = match OctetString::new(payload_hash.as_slice()) {
					Ok(o) => o,
					Err(e) => return Err(e),
				};
				len = match os.encoded_len() {
					Ok(l) => (len + l)?,
					Err(e) => return Err(e),
				};
			}
			if let Some(duration_ns) = self.duration_ns {
				len = match duration_ns.encoded_len() {
					Ok(l) => (len + l)?,
					Err(e) => return Err(e),
				};
			}

			len = match self.flags.encoded_len() {
				Ok(l) => (len + l)?,
				Err(e) => return Err(e),
			};

			if let Some(ref extras) = self.extras {
				let os = match OctetString::new(extras.as_slice()) {
					Ok(o) => o,
					Err(e) => return Err(e),
				};
				len = match os.encoded_len() {
					Ok(l) => (len + l)?,
					Err(e) => return Err(e),
				};
			}

			Ok(len)
		}

		fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
			self.seq.encode(encoder)?;

			// Encode Urn directly (it implements Encode)
			self.urn.encode(encoder)?;

			if let Some(ref label) = self.label {
				label.encode(encoder)?;
			}
			if let Some(ref payload_hash) = self.payload_hash {
				let os = OctetString::new(payload_hash.as_slice())?;
				os.encode(encoder)?;
			}
			if let Some(duration_ns) = self.duration_ns {
				duration_ns.encode(encoder)?;
			}

			self.flags.encode(encoder)?;

			if let Some(ref extras) = self.extras {
				let os = OctetString::new(extras.as_slice())?;
				os.encode(encoder)?;
			}

			Ok(())
		}
	}

	impl<'a> crate::der::DecodeValue<'a> for TbEvent {
		fn decode_value<R: crate::der::Reader<'a>>(
			reader: &mut R,
			_header: crate::der::Header,
		) -> crate::der::Result<Self> {
			reader.sequence(|seq: &mut crate::der::NestedReader<'_, R>| {
				let seq_val = u32::decode(seq)?;
				let urn_decoded = Urn::decode(seq)?;
				let urn: Urn<'static> = urn_decoded.into_owned();
				let label = Option::<String>::decode(seq)?;
				let payload_hash: Option<[u8; 32]> = Option::<OctetString>::decode(seq)?.and_then(|os| {
					let bytes = os.as_bytes();
					if bytes.len() == 32 {
						let mut hash = [0u8; 32];
						hash.copy_from_slice(bytes);
						Some(hash)
					} else {
						None
					}
				});

				let duration_ns = Option::<u64>::decode(seq)?;
				let flags = u32::decode(seq)?;
				let extras = Option::<OctetString>::decode(seq)?.map(|os| os.as_bytes().to_vec());
				Ok(TbEvent { seq: seq_val, urn, label, payload_hash, duration_ns, flags, extras })
			})
		}
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

	// Global state removed - all instrumentation now handled by TraceCollector

	#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
	pub struct EvidenceArtifact {
		pub spec_hash: OctetString,
		pub trace_hash: OctetString,
		pub evidence_hash: OctetString,
		pub events: Vec<TbEvent>,
		pub overflow: bool,
	}

	impl EvidenceArtifact {
		/// Finalize evidence artifact from events
		///
		/// Takes events as parameter instead of reading from global state.
		pub fn finalize(spec_hash: [u8; 32], events: Vec<TbEvent>) -> Result<Self, TightBeamError> {
			// Canonical byte representation (stable ordering) for trace hash
			let mut bytes = Vec::with_capacity(events.len() * 64);
			for ev in &events {
				bytes.extend_from_slice(&ev.seq.to_be_bytes());
				// URN serialized as string representation
				let urn_str = ev.urn.to_string();
				let urn_bytes = urn_str.as_bytes();
				bytes.extend_from_slice(&(urn_bytes.len() as u32).to_be_bytes());
				bytes.extend_from_slice(urn_bytes);
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
				overflow: false, // Overflow tracking moved to TraceCollector
			})
		}
	}
}

#[cfg(feature = "instrument")]
pub use active::*;
#[cfg(not(feature = "instrument"))]
pub use stub::*;
