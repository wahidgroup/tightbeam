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

	pub const TIGHTBEAM_NID: &str = "tightbeam";
	pub const TIGHTBEAM_INSTRUMENTATION_NSS: &str = "instrumentation:event/";
	pub const TIGHTBEAM_EVENT_URN_PREFIX: &str = "urn:tightbeam:instrumentation:event/";

	// Core lifecycle events
	pub const START: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/start");
	pub const END: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/end");

	// Gate events
	pub const GATE_ACCEPT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/gate-accept");
	pub const GATE_REJECT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/gate-reject");

	// Transport events
	pub const REQUEST_RECV: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/request-recv");
	pub const RESPONSE_SEND: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/response-send");

	// Connection lifecycle events
	pub const CONNECTION_ACCEPTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/connection-accepted");
	pub const CONNECTION_CLOSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/connection-closed");
	pub const CONNECTION_STALE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/connection-stale");
	#[rustfmt::skip]
	pub const CONNECTION_RECONNECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/connection-reconnected");

	// Assertion events
	pub const ASSERT_LABEL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/assert-label");
	pub const ASSERT_PAYLOAD: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/assert-payload");

	// Handler events
	pub const HANDLER_ENTER: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/handler-enter");
	pub const HANDLER_EXIT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/handler-exit");

	// Processing events
	pub const CRYPTO_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/crypto-step");
	pub const COMPRESS_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/compress-step");
	pub const ROUTE_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/route-step");
	pub const POLICY_EVAL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/policy-eval");

	// Process events
	pub const PROCESS_TRANSITION: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/process-transition");
	pub const PROCESS_HIDDEN: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/process-hidden");

	// FDR/exploration events
	pub const SEED_START: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/seed-start");
	pub const SEED_END: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/seed-end");
	pub const STATE_EXPAND: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/state-expand");
	pub const STATE_PRUNE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/state-prune");
	pub const DIVERGENCE_DETECT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/divergence-detect");
	pub const REFUSAL_SNAPSHOT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/refusal-snapshot");
	pub const ENABLED_SET_SAMPLE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/enabled-set-sample");

	// Error events
	pub const WARN: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/warn");
	pub const ERROR: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/error");

	// Timing events
	pub const TIMING_WCET: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/timing-wcet");
	pub const TIMING_DEADLINE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/timing-deadline");
	pub const TIMING_JITTER: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/timing-jitter");
	pub const TIMING_SLACK: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/timing-slack");

	// Fault events
	pub const FAULT_INJECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/fault-injected");
	pub const FAULT_RECOVERED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/fault-recovered");
	pub const FAULT_DETECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/fault-detected");

	// Schedulability events
	pub const TASK_RELEASE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/task-release");
	pub const TASK_COMPLETE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/task-complete");
	pub const TASK_MISSED_DEADLINE: Urn<'static> =
		Urn::new(TIGHTBEAM_NID, "instrumentation:event/task-missed-deadline");

	// Scheduler events
	pub const SCHEDULER_ALLOCATE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/scheduler-allocate");
	pub const SCHEDULER_RELEASE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/scheduler-release");
	pub const SCHEDULER_BLOCKED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "instrumentation:event/scheduler-blocked");
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
		pub timestamp_ns: Option<u64>,
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
	use crate::der::asn1::{ContextSpecific, ContextSpecificRef, OctetString, OctetStringRef};
	use crate::der::{Decode, Encode, FixedTag, Sequence, Tag, TagMode, TagNumber};
	use crate::utils::urn::Urn;
	use crate::Beamable;
	use crate::TightBeamError;

	#[derive(Clone, Debug, PartialEq)]
	pub struct TbEvent {
		/// Sequence number within the trace
		pub seq: u32,
		/// Event kind URN
		pub urn: Urn<'static>,
		/// Optional event label
		pub label: Option<String>,
		/// Optional SHA3-256 payload hash
		pub payload_hash: Option<[u8; 32]>,
		/// Elapsed time of the instrumented operation (a span length)
		pub duration_ns: Option<u64>,
		/// Instant the event occurred, relative to the trace clock origin
		/// (a point in time; used for deadline start/end matching)
		pub timestamp_ns: Option<u64>,
		/// Event flags
		pub flags: u32,
		/// Optional opaque extension bytes
		pub extras: Option<Vec<u8>>,
	}

	/// Context-specific tag numbers for `TbEvent` optional fields.
	///
	/// Every OPTIONAL field carries an EXPLICIT context tag so adjacent
	/// optionals of the same universal type (`duration_ns`/`timestamp_ns`,
	/// `payload_hash`/`extras`) stay unambiguous on the wire when any subset
	/// is absent.
	mod tb_event_tags {
		use crate::der::TagNumber;

		pub const LABEL: TagNumber = TagNumber::N0;
		pub const PAYLOAD_HASH: TagNumber = TagNumber::N1;
		pub const DURATION_NS: TagNumber = TagNumber::N2;
		pub const TIMESTAMP_NS: TagNumber = TagNumber::N3;
		pub const EXTRAS: TagNumber = TagNumber::N4;
	}

	fn tagged<T>(tag_number: TagNumber, value: T) -> ContextSpecific<T> {
		ContextSpecific { tag_number, tag_mode: TagMode::Explicit, value }
	}

	/// Borrowing variant for encode-only paths: avoids cloning the value
	/// just to wrap it in a context-specific tag.
	fn tagged_ref<T>(tag_number: TagNumber, value: &T) -> ContextSpecificRef<'_, T> {
		ContextSpecificRef { tag_number, tag_mode: TagMode::Explicit, value }
	}

	// Manual DER implementation: Sequence derive can't handle Urn<'static>
	// lifetime
	impl FixedTag for TbEvent {
		const TAG: Tag = Tag::Sequence;
	}

	impl crate::der::EncodeValue for TbEvent {
		fn value_len(&self) -> crate::der::Result<crate::der::Length> {
			let mut len = self.seq.encoded_len()?;
			len = (len + self.urn.encoded_len()?)?;

			if let Some(ref label) = self.label {
				len = (len + tagged_ref(tb_event_tags::LABEL, label).encoded_len()?)?;
			}
			if let Some(ref payload_hash) = self.payload_hash {
				let os = OctetStringRef::new(payload_hash.as_slice())?;
				len = (len + tagged(tb_event_tags::PAYLOAD_HASH, os).encoded_len()?)?;
			}
			if let Some(duration_ns) = self.duration_ns {
				len = (len + tagged(tb_event_tags::DURATION_NS, duration_ns).encoded_len()?)?;
			}
			if let Some(timestamp_ns) = self.timestamp_ns {
				len = (len + tagged(tb_event_tags::TIMESTAMP_NS, timestamp_ns).encoded_len()?)?;
			}

			len = (len + self.flags.encoded_len()?)?;

			if let Some(ref extras) = self.extras {
				let os = OctetStringRef::new(extras.as_slice())?;
				len = (len + tagged(tb_event_tags::EXTRAS, os).encoded_len()?)?;
			}

			Ok(len)
		}

		fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
			self.seq.encode(encoder)?;
			self.urn.encode(encoder)?;

			if let Some(ref label) = self.label {
				tagged_ref(tb_event_tags::LABEL, label).encode(encoder)?;
			}
			if let Some(ref payload_hash) = self.payload_hash {
				let os = OctetStringRef::new(payload_hash.as_slice())?;
				tagged(tb_event_tags::PAYLOAD_HASH, os).encode(encoder)?;
			}
			if let Some(duration_ns) = self.duration_ns {
				tagged(tb_event_tags::DURATION_NS, duration_ns).encode(encoder)?;
			}
			if let Some(timestamp_ns) = self.timestamp_ns {
				tagged(tb_event_tags::TIMESTAMP_NS, timestamp_ns).encode(encoder)?;
			}

			self.flags.encode(encoder)?;

			if let Some(ref extras) = self.extras {
				let os = OctetStringRef::new(extras.as_slice())?;
				tagged(tb_event_tags::EXTRAS, os).encode(encoder)?;
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

				let label = ContextSpecific::<String>::decode_explicit(seq, tb_event_tags::LABEL)?.map(|cs| cs.value);
				let payload_hash: Option<[u8; 32]> =
					ContextSpecific::<OctetString>::decode_explicit(seq, tb_event_tags::PAYLOAD_HASH)?.and_then(|cs| {
						let bytes = cs.value.as_bytes();
						if bytes.len() == 32 {
							let mut hash = [0u8; 32];
							hash.copy_from_slice(bytes);
							Some(hash)
						} else {
							None
						}
					});

				let duration_ns =
					ContextSpecific::<u64>::decode_explicit(seq, tb_event_tags::DURATION_NS)?.map(|cs| cs.value);
				let timestamp_ns =
					ContextSpecific::<u64>::decode_explicit(seq, tb_event_tags::TIMESTAMP_NS)?.map(|cs| cs.value);

				let flags = u32::decode(seq)?;
				let extras = ContextSpecific::<OctetString>::decode_explicit(seq, tb_event_tags::EXTRAS)?
					.map(|cs| cs.value.as_bytes().to_vec());

				Ok(TbEvent { seq: seq_val, urn, label, payload_hash, duration_ns, timestamp_ns, flags, extras })
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
		/// `overflow` MUST reflect whether the collector dropped events at
		/// its `max_events` bound (see `TraceCollector::overflowed`).
		pub fn finalize(spec_hash: [u8; 32], events: Vec<TbEvent>, overflow: bool) -> Result<Self, TightBeamError> {
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
				bytes.extend_from_slice(&ev.timestamp_ns.unwrap_or_default().to_be_bytes());
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

			Ok(Self { spec_hash: spec_hash_os, trace_hash, evidence_hash, events, overflow })
		}
	}
}

#[cfg(feature = "instrument")]
pub use active::*;
#[cfg(not(feature = "instrument"))]
pub use stub::*;

#[cfg(all(test, feature = "instrument"))]
mod tests {
	use super::*;
	use crate::error::Result;

	#[test]
	fn finalize_propagates_overflow_flag() -> Result<()> {
		let truncated = EvidenceArtifact::finalize([0u8; 32], Vec::new(), true)?;
		let complete = EvidenceArtifact::finalize([0u8; 32], Vec::new(), false)?;
		assert!(truncated.overflow);
		assert!(!complete.overflow);

		Ok(())
	}
}
