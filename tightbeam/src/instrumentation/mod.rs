//! Instrumentation subsystem.
//!
//! Implements the normative event taxonomy and evidence artifact hashing
//! defined for the tighbeam protocol.
//!
//! Feature gating contract:
//! - The module and [`events`] URN inventory are available whenever `std` is
//!   enabled so callers can label trace records without opting into TbEvent.
//! - When `instrument` is disabled, emit APIs are no-op stubs.
//! - When `instrument` is enabled, emission MUST be amortized O(1) and overflow
//!   MUST set a flag.
//!
//! Evidence hashing uses SHA3-256 over a stable length-prefixed byte
//! layout. `TbEvent` / `EvidenceArtifact` themselves encode as DER.

#![allow(clippy::module_name_repetitions)]

pub mod events;

#[cfg(not(feature = "instrument"))]
pub mod stub {
	use crate::utils::urn::Urn;
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
	use core::sync::atomic::{AtomicBool, Ordering};

	use std::sync::Mutex;

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

	/// Event retention policy for a [`TraceCollector`](crate::trace::TraceCollector).
	///
	/// The collector delivers every emitted [`TbEvent`] to exactly one sink.
	/// When [`TraceConfig::sink`](crate::trace::TraceConfig::sink is `None`,
	/// the collector MUST use [`BoundedMemorySink`] sized by `max_events`.
	/// Implementations MAY forward to an exporter, spill to disk, or retain
	/// unbounded history.
	///
	/// [`Self::emit`] runs on the hot control-plane path: implementations
	/// MUST be amortized O(1) and MUST NOT block on I/O (buffer and defer).
	pub trait EventSink: Send + Sync {
		/// Retain or forward one event.
		fn emit(&self, event: TbEvent);

		/// Remove and return all retained events, ordered by [`TbEvent::seq`].
		///
		/// Feeds spec verification and [`EvidenceArtifact::finalize`].
		/// Forward-only sinks that retain nothing MUST return an empty vector.
		fn drain(&self) -> Vec<TbEvent>;

		/// Sticky latch: `true` if any event was dropped since creation.
		///
		/// Feeds the `overflow` field of [`EvidenceArtifact::finalize`].
		/// Evidence from a truncated trace MUST NOT claim completeness.
		fn overflowed(&self) -> bool;
	}

	/// Default [`EventSink`]: bounded in-memory buffer with a sticky
	/// overflow latch.
	///
	/// Events past `max_events` are dropped (newest lost, oldest kept) and
	/// the latch is set. [`EventSink::drain`] frees capacity but MUST NOT
	/// clear the latch. Dropped events still consume collector sequence
	/// numbers, so gaps in [`TbEvent::seq`] mark truncation.
	#[derive(Debug)]
	pub struct BoundedMemorySink {
		max_events: u32,
		events: Mutex<Vec<TbEvent>>,
		overflow: AtomicBool,
	}

	impl BoundedMemorySink {
		pub fn new(max_events: u32) -> Self {
			Self { max_events, events: Mutex::new(Vec::new()), overflow: AtomicBool::new(false) }
		}
	}

	impl Default for BoundedMemorySink {
		fn default() -> Self {
			Self::new(TbInstrumentationConfig::default().max_events)
		}
	}

	impl EventSink for BoundedMemorySink {
		fn emit(&self, event: TbEvent) {
			// Capacity check and push happen under one lock acquisition so
			// concurrent emitters cannot overshoot `max_events` between the
			// check and the insert.
			if let Ok(mut events) = self.events.lock() {
				if (events.len() as u32) >= self.max_events {
					self.overflow.store(true, Ordering::Relaxed);
					return;
				}

				events.push(event);
			}
		}

		fn drain(&self) -> Vec<TbEvent> {
			if let Ok(mut events) = self.events.lock() {
				events.drain(..).collect()
			} else {
				Vec::new()
			}
		}

		fn overflowed(&self) -> bool {
			self.overflow.load(Ordering::Relaxed)
		}
	}

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

	fn sample_event(seq: u32) -> TbEvent {
		TbEvent {
			seq,
			urn: events::START,
			label: None,
			payload_hash: None,
			duration_ns: None,
			timestamp_ns: None,
			flags: 0,
			extras: None,
		}
	}

	#[test]
	fn bounded_sink_retains_up_to_cap() {
		let sink = BoundedMemorySink::new(2);

		sink.emit(sample_event(0));
		sink.emit(sample_event(1));

		assert!(!sink.overflowed());
		assert_eq!(sink.drain().len(), 2);
	}

	#[test]
	fn bounded_sink_drops_past_cap_and_latches() {
		let sink = BoundedMemorySink::new(1);

		sink.emit(sample_event(0));
		sink.emit(sample_event(1));

		assert!(sink.overflowed());
		assert_eq!(sink.drain().len(), 1);
	}

	#[test]
	fn bounded_sink_drain_rearms_capacity() {
		let sink = BoundedMemorySink::new(1);

		sink.emit(sample_event(0));
		sink.drain();
		sink.emit(sample_event(1));

		assert!(!sink.overflowed());
		assert_eq!(sink.drain().len(), 1);
	}

	#[test]
	fn bounded_sink_overflow_latch_survives_drain() {
		let sink = BoundedMemorySink::new(1);

		sink.emit(sample_event(0));
		sink.emit(sample_event(1));
		sink.drain();

		assert!(sink.overflowed());
	}
}
