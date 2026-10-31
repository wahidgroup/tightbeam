//! The instrumentation subsystem: the normative event taxonomy and the
//! evidence-artifact hash of the tightbeam protocol.
//!
//! The feature flags set this contract:
//! - The module, the [`events`] URN inventory, [`TbEvent`], and
//!   [`TbInstrumentationConfig`] build whenever `std` is on.
//! - With `instrument`, a collector records its events ([`TraceCollector::instrumented`]).
//! - With `instrument`, emission MUST be amortized O(1) and overflow MUST set a flag.
//!
//! The evidence hash is SHA3-256 over the spec hash, the trace hash, and the
//! DER of the overflow flag, and the trace hash is SHA3-256 over the DER of
//! the events. `TbEvent` and `EvidenceArtifact` encode as DER.
//!
//! [`TraceCollector::instrumented`]: crate::trace::TraceCollector::instrumented

#![allow(clippy::module_name_repetitions)]

use std::borrow::Cow;

use crate::urn::Urn;

pub mod events;

#[cfg(feature = "instrument")]
pub use active::{BoundedMemorySink, EventSink, EvidenceArtifact};

/// One record of a trace: the kind of an event, its place in the trace, and
/// the evidence it carries.
#[derive(Clone, Debug, PartialEq)]
pub struct TbEvent {
	/// The sequence number within the trace.
	pub seq: u64,
	/// The URN of the event kind.
	pub urn: Urn<'static>,
	/// The event label, when the event has one. A static label stays
	/// borrowed, and a decoded label is owned.
	pub label: Option<Cow<'static, str>>,
	/// The SHA3-256 hash of the payload, when the event carries one.
	pub payload_hash: Option<[u8; 32]>,
	/// The elapsed time of the instrumented operation, a span length.
	pub duration_ns: Option<u64>,
	/// The instant the event occurred, relative to the trace clock origin.
	/// A deadline check reads it to pair a start with its end.
	pub timestamp_ns: Option<u64>,
	/// The event flags. [`Self::FROM_EVENT_API`] marks a record that the
	/// event API of a trace wrote, and every other bit is zero.
	pub flags: u32,
	/// Opaque extension bytes, when the event carries any.
	pub extras: Option<Vec<u8>>,
}

impl TbEvent {
	/// The flag of a record that the event API of a trace wrote, such as
	/// [`TraceCollector::emit_event`].
	///
	/// Every build sets it the same way, so a run writes one sink record
	/// and one evidence hash with `testing` on or off. A plain record, such
	/// as one of [`TraceCollector::emit`], has every flag clear.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, TbEvent};
	/// use tightbeam::trace::TraceCollector;
	///
	/// let trace = TraceCollector::new();
	/// trace.emit_event(events::GATE_REJECT)?;
	///
	/// let records = trace.drain_events();
	/// let reject = records.iter().find(|record| record.urn == events::GATE_REJECT);
	/// assert_eq!(reject.map(|record| record.flags), Some(TbEvent::FROM_EVENT_API));
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	///
	/// [`TraceCollector::emit_event`]: crate::trace::TraceCollector::emit_event
	/// [`TraceCollector::emit`]: crate::trace::TraceCollector::emit
	pub const FROM_EVENT_API: u32 = 1;

	/// Whether the event API of a trace wrote this record, as
	/// [`Self::FROM_EVENT_API`] marks it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, TbEvent};
	/// use tightbeam::trace::TraceCollector;
	///
	/// let trace = TraceCollector::new();
	/// trace.emit_event(events::GATE_ACCEPT)?;
	/// trace.emit(events::GATE_ACCEPT, "plain");
	///
	/// let records = trace.drain_events();
	/// let accepts = records.iter().filter(|record| record.urn == events::GATE_ACCEPT);
	/// let marks: Vec<bool> = accepts.map(TbEvent::is_from_event_api).collect();
	/// assert_eq!(marks, [true, false]);
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn is_from_event_api(&self) -> bool {
		self.flags & Self::FROM_EVENT_API != 0
	}

	/// The overflow warning that a sink keeps in place of this event, the
	/// first event that the sink drops.
	///
	/// The warning is an [`events::WARN`] record with the sequence number and
	/// the clock stamp of this event, so the record of the sink shows where and
	/// when the sink began to drop events. Its label is the URN of this event,
	/// and its other fields are clear.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, TbEvent};
	///
	/// let dropped = TbEvent {
	///     seq: 7,
	///     urn: events::GATE_REJECT,
	///     label: Some("PermissionDenied".into()),
	///     payload_hash: Some([0; 32]),
	///     duration_ns: None,
	///     timestamp_ns: Some(1_500),
	///     flags: TbEvent::FROM_EVENT_API,
	///     extras: None,
	/// };
	///
	/// let warning = dropped.into_overflow_warning();
	/// assert_eq!((warning.seq, warning.urn, warning.timestamp_ns), (7, events::WARN, Some(1_500)));
	/// assert_eq!(warning.label.as_deref(), Some("urn:tightbeam:event:gate/reject"));
	/// ```
	pub fn into_overflow_warning(self) -> Self {
		let label = Cow::Owned(self.urn.to_string());

		Self {
			seq: self.seq,
			urn: events::WARN,
			label: Some(label),
			payload_hash: None,
			duration_ns: None,
			timestamp_ns: self.timestamp_ns,
			flags: 0,
			extras: None,
		}
	}
}

/// The instrumentation settings of a trace.
///
/// [`TraceConfig::with_instrumentation`] takes them, and the collector
/// applies them to each event it records. [`Default`] turns every flag off
/// and sets `max_events` to 1024.
///
/// # Warning
///
/// A build without `instrument` records no event, so every setting gives the
/// same trace.
///
/// # Examples
///
/// ```
/// use tightbeam::instrumentation::TbInstrumentationConfig;
///
/// let defaults = TbInstrumentationConfig::default();
/// let config = TbInstrumentationConfig { enable_payloads: true, ..defaults };
///
/// assert_eq!(config.max_events, 1024);
/// ```
///
/// [`TraceConfig::with_instrumentation`]: crate::trace::TraceConfig::with_instrumentation
#[derive(Clone, Copy, Debug)]
pub struct TbInstrumentationConfig {
	/// Whether each event carries the SHA3-256 hash of its payload.
	pub enable_payloads: bool,
	/// Whether the trace records the internal events, each at the step its
	/// constant names: [`HANDLER_ENTER`], [`HANDLER_EXIT`],
	/// [`CRYPTO_STEP`], [`COMPRESS_STEP`], [`ROUTE_STEP`], and
	/// [`POLICY_EVAL`].
	///
	/// [`HANDLER_ENTER`]: events::HANDLER_ENTER
	/// [`HANDLER_EXIT`]: events::HANDLER_EXIT
	/// [`CRYPTO_STEP`]: events::CRYPTO_STEP
	/// [`COMPRESS_STEP`]: events::COMPRESS_STEP
	/// [`ROUTE_STEP`]: events::ROUTE_STEP
	/// [`POLICY_EVAL`]: events::POLICY_EVAL
	pub enable_internal_detail: bool,
	/// Whether `FdrExplorer::explore_into` records the observable events
	/// each visited state offers, as an [`ENABLED_SET_SAMPLE`] event. A
	/// scenario records them into the trace that
	/// `ScenarioVerdict::exploration` returns.
	///
	/// # Warning
	///
	/// Each visited state adds events, so a large exploration can pass
	/// `max_events`. The default sink then drops the later events, and
	/// `ConsumedTrace::is_complete` of the exploration trace reads `false`.
	///
	/// [`ENABLED_SET_SAMPLE`]: events::ENABLED_SET_SAMPLE
	pub sample_enabled_sets: bool,
	/// Whether `FdrExplorer::explore_into` records the refusal set of each
	/// stable or accepting state it visits, as a [`REFUSAL_SNAPSHOT`]
	/// event. A scenario records them into the trace that
	/// `ScenarioVerdict::exploration` returns.
	///
	/// # Warning
	///
	/// Each visited state adds events, so a large exploration can pass
	/// `max_events`. The default sink then drops the later events, and
	/// `ConsumedTrace::is_complete` of the exploration trace reads `false`.
	///
	/// [`REFUSAL_SNAPSHOT`]: events::REFUSAL_SNAPSHOT
	pub sample_refusals: bool,
	/// Whether `FdrExplorer::explore_into` records the hidden run of each
	/// divergence it finds, as a [`DIVERGENCE_DETECT`] event.
	///
	/// - A state diverges when a hidden run from it reaches a cycle of hidden
	///   events or passes `max_internal_run`. Every exploration checks
	///   this, and a divergence refutes `divergence_free`.
	/// - A scenario records these events into the trace that `ScenarioVerdict::exploration` returns.
	///
	/// [`DIVERGENCE_DETECT`]: events::DIVERGENCE_DETECT
	pub divergence_heuristics: bool,
	/// How many events the default bounded sink holds. Past them, the sink
	/// keeps one overflow warning and drops the rest.
	pub max_events: u32,
	/// Whether each event keeps the duration that its caller measured.
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

#[cfg(feature = "instrument")]
pub mod active {
	use core::sync::atomic::{AtomicBool, Ordering};

	use std::borrow::Cow;
	use std::sync::{Arc, Mutex, PoisonError};

	use crate::crypto::hash::{Digest, DigestWriter, Sha3_256};
	use crate::der::asn1::{ContextSpecific, OctetString, OctetStringRef, Utf8StringRef};
	use crate::der::{Decode, Encode, FixedTag, Sequence, Tag, TagMode, TagNumber};
	use crate::urn::Urn;
	use crate::Beamable;

	use super::{TbEvent, TbInstrumentationConfig};

	#[cfg(any(test, feature = "testing"))]
	use crate::trace::ConsumedTrace;
	#[cfg(any(test, feature = "testing"))]
	use crate::TightBeamError;

	/// The context-specific tag numbers of the optional fields of `TbEvent`.
	///
	/// Each OPTIONAL field carries an EXPLICIT context tag, so optionals of one
	/// universal type (`duration_ns` and `timestamp_ns`, or `payload_hash` and
	/// `extras`) stay unambiguous when any subset is absent.
	pub(super) mod tb_event_tags {
		use crate::der::TagNumber;

		pub const LABEL: TagNumber = TagNumber::N0;
		pub const PAYLOAD_HASH: TagNumber = TagNumber::N1;
		pub const DURATION_NS: TagNumber = TagNumber::N2;
		pub const TIMESTAMP_NS: TagNumber = TagNumber::N3;
		pub const EXTRAS: TagNumber = TagNumber::N4;
	}

	pub(super) fn tagged<T>(tag_number: TagNumber, value: T) -> ContextSpecific<T> {
		ContextSpecific { tag_number, tag_mode: TagMode::Explicit, value }
	}

	// These impls write the DER encoding of `TbEvent` by hand, because the
	// `Sequence` derive does not support the `Urn<'static>` lifetime.
	impl FixedTag for TbEvent {
		const TAG: Tag = Tag::Sequence;
	}

	impl crate::der::EncodeValue for TbEvent {
		fn value_len(&self) -> crate::der::Result<crate::der::Length> {
			let mut len = self.seq.encoded_len()?;
			len = (len + self.urn.encoded_len()?)?;

			if let Some(ref label) = self.label {
				let text = Utf8StringRef::new(label.as_bytes())?;
				len = (len + tagged(tb_event_tags::LABEL, text).encoded_len()?)?;
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
				let text = Utf8StringRef::new(label.as_bytes())?;
				tagged(tb_event_tags::LABEL, text).encode(encoder)?;
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
			header: crate::der::Header,
		) -> crate::der::Result<Self> {
			// `read_nested` bounds the body to the declared length, so a nested
			// event cannot read past its own. `sequence` would also demand a
			// second tag.
			reader.read_nested(header.length, |reader| {
				let seq_val = u64::decode(reader)?;
				let urn_decoded = Urn::decode(reader)?;
				let urn: Urn<'static> = urn_decoded.into_owned();

				let label = ContextSpecific::<String>::decode_explicit(reader, tb_event_tags::LABEL)?
					.map(|cs| Cow::Owned(cs.value));
				// A present hash of the wrong length is malformed input.
				let payload_hash: Option<[u8; 32]> =
					match ContextSpecific::<OctetString>::decode_explicit(reader, tb_event_tags::PAYLOAD_HASH)? {
						None => None,
						Some(field) => {
							let hash: [u8; 32] = field
								.value
								.as_bytes()
								.try_into()
								.map_err(|_| crate::der::ErrorKind::Length { tag: crate::der::Tag::OctetString })?;

							Some(hash)
						}
					};

				let duration_ns =
					ContextSpecific::<u64>::decode_explicit(reader, tb_event_tags::DURATION_NS)?.map(|cs| cs.value);
				let timestamp_ns =
					ContextSpecific::<u64>::decode_explicit(reader, tb_event_tags::TIMESTAMP_NS)?.map(|cs| cs.value);
				let flags = u32::decode(reader)?;
				let extras = ContextSpecific::<OctetString>::decode_explicit(reader, tb_event_tags::EXTRAS)?
					.map(|cs| cs.value.as_bytes().to_vec());

				Ok(TbEvent { seq: seq_val, urn, label, payload_hash, duration_ns, timestamp_ns, flags, extras })
			})
		}
	}

	/// The event retention policy of a
	/// [`TraceCollector`](crate::trace::TraceCollector), which delivers every
	/// emitted [`TbEvent`] to exactly one sink.
	///
	/// - When the [`TraceConfig`] names no sink ([`TraceConfig::with_sink`]),
	///   the collector MUST use [`BoundedMemorySink`] sized by `max_events`.
	/// - Implementations MAY forward to an exporter, spill to disk, or retain unbounded history.
	///
	/// [`Self::emit`] and [`Self::retains`] run on the control-plane hot path,
	/// so an implementation MUST be amortized O(1) and MUST NOT block on I/O.
	/// A sink buffers its I/O and defers it.
	///
	/// # Overflow
	///
	/// A sink that drops events MUST keep one warning of the truncation, so
	/// the record it drains or forwards shows where the truncation began:
	///
	/// - It keeps [`TbEvent::into_overflow_warning`] of the first event it drops, in place of that event.
	/// - [`Self::retains`] answers `true` until the sink holds it, so the collector builds that event.
	/// - [`BoundedMemorySink`] keeps the warning as the one record past its bound.
	///
	/// # Re-entry
	///
	/// - [`Self::emit`] runs after the trace clock releases its lock, so it MAY
	///   adopt a clock ([`TraceCollector::with_clock`]).
	/// - It MUST NOT emit into the collector that called it. The record of a
	///   clock origin runs in a [`Once`](std::sync::Once), and an emit inside the
	///   record re-enters the `Once`, which deadlocks.
	///
	/// [`TraceConfig`]: crate::trace::TraceConfig
	/// [`TraceConfig::with_sink`]: crate::trace::TraceConfig::with_sink
	/// [`TraceCollector::with_clock`]: crate::trace::TraceCollector::with_clock
	pub trait EventSink: Send + Sync {
		/// Retain or forward one event.
		fn emit(&self, event: TbEvent);

		/// Remove and return all retained events, ordered by [`TbEvent::seq`].
		///
		/// They feed spec verification and [`EvidenceArtifact::of`]. A
		/// forward-only sink that retains nothing MUST return an empty vector.
		fn drain(&self) -> Vec<TbEvent>;

		/// A sticky latch that reads `true` once the sink drops any event.
		///
		/// [`ConsumedTrace::is_complete`] reads it, so the `overflow` field of
		/// [`EvidenceArtifact::of`] reports a trace that the sink truncated.
		/// Evidence from a truncated trace MUST NOT claim completeness.
		///
		/// [`ConsumedTrace::is_complete`]: crate::trace::ConsumedTrace::is_complete
		fn overflowed(&self) -> bool;

		/// Whether this sink keeps the next event that it receives, or the
		/// overflow warning in its place. The default keeps every event.
		///
		/// - The collector asks after it takes the event's sequence number and before it builds the event.
		/// - An event that the sink refuses costs no allocation.
		/// - A sink that answers `false` drops that event, so [`Self::overflowed`] MUST then read `true`.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::{events, BoundedMemorySink, EventSink, TbEvent};
		///
		/// let full = BoundedMemorySink::new(0);
		/// let first = TbEvent {
		///     seq: 0,
		///     urn: events::START,
		///     label: None,
		///     payload_hash: None,
		///     duration_ns: None,
		///     timestamp_ns: None,
		///     flags: 0,
		///     extras: None,
		/// };
		///
		/// // The full sink keeps the warning of its first event, then refuses.
		/// assert!(full.retains());
		/// full.emit(first);
		///
		/// assert!(!full.retains());
		/// assert!(full.overflowed());
		/// ```
		fn retains(&self) -> bool {
			true
		}

		/// The sink of a trace that splits from this one.
		///
		/// The default `None` gives a connection trace a bounded buffer of its
		/// own. A sink that forwards each event returns its destination.
		///
		/// # Examples
		///
		/// ```
		/// use std::sync::Arc;
		///
		/// use tightbeam::instrumentation::{BoundedMemorySink, EventSink, TbEvent};
		///
		/// /// A sink that forwards each event to a shared destination.
		/// struct Forwarding(Arc<BoundedMemorySink>);
		///
		/// impl EventSink for Forwarding {
		///     fn emit(&self, event: TbEvent) {
		///         self.0.emit(event);
		///     }
		///
		///     fn drain(&self) -> Vec<TbEvent> {
		///         Vec::new()
		///     }
		///
		///     fn overflowed(&self) -> bool {
		///         self.0.overflowed()
		///     }
		///
		///     fn sibling(&self) -> Option<Arc<dyn EventSink>> {
		///         Some(Arc::clone(&self.0) as Arc<dyn EventSink>)
		///     }
		/// }
		///
		/// let forwarding = Forwarding(Arc::new(BoundedMemorySink::default()));
		///
		/// assert!(forwarding.sibling().is_some());
		/// assert!(BoundedMemorySink::default().sibling().is_none());
		/// ```
		fn sibling(&self) -> Option<Arc<dyn EventSink>> {
			None
		}
	}

	/// The default [`EventSink`], a bounded in-memory buffer with a sticky
	/// overflow latch.
	///
	/// - It keeps the oldest `max_events` events and drops each later one.
	/// - It keeps [`TbEvent::into_overflow_warning`] of the first event it drops, and sets the latch.
	/// - [`EventSink::retains`] answers from the same state, so the collector builds no event the sink drops.
	/// - [`EventSink::drain`] frees capacity but MUST NOT clear the latch, so the sink keeps one warning.
	/// - Dropped events consume collector sequence numbers too, so a gap in
	///   [`TbEvent::seq`] marks the events dropped before a later retained one.
	#[derive(Debug)]
	pub struct BoundedMemorySink {
		max_events: u32,
		events: Mutex<Vec<TbEvent>>,
		overflow: AtomicBool,
	}

	/// What a [`BoundedMemorySink`] keeps of the next event that it receives.
	enum Slot {
		/// The event itself, below the bound.
		Event,
		/// The overflow warning in place of the first event past the bound.
		Warning,
		/// Nothing, once the sink holds its warning.
		Dropped,
	}

	impl BoundedMemorySink {
		pub fn new(max_events: u32) -> Self {
			Self { max_events, events: Mutex::new(Vec::new()), overflow: AtomicBool::new(false) }
		}

		/// What a sink that holds `held` events keeps of the next one. The
		/// latch sets with the warning, so the sink keeps one warning.
		fn slot(&self, held: usize) -> Slot {
			let held = u32::try_from(held).unwrap_or(u32::MAX);
			if held < self.max_events {
				return Slot::Event;
			}
			if self.overflow.load(Ordering::Relaxed) {
				return Slot::Dropped;
			}

			Slot::Warning
		}

		/// The lock of the events this sink holds, which a test poisons.
		#[cfg(test)]
		pub(super) fn events_lock(&self) -> &Mutex<Vec<TbEvent>> {
			&self.events
		}
	}

	impl Default for BoundedMemorySink {
		fn default() -> Self {
			Self::new(TbInstrumentationConfig::default().max_events)
		}
	}

	impl EventSink for BoundedMemorySink {
		// The capacity check and the push share one lock, so concurrent
		// emitters stay within `max_events` and the one warning. A poisoned
		// lock still holds a whole list, as `retains` states.
		fn emit(&self, event: TbEvent) {
			let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
			match self.slot(events.len()) {
				Slot::Event => events.push(event),
				Slot::Warning => {
					self.overflow.store(true, Ordering::Relaxed);
					events.push(event.into_overflow_warning());
				}
				Slot::Dropped => {}
			}
		}

		// A poisoned lock still holds a whole list, as `retains` states.
		fn drain(&self) -> Vec<TbEvent> {
			let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
			events.drain(..).collect()
		}

		fn overflowed(&self) -> bool {
			self.overflow.load(Ordering::Relaxed)
		}

		// It reads the length under the lock `emit` takes. A poisoned lock
		// still holds a whole list, because `emit` and `drain` each change it
		// in one step.
		fn retains(&self) -> bool {
			let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
			let slot = self.slot(events.len());
			!matches!(slot, Slot::Dropped)
		}
	}

	/// The evidence that a trace gives for a spec, as ASN.1 DER.
	///
	/// [`Self::of`] builds one from a consumed trace. The DER decode recomputes
	/// both hashes from the spec hash, the events, and `overflow` it read, and
	/// refuses an artifact whose hashes differ, so a decoded artifact is one
	/// that [`Self::of`] could build. The evidence hash covers `overflow`, so
	/// the evidence hash of a run fixes whether its trace misses events.
	///
	/// ```text
	/// EvidenceArtifact ::= SEQUENCE {
	///   specHash      OCTET STRING,
	///   traceHash     OCTET STRING,
	///   evidenceHash  OCTET STRING,
	///   events        SEQUENCE OF TbEvent,
	///   overflow      BOOLEAN }
	/// ```
	#[derive(Beamable, Debug, Clone, PartialEq)]
	pub struct EvidenceArtifact {
		/// The 32-byte hash of the spec that the caller passed to
		/// [`Self::of`].
		spec_hash: OctetString,
		/// The SHA3-256 hash of the DER of `events`.
		trace_hash: OctetString,
		/// The SHA3-256 hash of `spec_hash`, then `trace_hash`, then the DER of
		/// `overflow`.
		evidence_hash: OctetString,
		/// The events the trace hash covers, in the order of the trace.
		events: Vec<TbEvent>,
		/// Whether the trace misses events of its run.
		overflow: bool,
	}

	impl EvidenceArtifact {
		/// The artifact of `events` against `spec_hash`, with `overflow` as
		/// given and both hashes computed over them.
		///
		/// The DER of `events` streams into the digest as it encodes.
		///
		/// # Errors
		///
		/// - [`crate::der::Error`] -- the DER of the events passes the length that DER encodes.
		fn hashed(spec_hash: [u8; 32], events: Vec<TbEvent>, overflow: bool) -> crate::der::Result<Self> {
			let mut trace_writer = DigestWriter(Sha3_256::new());
			events.encode(&mut trace_writer)?;
			let trace_digest = trace_writer.0.finalize();
			let trace_hash = OctetString::new(trace_digest.as_slice())?;

			let mut evidence_writer = DigestWriter(Sha3_256::new());
			evidence_writer.0.update(spec_hash);
			evidence_writer.0.update(trace_hash.as_bytes());
			overflow.encode(&mut evidence_writer)?;

			let evidence_digest = evidence_writer.0.finalize();
			let evidence_hash = OctetString::new(evidence_digest.as_slice())?;
			let spec_hash = OctetString::new(spec_hash)?;

			Ok(Self { spec_hash, trace_hash, evidence_hash, events, overflow })
		}

		/// The 32-byte hash of the spec that the trace is evidence for.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::EvidenceArtifact;
		/// use tightbeam::trace::ConsumedTrace;
		///
		/// let artifact = EvidenceArtifact::of([7u8; 32], &ConsumedTrace::new())?;
		/// assert_eq!(artifact.spec_hash().as_bytes(), [7u8; 32]);
		/// # Ok::<(), tightbeam::TightBeamError>(())
		/// ```
		pub fn spec_hash(&self) -> &OctetString {
			&self.spec_hash
		}

		/// The SHA3-256 hash of the DER of [`Self::events`], a SEQUENCE OF
		/// `TbEvent`.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::crypto::hash::{Digest, Sha3_256};
		/// use tightbeam::der::Encode;
		/// use tightbeam::instrumentation::EvidenceArtifact;
		/// use tightbeam::trace::ConsumedTrace;
		///
		/// let artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;
		/// let expected = Sha3_256::digest(artifact.events().to_vec().to_der()?);
		/// assert_eq!(artifact.trace_hash().as_bytes(), expected.as_slice());
		/// # Ok::<(), Box<dyn core::error::Error>>(())
		/// ```
		pub fn trace_hash(&self) -> &OctetString {
			&self.trace_hash
		}

		/// The SHA3-256 hash of [`Self::spec_hash`], then [`Self::trace_hash`],
		/// then the DER of [`Self::overflow`], a BOOLEAN.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::crypto::hash::{Digest, Sha3_256};
		/// use tightbeam::der::Encode;
		/// use tightbeam::instrumentation::EvidenceArtifact;
		/// use tightbeam::trace::ConsumedTrace;
		///
		/// let artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;
		/// let overflow = artifact.overflow().to_der()?;
		/// let covered = [[0u8; 32].as_slice(), artifact.trace_hash().as_bytes(), overflow.as_slice()].concat();
		/// let expected = Sha3_256::digest(covered);
		/// assert_eq!(artifact.evidence_hash().as_bytes(), expected.as_slice());
		/// # Ok::<(), Box<dyn core::error::Error>>(())
		/// ```
		pub fn evidence_hash(&self) -> &OctetString {
			&self.evidence_hash
		}

		/// The events that the trace hash covers, in the order of the trace.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::{events, EvidenceArtifact};
		/// use tightbeam::trace::{ConsumedTrace, TraceCollector};
		///
		/// let collector = TraceCollector::new();
		/// collector.emit(events::GATE_ACCEPT, "Ok");
		///
		/// let mut trace = ConsumedTrace::new();
		/// trace.populate_from_collector(&collector);
		///
		/// let artifact = EvidenceArtifact::of([0u8; 32], &trace)?;
		/// let urns: Vec<_> = artifact.events().iter().map(|event| &event.urn).collect();
		/// assert_eq!(urns, [&events::GATE_ACCEPT]);
		/// # Ok::<(), tightbeam::TightBeamError>(())
		/// ```
		pub fn events(&self) -> &[TbEvent] {
			&self.events
		}

		/// Whether the trace misses events of its run.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::EvidenceArtifact;
		/// use tightbeam::trace::ConsumedTrace;
		///
		/// let artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;
		/// assert!(!artifact.overflow());
		/// # Ok::<(), tightbeam::TightBeamError>(())
		/// ```
		pub fn overflow(&self) -> bool {
			self.overflow
		}
	}

	#[cfg(any(test, feature = "testing"))]
	impl EvidenceArtifact {
		/// The evidence artifact of `trace` against `spec_hash`, the 32-byte
		/// hash of the spec that the trace is evidence for.
		///
		/// - `events` holds the instrumentation events of `trace`, and `overflow`
		///   reads whether `trace` misses events of its run
		///   ([`ConsumedTrace::is_complete`]).
		/// - `trace_hash` is the SHA3-256 of the DER of `events`, a SEQUENCE OF
		///   `TbEvent` (X.690 § 8.10). Its EXPLICIT tags set an absent OPTIONAL
		///   field apart from an empty one (X.690 § 8.14).
		/// - `evidence_hash` is the SHA3-256 of `spec_hash`, then `trace_hash`, then the DER of `overflow`.
		///
		/// # Errors
		///
		/// - [`TightBeamError`] -- the DER of the events passes the length that DER encodes.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::{events, EvidenceArtifact, TbInstrumentationConfig};
		/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
		///
		/// // The sink holds one event, so it drops the second.
		/// let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
		/// let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
		/// collector.emit(events::GATE_ACCEPT, "Ok");
		/// collector.emit(events::GATE_ACCEPT, "Ok");
		///
		/// let mut trace = ConsumedTrace::new();
		/// trace.populate_from_collector(&collector);
		///
		/// let artifact = EvidenceArtifact::of([0u8; 32], &trace)?;
		/// assert!(artifact.overflow());
		/// # Ok::<(), tightbeam::TightBeamError>(())
		/// ```
		pub fn of(spec_hash: [u8; 32], trace: &ConsumedTrace) -> Result<Self, TightBeamError> {
			let events = trace.instrument_events().to_vec();
			let overflow = !trace.is_complete();

			Ok(Self::hashed(spec_hash, events, overflow)?)
		}
	}

	// The DER traits sit here by hand, so the decode can recompute both hashes.
	impl Sequence<'_> for EvidenceArtifact {}

	impl crate::der::EncodeValue for EvidenceArtifact {
		fn value_len(&self) -> crate::der::Result<crate::der::Length> {
			let mut len = self.spec_hash.encoded_len()?;
			len = (len + self.trace_hash.encoded_len()?)?;
			len = (len + self.evidence_hash.encoded_len()?)?;
			len = (len + self.events.encoded_len()?)?;
			len + self.overflow.encoded_len()?
		}

		fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
			self.spec_hash.encode(encoder)?;
			self.trace_hash.encode(encoder)?;
			self.evidence_hash.encode(encoder)?;
			self.events.encode(encoder)?;
			self.overflow.encode(encoder)
		}
	}

	impl<'a> crate::der::DecodeValue<'a> for EvidenceArtifact {
		// A spec hash of another width than 32 octets is a length error, and a
		// hash that differs from the one the fields give is a value error, both
		// of the OCTET STRING that carries it.
		fn decode_value<R: crate::der::Reader<'a>>(
			reader: &mut R,
			header: crate::der::Header,
		) -> crate::der::Result<Self> {
			reader.read_nested(header.length, |reader| {
				let spec_hash = OctetStringRef::decode(reader)?;
				let trace_hash = OctetStringRef::decode(reader)?;
				let evidence_hash = OctetStringRef::decode(reader)?;
				let events = Vec::<TbEvent>::decode(reader)?;
				let overflow = bool::decode(reader)?;

				let spec_hash = <[u8; 32]>::try_from(spec_hash.as_bytes());
				let spec_hash = spec_hash.map_err(|_other_width| Tag::OctetString.length_error())?;
				let artifact = Self::hashed(spec_hash, events, overflow)?;
				let trace_covered = artifact.trace_hash.as_bytes() == trace_hash.as_bytes();
				let evidence_covered = artifact.evidence_hash.as_bytes() == evidence_hash.as_bytes();
				let covered = trace_covered && evidence_covered;
				if !covered {
					return Err(Tag::OctetString.value_error());
				}

				Ok(artifact)
			})
		}
	}
}

#[cfg(all(test, feature = "instrument"))]
mod tests {
	use core::time::Duration;
	use std::borrow::Cow;
	use std::sync::Arc;

	use super::active::{tagged, tb_event_tags};
	use super::*;
	use crate::asn1::admission::fixtures::der_refusal;
	use crate::clock::ManualClock;
	use crate::der::asn1::{Any, OctetString};
	use crate::der::{Decode, Encode, ErrorKind, Length, Tag};
	use crate::hex;
	use crate::testing::fixtures::{der_round_trip, poison, TestClock, TestTrace};
	use crate::trace::{ConsumedTrace, TraceCollector};

	/// The trace hash of [`artifact_of_one_event`], which Python's `hashlib`
	/// computed over the DER of its event, written by hand from the `TbEvent`
	/// module of the README.
	const ONE_EVENT_TRACE_HASH: [u8; 32] = hex!("c3c796ba389a4d648c87e3c8acb8d07118637b0e163daf130bd2ad511d260c23");

	/// The evidence hash of [`artifact_of_an_overflowed_trace`], which Python's
	/// `hashlib` computed over 32 zero octets, the trace hash, and `01 01 FF`,
	/// with the DER of the two events written by hand from the `TbEvent` module
	/// of the README.
	const OVERFLOWED_EVIDENCE_HASH: [u8; 32] = hex!("7b28dfd077f95e098705f8b97b01c5168b3a52297baa022a19a2d143439573d1");

	/// One `TbEvent` SEQUENCE that carries `hash` as its payload-hash field.
	///
	/// The fields follow the layout `encode_value` writes, so the caller varies
	/// the hash length alone.
	fn event_with_payload_hash(hash: impl AsRef<[u8]>) -> Vec<u8> {
		let hash = hash.as_ref();
		let octets = OctetString::new(hash).expect("test hashes wrap in an OctetString");
		let tagged_hash = tagged(tb_event_tags::PAYLOAD_HASH, octets);

		let mut body = 0u32.to_der().expect("a sequence number encodes");
		body.extend(crate::instrumentation::events::START.to_der().expect("a URN encodes"));
		body.extend(tagged_hash.to_der().expect("a tagged octet string encodes"));
		body.extend(0u32.to_der().expect("a flag word encodes"));

		// `Any` writes the SEQUENCE header, so this builder holds for a body of
		// any length, short-form or long-form.
		Any::new(Tag::Sequence, body)
			.expect("the field encodings above are a well-formed SEQUENCE body")
			.to_der()
			.expect("a SEQUENCE re-encodes")
	}

	/// An event decodes from its DER as the event that wrote it, each optional
	/// field and the URN included.
	#[test]
	fn an_event_survives_a_der_round_trip() {
		let event = TbEvent {
			seq: 1,
			urn: crate::instrumentation::events::START,
			label: Some(Cow::Borrowed("a label")),
			payload_hash: Some([7u8; 32]),
			duration_ns: Some(5),
			timestamp_ns: Some(9),
			flags: 3,
			extras: Some(vec![1, 2, 3]),
		};

		let decoded = der_round_trip(&event);
		assert_eq!(decoded, event);
	}

	/// The fields of [`event_with_payload_hash`] under a SEQUENCE header whose
	/// short-form length misses the body by `offset` octets.
	fn event_with_length_off_by(offset: i8) -> Vec<u8> {
		let honest = event_with_payload_hash([7u8; 32]);
		let [0x30, length @ 0..=0x7f, body @ ..] = honest.as_slice() else {
			panic!("the payload-hash event is a short-form SEQUENCE");
		};

		let declared = length.checked_add_signed(offset).expect("the declared length fits one octet");
		[&[0x30, declared][..], body].concat()
	}

	// `decode_value` gets an unbounded reader, so a decoder that ignores
	// `header.length` reads past its own event when events are nested. A
	// declared length that undercuts or overruns the body is refused.
	crate::tb_cases! {
		fn a_declared_length_that_misses_the_body_is_refused((offset, refusal): (i8, ErrorKind)) {
			let decoded = TbEvent::from_der(&event_with_length_off_by(offset));
			assert_eq!(der_refusal(decoded), Some(refusal));
		}
		cases {
			/// The declared body ends at octet 72, before the payload-hash
			/// field inside it ends at octet 73.
			shorter => (-4, ErrorKind::Incomplete { expected_len: Length::new(73), actual_len: Length::new(72) }),
			/// The header declares a body that ends at octet 80, past the 76
			/// octets of the input.
			longer => (4, ErrorKind::Incomplete { expected_len: Length::new(80), actual_len: Length::new(76) }),
		}
	}

	// A payload hash decodes at 32 octets alone, so a truncated hash is a
	// length error and never reads as an absent one.
	crate::tb_cases! {
		fn a_payload_hash_decodes_only_at_32_octets(
			(hash, decoded): (Vec<u8>, Result<Option<[u8; 32]>, ErrorKind>)
		) {
			let event = TbEvent::from_der(&event_with_payload_hash(hash));
			assert_eq!(event.map(|event| event.payload_hash).map_err(|error| error.kind()), decoded);
		}
		cases {
			short => (vec![0; 16], Err(ErrorKind::Length { tag: Tag::OctetString })),
			full => (vec![7; 32], Ok(Some([7; 32]))),
		}
	}

	/// An event of sequence number `seq` with no optional field.
	fn sample_event(seq: u64) -> TbEvent {
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

	/// A sink that holds `cap` events, after it receives the events of the
	/// sequence numbers below `count`.
	fn filled(cap: u32, count: u64) -> BoundedMemorySink {
		let sink = BoundedMemorySink::new(cap);
		(0..count).for_each(|seq| sink.emit(sample_event(seq)));
		sink
	}

	// A bounded sink within its cap keeps every event, and a sink past its cap
	// latches the overflow and keeps one warning past the cap.
	crate::tb_cases! {
		fn a_bounded_sink_latches_past_its_cap((cap, emits, overflowed, drained): (u32, u64, bool, usize)) {
			let sink = filled(cap, emits);
			assert_eq!((sink.overflowed(), sink.drain().len()), (overflowed, drained));
		}
		cases {
			within_cap => (2, 2, false, 2),
			past_cap => (1, 3, true, 2),
		}
	}

	/// The warning of an event takes its sequence number and its clock stamp,
	/// names its URN, and clears every other field.
	#[test]
	fn the_warning_of_an_event_takes_its_place_and_names_it() {
		let dropped = TbEvent {
			label: Some(Cow::Borrowed("dropped")),
			payload_hash: Some([7u8; 32]),
			duration_ns: Some(3),
			timestamp_ns: Some(1_500),
			flags: TbEvent::FROM_EVENT_API,
			extras: Some(vec![1, 2]),
			..sample_event(7)
		};

		let warning = dropped.into_overflow_warning();
		let expected = TbEvent {
			urn: events::WARN,
			label: Some(Cow::Borrowed("urn:tightbeam:event:core/start")),
			timestamp_ns: Some(1_500),
			..sample_event(7)
		};
		assert_eq!(warning, expected);
	}

	/// A full bounded sink that holds no warning yet retains the next event,
	/// so the collector builds the event that the warning replaces.
	#[test]
	fn a_full_bounded_sink_retains_the_event_its_warning_replaces() {
		let sink = filled(1, 1);
		assert_eq!([sink.retains(), sink.overflowed()], [true, false]);
	}

	/// A drain frees the capacity of a bounded sink, so it keeps the next
	/// event with its latch clear.
	#[test]
	fn bounded_sink_drain_rearms_capacity() {
		let sink = filled(1, 1);
		sink.drain();
		sink.emit(sample_event(1));
		assert!(!sink.overflowed());
		assert_eq!(sink.drain().len(), 1);
	}

	/// The overflow latch of a bounded sink stays set across a drain, so the
	/// sink keeps one warning.
	#[test]
	fn bounded_sink_overflow_latch_survives_drain() {
		let sink = filled(1, 2);
		sink.drain();
		assert!(sink.overflowed());
	}

	/// A full bounded sink that holds its warning refuses the next event, and
	/// its overflow latch reads `true`.
	#[test]
	fn bounded_sink_refuses_the_next_event_when_full_and_latches() {
		let sink = BoundedMemorySink::new(1);
		let first = sink.retains();
		sink.emit(sample_event(0));
		sink.emit(sample_event(1));
		assert_eq!([first, sink.retains(), sink.overflowed()], [true, false, true]);
	}

	/// A poisoned sink keeps the events it holds, and the warning in place of
	/// the first event past its bound sets the latch, as an unpoisoned sink
	/// does.
	#[test]
	fn a_poisoned_sink_keeps_its_events_and_latches_a_drop() {
		let sink = filled(1, 1);
		poison(sink.events_lock());

		sink.emit(sample_event(1));

		assert_eq!((sink.overflowed(), sink.drain().len()), (true, 2));
	}

	/// The artifact of the trace that drains `collector`, against the zero
	/// spec hash.
	fn artifact_of(collector: &TraceCollector) -> EvidenceArtifact {
		let artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::drained_from(collector));
		artifact.expect("the events of a test trace encode as DER")
	}

	/// The trace hash of the artifact of a trace whose one event `record`
	/// writes, under a config that keeps durations.
	fn trace_hash_of(record: impl FnOnce(&TraceCollector)) -> OctetString {
		let collector =
			TestTrace::with_config(TbInstrumentationConfig { record_durations: true, ..Default::default() });
		record(&collector);

		artifact_of(&collector).trace_hash().clone()
	}

	/// An event that records a zero span and one that records no span hash
	/// apart, because the DER of an absent field differs from that of a zero.
	#[test]
	fn two_events_that_differ_in_an_absent_field_hash_apart() {
		let timed = trace_hash_of(|collector| collector.emit_with_timing(events::START, "x", Duration::ZERO));
		let untimed = trace_hash_of(|collector| collector.emit(events::START, "x"));
		assert_ne!(timed, untimed);
	}

	/// A trace that another reader drained first leaves the drop latch clear,
	/// and its artifact still reports that it misses events.
	#[test]
	fn an_artifact_of_a_truncated_trace_reports_overflow() {
		let collector = TraceCollector::new();
		collector.emit(events::START, "taken");
		let _taken = collector.drain_events();
		collector.emit(events::END, "left");

		let artifact = artifact_of(&collector);
		assert!(artifact.overflow());
	}

	/// The artifact of a complete trace of one event.
	fn artifact_of_one_event() -> EvidenceArtifact {
		let collector = TraceCollector::new();
		collector.emit(events::START, "covered");

		artifact_of(&collector)
	}

	/// The DER of an `EvidenceArtifact` SEQUENCE of `spec_hash`, the two hashes
	/// of `artifact`, `events`, and `overflow`, whether or not the hashes cover
	/// them.
	fn forged_der(
		artifact: &EvidenceArtifact,
		spec_hash: impl AsRef<[u8]>,
		events: Vec<TbEvent>,
		overflow: bool,
	) -> Vec<u8> {
		let spec_hash = OctetString::new(spec_hash.as_ref()).expect("a test spec hash wraps in an OctetString");
		let fields = [
			spec_hash.to_der().expect("an octet string encodes"),
			artifact.trace_hash().to_der().expect("an octet string encodes"),
			artifact.evidence_hash().to_der().expect("an octet string encodes"),
			events.to_der().expect("the events of a test trace encode"),
			overflow.to_der().expect("a boolean encodes"),
		];

		let sequence = Any::new(Tag::Sequence, fields.concat()).expect("the fields are a SEQUENCE body");
		sequence.to_der().expect("a SEQUENCE re-encodes")
	}

	/// The artifact of a trace whose sink holds one of the two events it is
	/// offered, so the trace misses an event.
	fn artifact_of_an_overflowed_trace() -> EvidenceArtifact {
		let collector = TestTrace::with_config(TbInstrumentationConfig { max_events: 1, ..Default::default() });
		collector.emit(events::START, "kept");
		collector.emit(events::END, "dropped");

		artifact_of(&collector)
	}

	// Each case is (the artifact of a trace, whether the trace overflowed). An
	// artifact decodes as the artifact that `of` built, `overflow` included.
	crate::tb_cases! {
		fn an_artifact_survives_a_der_round_trip((build, overflow): (fn() -> EvidenceArtifact, bool)) {
			let artifact = build();
			let decoded = der_round_trip(&artifact);
			assert_eq!((decoded.overflow(), decoded), (overflow, artifact));
		}
		cases {
			complete => (artifact_of_one_event, false),
			overflowed => (artifact_of_an_overflowed_trace, true),
		}
	}

	/// The events of an overflowed trace hold the warning of the first event
	/// that its sink dropped, so the trace hash covers the truncation.
	#[test]
	fn the_artifact_of_an_overflowed_trace_covers_its_warning() {
		let artifact = artifact_of_an_overflowed_trace();
		let urns: Vec<_> = artifact.events().iter().map(|event| &event.urn).collect();
		assert_eq!(urns, [&events::START, &events::WARN]);
	}

	/// The trace hash is the SHA3-256 of the DER of the events, a SEQUENCE OF
	/// `TbEvent`.
	#[test]
	fn the_trace_hash_is_the_sha3_of_the_der_of_the_events() {
		let artifact = artifact_of_one_event();
		assert_eq!(artifact.trace_hash().as_bytes(), ONE_EVENT_TRACE_HASH);
	}

	/// The DER that one forgery writes of an artifact.
	type Forgery = fn(&EvidenceArtifact) -> Vec<u8>;

	// The decode recomputes both hashes from the fields it read and takes a
	// spec hash of 32 octets, so it refuses an artifact whose hashes miss a
	// field, and a spec hash of another width.
	crate::tb_cases! {
		fn a_forged_artifact_is_refused(
			(build, forge, refusal): (fn() -> EvidenceArtifact, Forgery, ErrorKind)
		) {
			let artifact = build();
			let decoded = EvidenceArtifact::from_der(&forge(&artifact));
			assert_eq!(der_refusal(decoded), Some(refusal));
		}
		cases {
			/// The trace hash covers the events, so an artifact whose hashes do
			/// not cover its events is refused.
			events_not_covered => (
				artifact_of_one_event,
				|artifact| forged_der(artifact, artifact.spec_hash().as_bytes(), Vec::new(), artifact.overflow()),
				ErrorKind::Value { tag: Tag::OctetString },
			),
			/// The evidence hash covers the spec hash, so an artifact under
			/// another spec hash with the same trace hash is refused.
			spec_hash_not_covered => (
				artifact_of_one_event,
				|artifact| forged_der(artifact, [1u8; 32], artifact.events().to_vec(), artifact.overflow()),
				ErrorKind::Value { tag: Tag::OctetString },
			),
			/// `of` takes a spec hash of 32 octets, so the decode refuses a
			/// spec hash of another width.
			spec_hash_not_32_octets => (
				artifact_of_one_event,
				|artifact| forged_der(artifact, [0u8; 16], artifact.events().to_vec(), artifact.overflow()),
				ErrorKind::Length { tag: Tag::OctetString },
			),
			/// The evidence hash covers `overflow`, so the decode refuses the
			/// artifact of a truncated trace whose `overflow` reads `false`.
			overflow_not_covered => (
				artifact_of_an_overflowed_trace,
				|artifact| forged_der(artifact, artifact.spec_hash().as_bytes(), artifact.events().to_vec(), false),
				ErrorKind::Value { tag: Tag::OctetString },
			),
		}
	}

	/// The evidence hash of a run on `clock`: three events through the event
	/// API, so each event carries a stamp of the clock.
	fn evidence_hash_on(clock: &Arc<ManualClock>) -> OctetString {
		let trace = TestTrace::on(clock);
		let start = trace.emit_event(events::START);
		let reject = trace.emit_event_with_evidence(events::GATE_REJECT, "PermissionDenied", Some(b"peer key"));
		let end = trace.emit_event(events::END);
		start.and(reject).and(end).expect("the trace injects no fault");

		artifact_of(&trace).evidence_hash().clone()
	}

	/// Two runs of the same events on a clock that gives each of them the
	/// same readings give one evidence hash.
	#[test]
	fn two_runs_of_one_clock_reading_give_one_evidence_hash() {
		let clock = TestClock::manual();
		let (first, second) = (evidence_hash_on(&clock), evidence_hash_on(&clock));
		assert_eq!(first, second);
	}

	/// The evidence hash of an overflowed trace covers the DER of its
	/// `overflow`, the BOOLEAN TRUE of X.690 § 11.1.
	#[test]
	fn the_evidence_hash_covers_the_der_of_overflow() {
		let artifact = artifact_of_an_overflowed_trace();
		assert_eq!(artifact.evidence_hash().as_bytes(), OVERFLOWED_EVIDENCE_HASH);
	}
}
