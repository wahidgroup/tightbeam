//! The instrumentation subsystem.
//!
//! It implements the normative event taxonomy and the evidence-artifact hash
//! of the tightbeam protocol.
//!
//! The feature flags set this contract:
//! - The module and the [`events`] URN inventory build whenever `std` is on,
//!   so callers can label trace records with or without [`TbEvent`].
//! - Without `instrument`, the emit APIs are stubs that discard each event.
//! - With `instrument`, emission MUST be amortized O(1) and overflow MUST set a flag.
//!
//! The evidence hash is SHA3-256 over a stable length-prefixed byte layout.
//! `TbEvent` and `EvidenceArtifact` encode as DER.

#![allow(clippy::module_name_repetitions)]

pub mod events;

#[cfg(not(feature = "instrument"))]
pub mod stub {
	use std::borrow::Cow;

	use crate::urn::Urn;
	use crate::TightBeamError;

	#[derive(Clone, Debug)]
	pub struct TbEvent {
		/// The sequence number within the trace.
		pub seq: u32,
		/// The URN of the event kind.
		pub urn: Urn<'static>,
		/// The event label, when the event has one. A static label stays
		/// borrowed.
		pub label: Option<Cow<'static, str>>,
		/// The SHA3-256 hash of the payload, when the event carries one.
		pub payload_hash: Option<[u8; 32]>,
		/// The elapsed time of the instrumented operation, a span length.
		pub duration_ns: Option<u64>,
		/// The instant the event occurred, relative to the trace clock origin.
		pub timestamp_ns: Option<u64>,
		/// The event flags.
		pub flags: u32,
		/// Opaque extension bytes, when the event carries any.
		pub extras: Option<Vec<u8>>,
	}

	/// The instrumentation settings of a trace, in a build without the
	/// `instrument` feature.
	///
	/// The fields match the `instrument` build, so code that sets them compiles
	/// in both. [`Default`] turns every flag off and sets `max_events` to 1024.
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
	#[derive(Clone, Copy, Debug)]
	pub struct TbInstrumentationConfig {
		/// Whether each event carries the SHA3-256 hash of its payload.
		pub enable_payloads: bool,
		/// Whether the trace records the internal events, each at the step its
		/// constant names: [`HANDLER_ENTER`], [`HANDLER_EXIT`],
		/// [`CRYPTO_STEP`], [`COMPRESS_STEP`], [`ROUTE_STEP`], and
		/// [`POLICY_EVAL`].
		///
		/// # Warning
		///
		/// A build without `instrument` emits no event, so either value gives
		/// the same trace.
		///
		/// [`HANDLER_ENTER`]: super::events::HANDLER_ENTER
		/// [`HANDLER_EXIT`]: super::events::HANDLER_EXIT
		/// [`CRYPTO_STEP`]: super::events::CRYPTO_STEP
		/// [`COMPRESS_STEP`]: super::events::COMPRESS_STEP
		/// [`ROUTE_STEP`]: super::events::ROUTE_STEP
		/// [`POLICY_EVAL`]: super::events::POLICY_EVAL
		pub enable_internal_detail: bool,
		/// Whether FDR exploration records the observable events each visited
		/// state offers, as an [`ENABLED_SET_SAMPLE`] event.
		///
		/// # Warning
		///
		/// A build without `instrument` emits no event, so either value gives
		/// the same trace.
		///
		/// [`ENABLED_SET_SAMPLE`]: super::events::ENABLED_SET_SAMPLE
		pub sample_enabled_sets: bool,
		/// Whether FDR exploration records the refusal set of each stable or
		/// accepting state it visits, as a [`REFUSAL_SNAPSHOT`] event.
		///
		/// # Warning
		///
		/// A build without `instrument` emits no event, so either value gives
		/// the same trace.
		///
		/// [`REFUSAL_SNAPSHOT`]: super::events::REFUSAL_SNAPSHOT
		pub sample_refusals: bool,
		/// Whether FDR exploration records the hidden run of each divergence it
		/// finds, as a [`DIVERGENCE_DETECT`] event.
		///
		/// # Warning
		///
		/// A build without `instrument` emits no event, so either value gives
		/// the same trace.
		///
		/// [`DIVERGENCE_DETECT`]: super::events::DIVERGENCE_DETECT
		pub divergence_heuristics: bool,
		/// How many events the default bounded sink holds before it drops more.
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

	use std::borrow::Cow;
	use std::sync::{Arc, Mutex, PoisonError};

	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::der::asn1::{ContextSpecific, OctetString, OctetStringRef, Utf8StringRef};
	use crate::der::{Decode, Encode, FixedTag, Sequence, Tag, TagMode, TagNumber};
	use crate::urn::Urn;
	use crate::Beamable;
	use crate::TightBeamError;

	#[derive(Clone, Debug, PartialEq)]
	pub struct TbEvent {
		/// The sequence number within the trace.
		pub seq: u32,
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
	}

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
				let seq_val = u32::decode(reader)?;
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

	/// The instrumentation settings of a trace.
	///
	/// [`TraceConfig::with_instrumentation`] takes them, and the collector
	/// applies them to each event it records. [`Default`] turns every flag off
	/// and sets `max_events` to 1024.
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
		/// [`HANDLER_ENTER`]: super::events::HANDLER_ENTER
		/// [`HANDLER_EXIT`]: super::events::HANDLER_EXIT
		/// [`CRYPTO_STEP`]: super::events::CRYPTO_STEP
		/// [`COMPRESS_STEP`]: super::events::COMPRESS_STEP
		/// [`ROUTE_STEP`]: super::events::ROUTE_STEP
		/// [`POLICY_EVAL`]: super::events::POLICY_EVAL
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
		/// [`ENABLED_SET_SAMPLE`]: super::events::ENABLED_SET_SAMPLE
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
		/// [`REFUSAL_SNAPSHOT`]: super::events::REFUSAL_SNAPSHOT
		pub sample_refusals: bool,
		/// Whether `FdrExplorer::explore_into` records the hidden run of each
		/// divergence it finds, as a [`DIVERGENCE_DETECT`] event.
		///
		/// - A state diverges when a hidden run from it reaches a cycle of hidden
		///   events or passes `max_internal_run`. Every exploration checks
		///   this, and a divergence refutes `divergence_free`.
		/// - A scenario records these events into the trace that `ScenarioVerdict::exploration` returns.
		///
		/// [`DIVERGENCE_DETECT`]: super::events::DIVERGENCE_DETECT
		pub divergence_heuristics: bool,
		/// How many events the default bounded sink holds before it drops more.
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

	/// The event retention policy of a
	/// [`TraceCollector`](crate::trace::TraceCollector), which delivers every
	/// emitted [`TbEvent`] to exactly one sink.
	///
	/// - When [`TraceConfig::sink`](crate::trace::TraceConfig::sink) is `None`,
	///   the collector MUST use [`BoundedMemorySink`] sized by `max_events`.
	/// - Implementations MAY forward to an exporter, spill to disk, or retain unbounded history.
	///
	/// [`Self::emit`] and [`Self::retains`] run on the control-plane hot path,
	/// so an implementation MUST be amortized O(1) and MUST NOT block on I/O.
	/// A sink buffers its I/O and defers it.
	pub trait EventSink: Send + Sync {
		/// Retain or forward one event.
		fn emit(&self, event: TbEvent);

		/// Remove and return all retained events, ordered by [`TbEvent::seq`].
		///
		/// They feed spec verification and [`EvidenceArtifact::finalize`]. A
		/// forward-only sink that retains nothing MUST return an empty vector.
		fn drain(&self) -> Vec<TbEvent>;

		/// A sticky latch that reads `true` once the sink drops any event.
		///
		/// It feeds the `overflow` field of [`EvidenceArtifact::finalize`].
		/// Evidence from a truncated trace MUST NOT claim completeness.
		fn overflowed(&self) -> bool;

		/// Whether this sink keeps the next event that it receives.
		///
		/// The collector asks after it takes the event's sequence number and
		/// before it builds the event, so a dropped event costs no allocation.
		/// A sink that answers `false` drops that event, so
		/// [`Self::overflowed`] MUST then read `true`. The default keeps every
		/// event.
		///
		/// # Examples
		///
		/// ```
		/// use tightbeam::instrumentation::{BoundedMemorySink, EventSink};
		///
		/// let full = BoundedMemorySink::new(0);
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
	/// - It keeps the oldest events, drops each event past `max_events`, and sets the latch.
	/// - [`EventSink::retains`] answers from the same bound, so the collector builds no event the sink drops.
	/// - [`EventSink::drain`] frees capacity but MUST NOT clear the latch.
	/// - Dropped events consume collector sequence numbers too, so gaps in [`TbEvent::seq`] mark truncation.
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

		/// Whether a sink that holds `held` events drops the next one, which
		/// sets the latch.
		fn drops_next(&self, held: usize) -> bool {
			let full = (held as u32) >= self.max_events;
			if full {
				self.overflow.store(true, Ordering::Relaxed);
			}

			full
		}
	}

	impl Default for BoundedMemorySink {
		fn default() -> Self {
			Self::new(TbInstrumentationConfig::default().max_events)
		}
	}

	impl EventSink for BoundedMemorySink {
		fn emit(&self, event: TbEvent) {
			// The capacity check and the push share one lock, so concurrent
			// emitters cannot overshoot `max_events` between them.
			if let Ok(mut events) = self.events.lock() {
				if self.drops_next(events.len()) {
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

		// It reads the length under the lock `emit` takes. A poisoned lock
		// still holds a whole list, because `emit` and `drain` each change it
		// in one step.
		fn retains(&self) -> bool {
			let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
			!self.drops_next(events.len())
		}
	}

	#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
	pub struct EvidenceArtifact {
		/// The 32-byte hash of the spec that the caller passed to `finalize`.
		pub spec_hash: OctetString,
		/// The SHA3-256 hash of the events in their length-prefixed layout.
		pub trace_hash: OctetString,
		/// The SHA3-256 hash of `spec_hash` followed by `trace_hash`.
		pub evidence_hash: OctetString,
		/// The events the trace hash covers, in the order given.
		pub events: Vec<TbEvent>,
		/// Whether the collector dropped events at its `max_events` bound.
		pub overflow: bool,
	}

	impl EvidenceArtifact {
		/// Builds the evidence artifact of `events` against `spec_hash`.
		///
		/// `overflow` MUST reflect whether the collector dropped events at
		/// its `max_events` bound (see `TraceCollector::overflowed`).
		pub fn finalize(
			spec_hash: [u8; 32],
			events: impl IntoIterator<Item = TbEvent>,
			overflow: bool,
		) -> Result<Self, TightBeamError> {
			let events: Vec<TbEvent> = events.into_iter().collect();
			// The trace hash reads a canonical byte layout in a stable order.
			let mut bytes = Vec::with_capacity(events.len().saturating_mul(64));
			for ev in &events {
				bytes.extend_from_slice(&ev.seq.to_be_bytes());

				// The URN enters the layout as its string form.
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
	use std::borrow::Cow;

	use super::*;
	use crate::der::asn1::{Any, OctetString};
	use crate::der::{Decode, Encode, Tag};
	use crate::error::Result;

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

		let encoded = event.to_der().expect("an event built from valid parts encodes");
		let decoded = TbEvent::from_der(&encoded).expect("what the encoder wrote, the decoder reads");
		assert_eq!(decoded.seq, event.seq);
		assert_eq!(decoded.label, event.label);
		assert_eq!(decoded.payload_hash, event.payload_hash);
		assert_eq!(decoded.duration_ns, event.duration_ns);
		assert_eq!(decoded.timestamp_ns, event.timestamp_ns);
		assert_eq!(decoded.flags, event.flags);
		assert_eq!(decoded.extras, event.extras);
	}

	/// The same fields under a SEQUENCE header that declares `declared` bytes
	/// of body, whatever the real length of the body.
	fn event_with_declared_length(declared: usize) -> Vec<u8> {
		let honest = event_with_payload_hash([7u8; 32]);
		let body = &honest[2..];
		assert!(
			honest[0] == 0x30 && honest[1] < 128,
			"the helper above writes a short-form SEQUENCE"
		);

		let mut der = vec![0x30, declared as u8];
		der.extend_from_slice(body);
		der
	}

	// `decode_value` gets an unbounded reader, so a decoder that ignores
	// `header.length` reads past its own event when events are nested.
	#[test]
	fn a_declared_length_shorter_than_the_body_is_refused() {
		let honest_len = event_with_payload_hash([7u8; 32])[1] as usize;
		let refused = TbEvent::from_der(&event_with_declared_length(honest_len - 4));
		assert!(refused.is_err(), "a SEQUENCE length that undercuts its body must not decode");
	}

	#[test]
	fn a_declared_length_longer_than_the_body_is_refused() {
		let honest_len = event_with_payload_hash([7u8; 32])[1] as usize;
		let refused = TbEvent::from_der(&event_with_declared_length(honest_len + 4));
		assert!(refused.is_err(), "a SEQUENCE length that overruns its body must not decode");
	}

	// A truncated hash must not read as an absent one.
	#[test]
	fn a_payload_hash_of_the_wrong_length_is_refused() {
		let refused = TbEvent::from_der(&event_with_payload_hash([0u8; 16]));
		assert!(refused.is_err(), "a 16-byte payload hash must not decode as an absent one");
	}

	#[test]
	fn a_payload_hash_of_the_right_length_decodes() {
		let accepted = TbEvent::from_der(&event_with_payload_hash([7u8; 32])).expect("a 32-byte hash decodes");
		assert_eq!(accepted.payload_hash, Some([7u8; 32]));
	}

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

	/// A full bounded sink refuses the next event, and the refusal sets its
	/// overflow latch.
	#[test]
	fn bounded_sink_refuses_the_next_event_when_full_and_latches() {
		let sink = BoundedMemorySink::new(1);
		let first = sink.retains();
		sink.emit(sample_event(0));
		assert_eq!([first, sink.retains(), sink.overflowed()], [true, false, true]);
	}
}
