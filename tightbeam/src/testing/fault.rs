//! Fault injection traits for CSP state-driven error injection
//!
//! These traits enable type-safe fault injection by allowing CSP states and
//! events to be used as keys for fault configuration. They work independently
//! of the FDR exploration layer.

use std::borrow::Cow;

use crate::urn::Urn;

/// Trait for type-safe process state identifiers
///
/// Auto-implemented by `tb_gen_process_types!` macro or can be manually
/// implemented for custom state tracking in fault injection scenarios.
///
/// # Example
///
/// ```ignore
/// use tightbeam::testing::ProcessState;
///
/// #[derive(Debug, Clone, Copy)]
/// struct MyState;
///
/// impl ProcessState for MyState {
///     fn process_name(&self) -> &'static str { "MyProcess" }
///     fn state_name(&self) -> &'static str { "Ready" }
/// }
/// ```
pub trait ProcessState: Copy + core::fmt::Debug {
	/// Process name (e.g., "ClientServerProcess")
	fn process_name(&self) -> &'static str;

	/// State name (e.g., "Idle", "Connected")
	fn state_name(&self) -> &'static str;

	/// Full qualified key for fault injection HashMap lookups
	///
	/// Format: "ProcessName.StateName"
	fn full_key(&self) -> Cow<'static, str> {
		Cow::Owned(format!("{}.{}", self.process_name(), self.state_name()))
	}
}

/// Trait for type-safe process event identifiers
///
/// Auto-implemented by `tb_gen_process_types!` macro or can be manually
/// implemented for custom event tracking in fault injection scenarios.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
///
/// use tightbeam::testing::ProcessEvent;
/// use tightbeam::urn::Urn;
///
/// const SEND: Urn<'static> = tightbeam::urn!("doc", "event:fault/send");
///
/// #[derive(Debug, Clone)]
/// struct MyEvent(Urn<'static>);
///
/// impl ProcessEvent for MyEvent {
///     fn event_label(&self) -> Cow<'static, str> { self.0.event_label() }
/// }
///
/// assert_eq!(MyEvent(SEND).event_label(), "urn:doc:event:fault/send");
/// ```
pub trait ProcessEvent: Clone + core::fmt::Debug {
	/// The label of the event, as the CSP spec and the trace name it. A URN
	/// event renders the full URN, so a fault key matches the label that the
	/// trace records.
	fn event_label(&self) -> Cow<'static, str>;
}

impl ProcessEvent for Urn<'static> {
	fn event_label(&self) -> Cow<'static, str> {
		Cow::Owned(self.to_string())
	}
}
