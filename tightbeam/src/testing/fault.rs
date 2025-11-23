//! Fault injection traits for CSP state-driven error injection
//!
//! These traits enable type-safe fault injection by allowing CSP states and
//! events to be used as keys for fault configuration. They work independently
//! of the FDR exploration layer.

use std::borrow::Cow;

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
/// ```ignore
/// use tightbeam::testing::ProcessEvent;
///
/// #[derive(Debug, Clone, Copy)]
/// struct MyEvent(&'static str);
///
/// impl ProcessEvent for MyEvent {
///     fn event_label(&self) -> &'static str { self.0 }
/// }
/// ```
pub trait ProcessEvent: Copy + core::fmt::Debug {
	/// Event label as used in CSP spec (e.g., "connect", "send")
	fn event_label(&self) -> &'static str;
}
