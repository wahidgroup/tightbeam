//! The freshness admission of signed gateway control frames.
//!
//! - [`FreshnessWindow`] is the one rule for whether a stated instant is
//!   fresh. The rumor seen window, the control window, the hive's replay
//!   window, and the gossip journal's retention all judge through it, each
//!   on the instant its frame or rumor states.
//! - [`GatewayReplayGuard`] is the one home for how a gateway spends and frees a control frame's replay slot.
//!
//! # Sources
//!
//! - CWE-294, authentication bypass by capture-replay: <https://cwe.mitre.org/data/definitions/294.html>

use core::time::Duration;
use std::sync::Arc;

use crate::clock::{Clock, UnixMillis};
use crate::colony::hive::ReplayGuard;
use crate::colony::protocol::IssuedAt;
use crate::crypto::sign::VerifiedSignature;
use crate::policy::TransitStatus;
use crate::Frame;

/// A span of time on each side of a clock reading, inside which a stated
/// instant is fresh.
///
/// The window holds in both directions, so a peer whose clock runs ahead of
/// or behind this one by at most the window still answers. The bound is
/// inclusive.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::clock::UnixMillis;
/// use tightbeam::colony::cluster::FreshnessWindow;
///
/// let window = FreshnessWindow::new(Duration::from_secs(30));
/// let now = UnixMillis::new(100_000);
///
/// assert!(window.admits(UnixMillis::new(70_000), now));
/// assert!(window.admits(UnixMillis::new(130_000), now));
/// assert!(!window.admits(UnixMillis::new(69_999), now));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessWindow {
	window: Duration,
}

impl FreshnessWindow {
	/// A window that reaches `window` to each side of the clock.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::cluster::FreshnessWindow;
	///
	/// let window = FreshnessWindow::new(Duration::ZERO);
	/// let now = UnixMillis::new(5_000);
	///
	/// assert!(window.admits(now, now));
	/// ```
	#[must_use]
	pub const fn new(window: Duration) -> Self {
		Self { window }
	}

	/// Whether `order`, a stated issue time, lies inside this window of `now`.
	///
	/// Both are instants, and the comparison reads the magnitude of their
	/// difference, so an exchange of the two changes no answer, and two plain
	/// parameters carry them.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::cluster::FreshnessWindow;
	///
	/// let window = FreshnessWindow::new(Duration::from_millis(1_000));
	///
	/// assert!(window.admits(UnixMillis::new(11_000), UnixMillis::new(10_000)));
	/// assert!(!window.admits(UnixMillis::new(11_001), UnixMillis::new(10_000)));
	/// ```
	#[must_use]
	pub fn admits(&self, order: UnixMillis, now: UnixMillis) -> bool {
		let distance = now.abs_diff(order);
		distance <= self.window
	}
}

impl From<Duration> for FreshnessWindow {
	/// The window that reaches `window` to each side of the clock, as
	/// [`FreshnessWindow::new`] builds it.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::colony::cluster::FreshnessWindow;
	///
	/// let window = FreshnessWindow::from(Duration::from_secs(30));
	/// assert_eq!(window, FreshnessWindow::new(Duration::from_secs(30)));
	/// ```
	fn from(window: Duration) -> Self {
		Self::new(window)
	}
}

/// The ledger that admits each signed control frame once.
pub(crate) struct GatewayReplayGuard {
	ledger: Arc<ReplayGuard>,
	/// The gateway's clock, against which the guard judges freshness.
	clock: Arc<dyn Clock>,
}

impl GatewayReplayGuard {
	/// A guard that admits each frame once inside `window` of its stated issue
	/// time, as `clock` reads it.
	pub(crate) fn new(window: Duration, clock: Arc<dyn Clock>) -> Self {
		Self { ledger: Arc::new(ReplayGuard::new(window)), clock }
	}

	/// Whether `frame`, whose signature verified as `signature`, is a fresh,
	/// first-seen signed control frame.
	///
	/// The checks apply in order:
	///
	/// 1. Require a signer identifier on the frame.
	/// 2. Insert the verified signature in the ledger under its
	///    `metadata.order`, by the rule of [`ReplayGuard::admits`].
	///
	/// The ledger refuses an order outside the freshness window, a full
	/// partition, and a duplicate of either kind:
	///
	/// - A signature it holds. It keys on the canonical form, so a capture
	///   with `s` flipped to `n - s` finds the slot its original spent.
	/// - A second frame of the signer at an order it holds, whatever its signature (README §5.7.1).
	pub(crate) fn admits(&self, frame: &Frame, signature: &VerifiedSignature) -> TransitStatus {
		let Some(signer_id) = frame.signer_id() else {
			return TransitStatus::PermissionDenied;
		};

		let now = self.clock.unix();
		if !self.ledger.check_and_insert(&signer_id, signature, frame.issued_at(), now) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}

	/// Frees the slot `signature` spent, so a refused frame stays
	/// admissible.
	///
	/// A gateway that refuses after admission would otherwise consume the
	/// peer's one chance to send that frame (CWE-645).
	pub(crate) fn release(&self, signature: &VerifiedSignature) {
		self.ledger.forget(signature);
	}
}

impl Clone for GatewayReplayGuard {
	fn clone(&self) -> Self {
		Self { ledger: Arc::clone(&self.ledger), clock: Arc::clone(&self.clock) }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::clock::ManualClock;
	use crate::tb_cases;
	use crate::testing::fixtures::{TestIdentity, TestRumor};

	/// The window every case judges against.
	const WINDOW: FreshnessWindow = FreshnessWindow::new(Duration::from_millis(30_000));

	/// The clock reading every case judges at.
	const NOW: UnixMillis = UnixMillis::new(31_000);

	// An issue time inside the window is fresh on either side of the clock,
	// and the window's edge counts as inside.
	tb_cases! {
		fn an_issue_time_inside_the_window_is_fresh(order: UnixMillis) {
			assert!(WINDOW.admits(order, NOW));
		}
		cases {
			at_the_clock => NOW,
			at_the_past_edge => UnixMillis::new(1_000),
			at_the_future_edge => UnixMillis::new(61_000),
		}
	}

	// One millisecond past either edge is stale.
	tb_cases! {
		fn an_issue_time_past_the_window_is_stale(order: UnixMillis) {
			assert!(!WINDOW.admits(order, NOW));
		}
		cases {
			past_the_past_edge => UnixMillis::new(999),
			past_the_future_edge => UnixMillis::new(61_001),
		}
	}

	/// A signed frame that states `order`, beside the signature that verified
	/// over it.
	fn signed_at(order: UnixMillis) -> (Frame, VerifiedSignature) {
		signed_carrying(order, [1])
	}

	/// A signed frame that states `order` and carries `payload`, beside the
	/// signature that verified over it. Two payloads give two signatures at
	/// one order.
	fn signed_carrying(order: UnixMillis, payload: impl Into<Vec<u8>>) -> (Frame, VerifiedSignature) {
		let frame = TestRumor::application(order.get(), payload);
		let identity = TestIdentity::insecure_fixed();
		let signature = frame.verify_under(identity.signing_certificate(), identity.policy());

		(frame, signature.expect("the fixed test key signed the frame"))
	}

	/// A control frame whose order leads the gateway clock by 59 s, inside a
	/// 60 s window, is still fresh 61 s after its admission, so the ledger
	/// refuses its replay (CWE-294).
	#[test]
	fn a_future_dated_control_frame_is_a_replay_while_it_is_fresh() {
		let clock = Arc::new(ManualClock::default());
		let guard = GatewayReplayGuard::new(Duration::from_millis(60_000), Arc::clone(&clock) as Arc<dyn Clock>);
		let (frame, signature) = signed_at(clock.unix().saturating_add(Duration::from_millis(59_000)));

		let first = guard.admits(&frame, &signature);
		clock.advance(Duration::from_millis(61_000));
		let replayed = guard.admits(&frame, &signature);

		assert_eq!(first, TransitStatus::Ok);
		assert_eq!(replayed, TransitStatus::PermissionDenied);
	}

	/// A control frame whose order lies past the window is stale, so the
	/// ledger refuses it (CWE-294).
	#[test]
	fn a_control_frame_past_the_window_is_refused() {
		let clock = Arc::new(ManualClock::default());
		let guard = GatewayReplayGuard::new(Duration::from_millis(60_000), Arc::clone(&clock) as Arc<dyn Clock>);
		let (frame, signature) = signed_at(clock.unix());

		clock.advance(Duration::from_millis(60_001));
		assert_eq!(guard.admits(&frame, &signature), TransitStatus::PermissionDenied);
	}

	/// A second control frame of one signer at the order of an admitted one
	/// is a duplicate (README §5.7.1), though its signature is new.
	#[test]
	fn a_second_control_frame_at_an_admitted_order_is_refused() {
		let clock = Arc::new(ManualClock::default());
		let guard = GatewayReplayGuard::new(Duration::from_millis(60_000), Arc::clone(&clock) as Arc<dyn Clock>);
		let (first, first_signature) = signed_carrying(clock.unix(), [1]);
		let (second, second_signature) = signed_carrying(clock.unix(), [2]);

		let admitted = guard.admits(&first, &first_signature);
		let duplicate = guard.admits(&second, &second_signature);
		assert_eq!((admitted, duplicate), (TransitStatus::Ok, TransitStatus::PermissionDenied));
	}
}
