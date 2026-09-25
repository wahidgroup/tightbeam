//! Properties of the values a gateway parses from a peer.

use proptest::prelude::*;

use tightbeam::colony::cluster::{HopBudget, WireHopBudget};
use tightbeam::constants::DEFAULT_HOP_BUDGET;

proptest! {
	/// A gateway spends at most the smaller of the peer's count and its own
	/// cap, and only the origin sentinel reads as a request no peer relayed.
	#[test]
	fn a_hop_budget_is_the_peer_count_under_the_cap(
		sent in prop_oneof![Just(DEFAULT_HOP_BUDGET), any::<u8>()],
		cap in any::<u8>(),
	) {
		let budget = HopBudget::from_wire(WireHopBudget::new(sent), cap);
		prop_assert_eq!((budget.wire(), budget.is_relayed()), (sent.min(cap), sent != DEFAULT_HOP_BUDGET));
	}
}
