#![cfg(feature = "testing")]

mod cluster;
mod hive;
mod laser;
mod laser_protocol;
mod peer_list;
mod servlet;
mod streaming;
#[cfg(feature = "instrument")]
mod trace;
mod worker;

use std::sync::Arc;

use tightbeam::basis_points::BasisPoints;
use tightbeam::colony::servlet::LatencyTracker;

/// The target latency of a [`tracker_at`] tracker, in microseconds.
const TRACKER_TARGET_US: u64 = 100_000;

/// A real latency tracker whose utilization reads `load`.
///
/// The tracker weighs each sample in full, so its average is its one sample,
/// which takes `load` basis points of the target.
pub fn tracker_at(load: BasisPoints) -> Arc<LatencyTracker> {
	let tracker = LatencyTracker::new(BasisPoints::MAX, TRACKER_TARGET_US);
	let sample_us = u64::from(load.get()) * TRACKER_TARGET_US / u64::from(BasisPoints::MAX.get());
	tracker.record(sample_us);
	Arc::new(tracker)
}
