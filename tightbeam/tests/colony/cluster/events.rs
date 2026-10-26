//! The event markers that the test doubles of the cluster scenarios record.
//!
//! A scenario asserts a gateway decision through the production events of
//! `tightbeam::instrumentation::events`, and a value that it reads on its own
//! task with an `assert!`. A marker here records a fact that a test double
//! observes on a task of its own, where the verdict of the scenario reads the
//! trace:
//!
//! - A servlet that a frame or a stream reached.
//! - A field of a frame that a probe servlet read.
//! - A slate that the gateway offered a balancer.
//! - A servlet that its hive stopped.
//!
//! Each marker records an observation of a test double, in the `test`
//! namespace, under the name of what it records.

use tightbeam::urn::Urn;

/// The probe servlet of the teardown scenario records it when its hive stops
/// it.
pub(crate) const SERVLET_STOPPED: Urn<'static> = tightbeam::urn!("test", "event:cluster/servlet-stopped");
/// The recording balancer records it for each slate that the gateway offers
/// it, with the width of the slate as its value.
pub(crate) const BALANCER_OFFERED: Urn<'static> = tightbeam::urn!("test", "event:cluster/balancer-offered");
/// The stream servlet records it when a routed stream reaches its handler.
pub(crate) const STREAM_SERVLET_HANDLED: Urn<'static> = tightbeam::urn!("test", "event:cluster/stream-servlet-handled");
/// The stream servlet records it when a routed duplex stream reaches its
/// handler.
pub(crate) const DUPLEX_SERVLET_HANDLED: Urn<'static> = tightbeam::urn!("test", "event:cluster/duplex-servlet-handled");
/// The first instance of a two-instance type records it when a frame reaches
/// its handler.
pub(crate) const FIRST_INSTANCE_RECEIVED: Urn<'static> =
	tightbeam::urn!("test", "event:cluster/first-instance-received");
/// The draining sibling records it when a frame reaches its handler.
pub(crate) const SIBLING_RECEIVED: Urn<'static> = tightbeam::urn!("test", "event:cluster/sibling-received");
/// The probe servlet records whether the frame it received carries the id of
/// the client, as `1` or `0`.
pub(crate) const PROBE_FRAME_CLIENT_ID: Urn<'static> = tightbeam::urn!("test", "event:cluster/probe-frame-client-id");
/// The probe servlet records whether the frame it received carries a
/// signature, as `1` or `0`.
pub(crate) const PROBE_FRAME_SIGNED: Urn<'static> = tightbeam::urn!("test", "event:cluster/probe-frame-signed");
/// The probe servlet records whether the frame it received names a previous
/// frame, as `1` or `0`.
pub(crate) const PROBE_FRAME_PREVIOUS: Urn<'static> = tightbeam::urn!("test", "event:cluster/probe-frame-previous");
/// The probe servlet records whether the signature of the client verifies
/// over the bytes it received, as `1` or `0`.
pub(crate) const PROBE_FRAME_SIG_VALID: Urn<'static> = tightbeam::urn!("test", "event:cluster/probe-frame-sig-valid");
/// The gossip ingress servlet records whether the key of the origin gateway
/// signed the rumor frame it received.
pub(crate) const GOSSIP_INGRESS_SIGNED_BY_GATEWAY: Urn<'static> =
	tightbeam::urn!("test", "event:cluster/gossip-ingress-signed-by-gateway");
