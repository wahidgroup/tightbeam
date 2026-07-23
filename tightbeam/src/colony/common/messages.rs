//! Protocol messages for cluster-hive communication
//!
//! All message types used in the cluster ↔ hive protocol.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::{Choice, Enumerated, Sequence};
use crate::policy::TransitStatus;
use crate::utils::BasisPoints;
use crate::Beamable;

// =============================================================================
// Cluster Inbound Protocol
// =============================================================================

/// Work request envelope for cluster routing
///
/// Clients send this to the cluster gateway. The cluster routes based on
/// `servlet_type` and forwards `payload` to the selected hive.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// Target servlet type (e.g., b"ping_servlet")
	pub servlet_type: Vec<u8>,
	/// Raw message payload (encoded inner message)
	pub payload: Vec<u8>,
}

/// Work response from cluster
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterWorkResponse {
	/// Status of the routing/execution
	pub status: TransitStatus,
	/// Response payload from servlet (if successful)
	pub payload: Option<Vec<u8>>,
}

impl ClusterWorkResponse {
	/// Create a successful response with payload
	#[inline]
	pub fn ok(payload: Vec<u8>) -> Self {
		Self { status: TransitStatus::Ok, payload: Some(payload) }
	}

	/// Create an error response with status
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, payload: None }
	}
}

/// Inbound message envelope for the cluster gateway - ASN.1 CHOICE.
///
/// Every frame sent to a cluster carries exactly one of these variants.
/// The context-specific tag discriminates the type on the wire, so the
/// gateway decodes once and matches.
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum ClusterRequest {
	/// Hive announcing its servlets [context 0]
	#[asn1(context_specific = "0", constructed = "true")]
	RegisterHive(RegisterHiveRequest),
	/// Hive scaling notification [context 1]
	#[asn1(context_specific = "1", constructed = "true")]
	ServletAddressUpdate(ServletAddressUpdate),
	/// Client work submission [context 2]
	#[asn1(context_specific = "2", constructed = "true")]
	Work(ClusterWorkRequest),
}

// =============================================================================
// Hive Registration Messages
// =============================================================================

/// Message type for registering a hive with a cluster
///
/// This message is sent from a hive to a cluster controller to announce
/// its availability and capabilities, including actual servlet addresses.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterHiveRequest {
	/// Issue time in unix milliseconds. Binds the signed frame to a
	/// freshness window so captured registrations cannot be replayed (CWE-294)
	pub issued_at_ms: u64,
	/// The address where this hive can be reached (for heartbeats)
	pub hive_addr: Vec<u8>,
	/// Servlet type-to-address mappings for direct routing
	pub servlet_addresses: Vec<ServletInfo>,
	/// Optional metadata about the hive
	pub metadata: Option<Vec<u8>>,
}

/// Response message for hive registration
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterHiveResponse {
	/// The status of the registration request
	pub status: TransitStatus,
	/// Optional cluster-assigned hive ID
	pub hive_id: Option<Vec<u8>>,
}

/// Notification from hive to cluster about servlet address changes
///
/// Sent by hives when auto-scaling spawns or stops servlet instances.
/// Enables push-based cluster registry updates.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdate {
	/// Issue time in unix milliseconds. Binds the signed frame to a
	/// freshness window so captured updates cannot be replayed (CWE-294)
	pub issued_at_ms: u64,
	/// Hive identifier (matches hive_addr from registration)
	pub hive_id: Vec<u8>,
	/// Newly spawned servlet addresses
	pub added: Vec<ServletInfo>,
	/// Removed servlet network addresses.
	pub removed: Vec<Vec<u8>>,
}

/// Response to servlet address update notification
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdateResponse {
	/// Status of the update (Ok = success)
	pub status: TransitStatus,
}

// =============================================================================
// Servlet Activation Messages
// =============================================================================

/// Message type for activating a servlet on a hive
///
/// This message is sent from a cluster controller to a hive to instruct
/// it to morph into a specific servlet configuration.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletRequest {
	/// The identifier of the servlet to activate
	pub servlet_id: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Response message for servlet activation
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The status of the activation request
	pub status: TransitStatus,
	/// The address of the activated servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
}

impl ActivateServletResponse {
	/// Create a successful activation response
	#[inline]
	pub fn ok(address: Vec<u8>) -> Self {
		Self { status: TransitStatus::Ok, servlet_address: Some(address) }
	}

	/// Create a failed activation response
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, servlet_address: None }
	}
}

// =============================================================================
// Servlet Info
// =============================================================================

/// Servlet information entry
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletInfo {
	/// The servlet instance ID
	pub servlet_id: Vec<u8>,
	/// The servlet's address
	pub address: Vec<u8>,
}

// =============================================================================
// Hive Management Messages
// =============================================================================

/// Hive management request message
///
/// Uses context-specific tags to distinguish between different request types.
/// Only one field should be set per request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementRequest {
	/// Spawn a new servlet instance [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletParams>,
	/// List all active servlets [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsParams>,
	/// Stop a specific servlet instance [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

/// Parameters for spawning a new servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// The type of servlet to spawn (e.g., "worker_servlet")
	pub servlet_type: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Parameters for listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsParams {
	/// Optional filter (reserved for future use)
	pub filter: Option<Vec<u8>>,
}

/// Parameters for stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// The ID of the servlet instance to stop
	pub servlet_id: Vec<u8>,
}

/// Hive management response message
///
/// Uses context-specific tags to distinguish between different response types.
/// Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementResponse {
	/// Response to spawn request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletResult>,
	/// Response to list request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsResult>,
	/// Response to stop request [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletResult>,
}

/// Result of spawning a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletResult {
	/// The status of the spawn request
	pub status: TransitStatus,
	/// The address of the newly spawned servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
	/// The identifier of the servlet instance (e.g., "worker_servlet_127.0.0.1:8080")
	pub servlet_id: Option<Vec<u8>>,
}

/// Result of listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request
	pub status: TransitStatus,
	/// List of active servlets
	pub servlets: Vec<ServletInfo>,
}

/// Result of stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request
	pub status: TransitStatus,
}

impl HiveManagementResponse {
	/// Create a spawn success response
	#[inline]
	pub fn spawn_ok(address: Vec<u8>, servlet_id: Vec<u8>) -> Self {
		Self {
			spawn: Some(SpawnServletResult {
				status: TransitStatus::Ok,
				servlet_address: Some(address),
				servlet_id: Some(servlet_id),
			}),
			list: None,
			stop: None,
		}
	}

	/// Create a spawn failure response
	#[inline]
	pub fn spawn_err(status: TransitStatus) -> Self {
		Self {
			spawn: Some(SpawnServletResult { status, servlet_address: None, servlet_id: None }),
			list: None,
			stop: None,
		}
	}

	/// Create a list response
	#[inline]
	pub fn list_ok(servlets: Vec<ServletInfo>) -> Self {
		Self {
			spawn: None,
			list: Some(ListServletsResult { status: TransitStatus::Ok, servlets }),
			stop: None,
		}
	}

	/// Create a stop success response
	#[inline]
	pub fn stop_ok() -> Self {
		Self {
			spawn: None,
			list: None,
			stop: Some(StopServletResult { status: TransitStatus::Ok }),
		}
	}

	/// Create a stop failure response
	#[inline]
	pub fn stop_err(status: TransitStatus) -> Self {
		Self { spawn: None, list: None, stop: Some(StopServletResult { status }) }
	}
}

// =============================================================================
// Cluster Command Protocol
// =============================================================================

/// Status reported by cluster in heartbeat
///
/// Clusters report their current operational status to hives during heartbeat.
/// Hives may use this to adjust their behavior (e.g., reduce capacity during draining).
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClusterStatus {
	/// Normal operation
	#[default]
	Healthy = 0,
	/// Partial degradation (some services unavailable)
	Degraded = 1,
	/// Overloaded (high utilization)
	Overloaded = 2,
	/// Draining (preparing for shutdown)
	Draining = 3,
}

/// Cluster command message - ASN.1 CHOICE
///
/// Commands from cluster to hive. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per message.
///
/// **Security**: Requires nonrepudiation signature and frame integrity.
/// Frames without proper authentication will be rejected and may trigger
/// the circuit breaker. `issued_at_ms` binds the signature to a point in
/// time: hives reject commands outside their freshness window and replays
/// of already-seen signatures within it (CWE-294).
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
#[beam(frame_integrity)]
pub struct ClusterCommand {
	/// Issue time in milliseconds since UNIX epoch (freshness binding)
	pub issued_at_ms: u64,

	/// Heartbeat request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatParams>,

	/// Hive management request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementRequest>,
}

/// Heartbeat parameters
///
/// Minimal payload - identity is established via certificate in the
/// frame's nonrepudiation signature.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatParams {
	/// Cluster's current operational status
	pub cluster_status: ClusterStatus,
}

/// Cluster command response - ASN.1 CHOICE
///
/// Responses from hive to cluster. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterCommandResponse {
	/// Heartbeat response [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatResult>,

	/// Management response [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementResponse>,
}

/// Heartbeat response with hive health status
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatResult {
	/// Overall status (Ok = healthy, ResourceExhausted = at capacity)
	pub status: TransitStatus,
	/// Current aggregate utilization across all servlets
	pub utilization: BasisPoints,
	/// Number of active servlet instances
	pub active_servlets: u32,
}

// =============================================================================
// Response Builder Helpers
// =============================================================================

impl ClusterCommandResponse {
	/// Create a heartbeat response
	#[inline]
	pub fn heartbeat(status: TransitStatus, utilization: BasisPoints, active_servlets: u32) -> Self {
		Self {
			heartbeat: Some(HeartbeatResult { status, utilization, active_servlets }),
			manage: None,
		}
	}

	/// Create a management response wrapper
	#[inline]
	pub fn manage(response: HiveManagementResponse) -> Self {
		Self { heartbeat: None, manage: Some(response) }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::error::Result;

	fn round_trip(original: ClusterRequest) -> Result<()> {
		let encoded = crate::encode(&original)?;
		let decoded: ClusterRequest = crate::decode(&encoded)?;
		assert_eq!(original, decoded);
		Ok(())
	}

	#[test]
	fn cluster_request_register_hive_round_trips() -> Result<()> {
		round_trip(ClusterRequest::RegisterHive(RegisterHiveRequest {
			issued_at_ms: 1_000,
			hive_addr: b"127.0.0.1:9000".to_vec(),
			servlet_addresses: vec![ServletInfo { servlet_id: b"ping".to_vec(), address: b"127.0.0.1:9001".to_vec() }],
			metadata: None,
		}))
	}

	#[test]
	fn cluster_request_servlet_address_update_round_trips() -> Result<()> {
		round_trip(ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
			issued_at_ms: 1_000,
			hive_id: b"127.0.0.1:9000".to_vec(),
			added: vec![],
			removed: vec![b"127.0.0.1:9100".to_vec()],
		}))
	}

	#[test]
	fn cluster_request_work_round_trips() -> Result<()> {
		round_trip(ClusterRequest::Work(ClusterWorkRequest {
			servlet_type: b"ping".to_vec(),
			payload: vec![0x02, 0x01, 0x2A],
		}))
	}

	#[test]
	fn bare_inner_type_rejected_without_envelope_tag() -> Result<()> {
		let bare = crate::encode(&ClusterWorkRequest { servlet_type: b"ping".to_vec(), payload: vec![] })?;

		let decoded = crate::decode::<ClusterRequest>(&bare);
		assert!(decoded.is_err());
		Ok(())
	}
}
