//! Cluster macros: name a gateway type as an alias of [`crate::colony::cluster::ClusterGateway`].
//!
//! Lifecycle, dispatch, heartbeat, and gossip live in
//! [`crate::colony::cluster::runtime`].

/// Create a cluster gateway type for a protocol (and optional digest and
/// edge protocol).
///
/// The runtime configuration is supplied to `Cluster::start`, not to the
/// macro. `edge` declares the protocol of the optional edge accept plane
/// for external clients. The plane binds only when
/// `ClusterConfig::edge_bind_addr` is set, and it admits `Work` frames
/// only. Without `edge`, the edge protocol defaults to the colony protocol.
///
/// # Syntax
///
/// ```ignore
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener
/// }
///
/// // With custom digest:
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     digest: Blake3
/// }
///
/// // With an edge accept plane for external clients:
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     edge: WsListener
/// }
/// ```
#[macro_export]
macro_rules! cluster {
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path,
		digest: $digest:path
	) => {
		$(#[$meta])*
		pub type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $digest, $edge>;
	};

	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path
	) => {
		$(#[$meta])*
		pub type $cluster_name =
			$crate::colony::cluster::ClusterGateway<$protocol, $crate::crypto::hash::Sha3_256, $edge>;
	};

	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path
	) => {
		$(#[$meta])*
		pub type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $digest>;
	};

	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		pub type $cluster_name =
			$crate::colony::cluster::ClusterGateway<$protocol, $crate::crypto::hash::Sha3_256>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path,
		digest: $digest:path
	) => {
		$(#[$meta])*
		type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $digest, $edge>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path
	) => {
		$(#[$meta])*
		type $cluster_name =
			$crate::colony::cluster::ClusterGateway<$protocol, $crate::crypto::hash::Sha3_256, $edge>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path
	) => {
		$(#[$meta])*
		type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $digest>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		type $cluster_name =
			$crate::colony::cluster::ClusterGateway<$protocol, $crate::crypto::hash::Sha3_256>;
	};
}
