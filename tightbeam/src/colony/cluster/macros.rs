//! Cluster macros: name a gateway type as an alias of [`ClusterGateway`].
//!
//! Lifecycle, dispatch, heartbeat, and gossip live in
//! [`crate::colony::cluster::runtime`].

/// Create a cluster gateway type for a protocol (and optional digest).
///
/// The runtime configuration is supplied to `Cluster::start`, not to the macro.
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
/// ```
#[macro_export]
macro_rules! cluster {
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
