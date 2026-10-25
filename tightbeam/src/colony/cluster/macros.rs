//! The cluster macro, which names a gateway type as an alias of
//! [`crate::colony::cluster::ClusterGateway`].

/// Declares a cluster gateway type for a protocol and an optional edge
/// protocol.
///
/// The caller passes the runtime configuration to [`Cluster::start`], not to
/// the macro.
///
/// - `edge` declares the protocol of the optional edge accept plane for external clients.
/// - The plane binds only when [`ClusterConfig::edge_bind_addr`] is set, and it admits `Work` frames only.
/// - Without `edge`, the edge protocol defaults to the colony protocol.
///
/// # Syntax
///
/// ```
/// use tightbeam::cluster;
/// use tightbeam::transport::tcp::r#async::TokioListener;
///
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener
/// }
///
/// // With an edge accept plane for external clients:
/// cluster! {
///     pub MyEdgeCluster,
///     protocol: TokioListener,
///     edge: TokioListener
/// }
/// ```
///
/// [`Cluster::start`]: crate::colony::cluster::Cluster::start
/// [`ClusterConfig::edge_bind_addr`]: crate::colony::cluster::ClusterConfig::edge_bind_addr
#[macro_export]
macro_rules! cluster {
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path
	) => {
		$(#[$meta])*
		pub type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $edge>;
	};

	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		pub type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		edge: $edge:path
	) => {
		$(#[$meta])*
		type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol, $edge>;
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		type $cluster_name = $crate::colony::cluster::ClusterGateway<$protocol>;
	};
}
