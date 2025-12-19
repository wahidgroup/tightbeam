//! Payment Gateway Cluster
//!
//! Defines the payment gateway cluster with ACO/ABC bio-inspired routing.

use tightbeam::cluster;
use tightbeam::colony::cluster::ClusterConf;
use tightbeam::transport::tcp::r#async::TokioListener;

// ============================================================================
// Payment Gateway Cluster
// ============================================================================

cluster! {
	pub PaymentGatewayCluster,
	protocol: TokioListener,
	config: ClusterConf::default()
}
