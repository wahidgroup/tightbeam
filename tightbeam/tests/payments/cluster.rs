//! Payment Gateway Cluster
//!
//! Defines the payment gateway cluster.

use tightbeam::cluster;
use tightbeam::transport::tcp::r#async::TokioListener;

// ============================================================================
// Payment Gateway Cluster
// ============================================================================

cluster! {
	pub PaymentGatewayCluster,
	protocol: TokioListener
}
