//! Payment Processor Hives
//!
//! Defines hives that host payment processing servlets.

use tightbeam::hive;
use tightbeam::transport::tcp::r#async::TokioListener;

// ============================================================================
// Payment Processor Hive
// ============================================================================

hive! {
	pub PaymentProcessorHive,
	protocol: TokioListener
}
