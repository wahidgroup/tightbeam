//! Payment Processor Hives
//!
//! Defines hives that host payment processing servlets.

use tightbeam::colony::servlet::Servlet;
use tightbeam::hive;
use tightbeam::transport::tcp::r#async::TokioListener;

use super::messages::{CaptureTransaction, CreditTransferTransaction};
use super::servlets::{AuthorizationServlet, CaptureServlet, KeyManagerRequest, KeyManagerServlet};

// ============================================================================
// Payment Processor Hive
// ============================================================================

hive! {
	pub PaymentProcessorHive,
	protocol: TokioListener,
	servlets: {
		keymanager: KeyManagerServlet<KeyManagerRequest>,
		authorize: AuthorizationServlet<CreditTransferTransaction>,
		capture: CaptureServlet<CaptureTransaction>
	}
}
