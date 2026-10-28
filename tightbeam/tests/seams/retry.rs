//! An outside crate writes the retry policy of the scaling updates of a hive
//! here: a [`CoreRetryPolicy`] that the hive asks for its attempt limit and
//! for the delay before each retry.
//!
//! The hive runs on a manual clock, which the test moves an hour past the
//! clock of the gateway once the hive registers. The scaling update that the
//! hive then signs falls outside the freshness window of the gateway, so the
//! gateway refuses each attempt, and the hive retries under the outside
//! policy.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "colony"
))]

use core::time::Duration;
use std::sync::{Arc, Mutex, PoisonError};

use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::cluster::Cluster;
use tightbeam::colony::hive::{Hive, HiveTlsConfig, ServletBox};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestMessage;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::policy::CoreRetryPolicy;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::Protocol;
use tightbeam::urn::Urn;
use tightbeam::utils::time::ManualClock;
use tightbeam::utils::BasisPoints;
use tightbeam::{bps, cluster, hive, servlet, TightBeamError};

use super::servlet::{identity_of, seam_cluster_conf, signer_of};
use crate::common::hive::scenario_hive_config;
use crate::common::poll::poll_until;
use crate::common::x509::GatewayCerts;

/// The retries [`AskedRetry`] allows after the first attempt.
const RETRIES: usize = 2;

/// How far the test moves the clock of the hive: past one scaling evaluation
/// of the hive, and past the freshness window of the gateway.
const SKEW: Duration = Duration::from_secs(3600);

/// The polls of the wait for the retries of the hive.
const POLLS: u32 = 100;

/// The interval between two polls.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

servlet! {
	/// The servlet behind the loaded box. It echoes each frame.
	RetryEchoServlet<TestMessage, EnvConfig = ()>,
	protocol: TokioListener,
	handle: raw |frame, _ctx| async move {
		Ok(Some(frame))
	}
}

hive! {
	RetryHive,
	protocol: TokioListener
}

cluster! {
	RetryGateway,
	protocol: TokioListener
}

/// A retry policy an outside crate writes: it allows [`RETRIES`] retries at
/// once, and logs each attempt whose delay a caller asks for.
#[derive(Clone, Default)]
struct AskedRetry(Arc<Mutex<Vec<usize>>>);

impl AskedRetry {
	/// The attempts whose delay a caller asked for, in the order it asked.
	fn asked(&self) -> Vec<usize> {
		self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()
	}
}

impl CoreRetryPolicy for AskedRetry {
	fn max_attempts(&self) -> usize {
		RETRIES
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
		self.0.lock().unwrap_or_else(PoisonError::into_inner).push(attempt);
		0
	}
}

/// A servlet box that reports full load, so the scaling task of its hive adds
/// an instance at its first evaluation. It names a signer, so the hive
/// announces each instance to the gateway.
struct LoadedServlet {
	inner: RetryEchoServlet,
	signer: SignerIdentifier,
}

impl LoadedServlet {
	/// A loaded box over a cleartext echo servlet, whose registration names
	/// `signer`.
	async fn start(trace: Arc<TraceCollector>, signer: SignerIdentifier) -> Result<Self, TightBeamError> {
		let inner = RetryEchoServlet::start(trace, ServletConfig::cleartext()).await?;
		Ok(Self { inner, signer })
	}
}

impl ServletBox for LoadedServlet {
	fn addr_bytes(&self) -> Arc<[u8]> {
		self.inner.addr_bytes()
	}

	fn stop_boxed(self: Box<Self>) {
		Box::new(self.inner).stop_boxed();
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		Some(&self.signer)
	}

	fn utilization(&self) -> Option<BasisPoints> {
		Some(bps!(10000))
	}
}

/// The type URN the loaded servlet registers under.
fn loaded_urn() -> Urn<'static> {
	let urn = ColonyNamespace::default().servlet("loaded-echo");
	urn.expect("test names satisfy the mint grammar")
}

/// A hive on `clock` under the identity of `certs`, which retries its scaling
/// updates under `retry` and registers with the gateway at `gateway`. Its one
/// servlet reports full load.
async fn registered_hive(
	certs: &GatewayCerts,
	gateway: &<TokioListener as Protocol>::Address,
	clock: Arc<ManualClock>,
	retry: AskedRetry,
) -> RetryHive {
	let (spec, provider) = identity_of(certs);
	let hive_tls = HiveTlsConfig::new(spec, provider, PeerAuthentication::Anonymous);
	let hive_tls = hive_tls.expect("the hive certificate decodes");
	let mut conf = scenario_hive_config();
	conf.hive_tls = Some(Arc::new(hive_tls));
	conf.trust_store = Some(Arc::clone(&certs.trust));
	conf.clock = clock;
	conf.control.notify_retry = Arc::new(retry);

	let trace = Arc::new(TraceCollector::new());
	let signer = signer_of(&certs.cert);
	let servlet = LoadedServlet::start(Arc::clone(&trace), signer.clone()).await;
	let servlet = servlet.expect("the loaded servlet starts");
	let mut hive = RetryHive::new(Some(conf)).expect("the hive configuration holds");
	let spawner = move |trace| LoadedServlet::start(trace, signer.clone());
	let registered_servlet = hive.register(loaded_urn(), servlet, spawner);
	registered_servlet.expect("the hive registers its servlet");
	hive.establish(trace).await.expect("the hive establishes");

	let registered = hive.register_with_cluster(gateway).await;
	let registered = registered.expect("the gateway answers the registration");
	assert_eq!(registered.status, TransitStatus::Ok, "the gateway registers the hive");
	hive
}

/// A hive asks an outside retry policy for the delay before each retry of a
/// scaling update that the gateway refuses.
#[tokio::test]
async fn a_hive_retries_a_refused_scaling_update_under_an_outside_policy() -> Result<(), TightBeamError> {
	let certs = GatewayCerts::generate("CN=Retry Gateway");
	let gateway = RetryGateway::start(Arc::new(TraceCollector::new()), seam_cluster_conf(&certs)).await?;
	let clock = Arc::new(ManualClock::default());
	let retry = AskedRetry::default();
	let _hive = registered_hive(&certs, gateway.addr(), Arc::clone(&clock), retry.clone()).await;

	clock.advance(SKEW);
	let asked_each_retry = poll_until(POLLS, POLL_INTERVAL, || retry.asked() == [0, 1]).await;
	assert!(asked_each_retry);
	Ok(())
}
