//! An outside crate writes the retry policy of the scaling updates of a hive
//! here: a [`CoreRetryPolicy`] that the hive asks for its attempt limit and
//! for the delay before each retry.
//!
//! The hive signs its scaling updates on a manual clock an hour past the clock
//! of the gateway, so the gateway refuses each attempt, and the hive retries
//! under the outside policy. The refusal of the slate that the hive announces
//! next marks the end of the attempts.

#![cfg(feature = "colony")]

use core::time::Duration;
use std::sync::Arc;

use tokio::sync::watch;

use tightbeam::basis_points::BasisPoints;
use tightbeam::clock::Clock;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::cluster::{Cluster, ClusterConfig};
use tightbeam::colony::hive::{Hive, ServletBox};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestMessage;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::CoreRetryPolicy;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::Protocol;
use tightbeam::{bps, cluster, hive, servlet, TightBeamError};

use crate::common::clock::ParkingClock;
use crate::common::hive::{anonymous_hive_tls, scenario_hive_config, servlet_urn};
use crate::common::poll::{poll_until, within_hang_guard};
use crate::common::result::TestResult;
use crate::common::x509::{signer_of, GatewayCerts};

/// The retries [`AskedRetry`] allows after the first attempt.
const RETRIES: usize = 2;

/// The scaling cadence of the hive, on its manual clock.
const SCALING_PERIOD: Duration = Duration::from_secs(5);

/// How far the test moves the clock of the hive: past one scaling evaluation
/// of the hive, and past the freshness window of the gateway.
const SKEW: Duration = Duration::from_secs(3600);

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
struct AskedRetry(Arc<watch::Sender<Vec<usize>>>);

impl AskedRetry {
	/// The attempts whose delay a caller asked for, in the order it asked,
	/// once it asked for `count` of them.
	///
	/// The wait panics when a caller asks for fewer within [`HANG_GUARD`].
	///
	/// [`HANG_GUARD`]: crate::common::poll::HANG_GUARD
	async fn asked(&self, count: usize) -> Vec<usize> {
		let mut asks = self.0.subscribe();
		let heard = asks.wait_for(|asked| asked.len() >= count);
		let asked = within_hang_guard(heard, "the hive asks within the hang guard").await;
		let asked = asked.expect("the policy holds the sender of its asks");
		asked.to_vec()
	}
}

impl CoreRetryPolicy for AskedRetry {
	fn max_attempts(&self) -> usize {
		RETRIES
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
		self.0.send_modify(|asked| asked.push(attempt));
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

/// A hive on `clock` under the identity of `certs`, which scales every
/// [`SCALING_PERIOD`], retries its scaling updates under `retry`, and
/// registers with the gateway at `gateway`. Its one servlet reports full load.
async fn registered_hive(
	certs: &GatewayCerts,
	gateway: &<TokioListener as Protocol>::Address,
	clock: Arc<dyn Clock>,
	retry: AskedRetry,
) -> RetryHive {
	let hive_tls = anonymous_hive_tls(certs.identity());
	let mut conf = scenario_hive_config();
	conf.hive_tls = Some(Arc::new(hive_tls));
	conf.trust_store = Some(Arc::clone(&certs.trust));
	conf.clock = clock;
	conf.scaling.cooldown = SCALING_PERIOD;
	conf.control.notify_retry = Arc::new(retry);

	let trace = Arc::new(TraceCollector::new());
	let signer = signer_of(&certs.cert);
	let servlet = LoadedServlet::start(Arc::clone(&trace), signer.clone()).await;
	let servlet = servlet.expect("the loaded servlet starts");
	let mut hive = RetryHive::new(Some(conf)).expect("the hive configuration holds");
	let spawner = move |trace| LoadedServlet::start(trace, signer.clone());
	let registered_servlet = hive.register(servlet_urn("loaded-echo"), servlet, spawner);

	registered_servlet.expect("the hive registers its servlet");
	hive.establish(trace).await.expect("the hive establishes");

	let registered = hive.register_with_cluster(gateway).await;
	let registered = registered.expect("the gateway answers the registration");
	assert_eq!(registered.status, TransitStatus::Ok);
	hive
}

/// A hive asks an outside retry policy for the delay before each retry of a
/// scaling update that the gateway refuses, and the gateway refuses the update
/// once for the first attempt and once for each retry that the policy allows.
#[tokio::test]
async fn a_hive_retries_a_refused_scaling_update_under_an_outside_policy() -> TestResult {
	let certs = GatewayCerts::generate("CN=Retry Gateway");
	let trace = Arc::new(TraceCollector::new());
	let gateway = RetryGateway::start(Arc::clone(&trace), ClusterConfig::new(certs.cluster_tls())).await?;
	let clock = Arc::new(ParkingClock::default());
	let retry = AskedRetry::default();
	let _hive = registered_hive(&certs, gateway.addr(), Arc::clone(&clock) as Arc<dyn Clock>, retry.clone()).await;

	clock.parked(SCALING_PERIOD).await;
	clock.advance(SKEW);

	let asked = retry.asked(RETRIES).await;
	assert_eq!(asked, [0, 1]);

	let announced = || trace.recorded(events::CLUSTER_REGISTER_REFUSED) > 0;
	let gave_up = poll_until(50, Duration::from_millis(20), announced).await;
	let refused = trace.recorded(events::CLUSTER_UPDATE_REFUSED);
	assert_eq!((gave_up, refused), (true, RETRIES + 1));
	Ok(())
}
