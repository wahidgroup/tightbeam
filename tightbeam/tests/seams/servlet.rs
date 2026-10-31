//! An outside crate registers a servlet here through a [`ServletBox`] of its
//! own, which names the signer the servlet answers under.
//!
//! A hive carries that signer in its registration, and the gateway's dial of
//! the servlet admits only the certificate it names (CWE-346).
//!
//! An outside crate also writes the [`UtilizationGauge`] of a `servlet!`
//! servlet here, which the hive reads when it scales the servlet.
//!
//! An outside [`ServletBox`] that keeps the default drain stops at the drain
//! of its hive.

#![cfg(feature = "colony")]

use core::sync::atomic::Ordering;
use core::time::Duration;
use std::sync::Arc;

use tightbeam::basis_points::BasisPoints;
use tightbeam::builder::TypeBuilder;
use tightbeam::clock::Clock;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::cluster::ClusterConfig;
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox};
use tightbeam::colony::servlet::{ServletConfig, UtilizationGauge};
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::{ClusterEnv, SetupEnv, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, Protocol};
use tightbeam::urn::Urn;
use tightbeam::{cluster, exactly, hive, servlet, tb_assert_spec, tb_scenario, Frame, TightBeamError, Version};

use super::StopProbe;
use crate::common::clock::ParkingClock;
use crate::common::hive::servlet_urn;
use crate::common::result::TestResult;
use crate::common::security::{random_signing_key, test_certificate};
use crate::common::x509::{signer_of, GatewayCerts};

const OUTSIDE_SERVLET_RAN: Urn<'static> = tightbeam::urn!("test", "event:seams/outside-servlet-ran");

/// The content the client's work frame carries and the servlet echoes.
const OUTSIDE_CONTENT: &str = "routed to an outside box";

servlet! {
	/// The servlet behind the outside box. It records each frame it runs and
	/// echoes the frame.
	SeamEchoServlet<TestMessage, EnvConfig = ()>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		ctx.trace().event(OUTSIDE_SERVLET_RAN)?;
		Ok(Some(frame))
	}
}

hive! {
	SeamHive,
	protocol: TokioListener
}

cluster! {
	SeamCluster,
	protocol: TokioListener
}

/// A [`ServletBox`] an outside crate writes: it holds a live servlet, and its
/// registration names `signer` as the identity that servlet answers under.
struct OutsideServlet {
	inner: SeamEchoServlet,
	signer: SignerIdentifier,
}

impl ServletBox for OutsideServlet {
	fn addr_bytes(&self) -> Arc<[u8]> {
		self.inner.addr_bytes()
	}

	fn stop_boxed(self: Box<Self>) {
		Box::new(self.inner).stop_boxed();
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		Some(&self.signer)
	}
}

/// The type URN the outside servlet registers under.
fn echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("outside-echo")
		.expect("test names satisfy the mint grammar")
}

/// The certificate and key of `certs`, as a specification and a provider.
fn identity_of(certs: &GatewayCerts) -> (CertificateSpec, Arc<Secp256k1KeyProvider>) {
	let spec = CertificateSpec::Built(Box::new(certs.cert.to_owned()));
	let provider = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));
	(spec, provider)
}

/// A gateway under `certs`, whose hive trust holds the same identity.
fn seam_cluster_conf(certs: &GatewayCerts) -> ClusterConfig {
	ClusterConfig::new(certs.cluster_tls())
}

/// Starts an established hive under `certs` that registers one
/// [`OutsideServlet`] whose registration names `named`.
async fn start_outside_hive(
	trace: TraceCollector,
	certs: Arc<GatewayCerts>,
	named: SignerIdentifier,
) -> Result<SeamHive, TightBeamError> {
	let (spec, provider) = identity_of(&certs);
	let servlet_conf = ServletConfig::<TokioListener, TestMessage>::builder()
		.with_certificate(spec, provider, vec![])?
		.with_config(Arc::new(()))
		.build();

	let inner = SeamEchoServlet::start(Arc::new(trace.share()), servlet_conf).await?;
	let servlet = OutsideServlet { inner, signer: named.clone() };

	let (spec, provider) = identity_of(&certs);
	let hive_tls = HiveTlsConfig::new(spec, provider, PeerAuthentication::Anonymous)?;
	let trust_store = Some(Arc::clone(&certs.trust));
	let conf = HiveConfig { hive_tls: Some(Arc::new(hive_tls)), trust_store, ..Default::default() };

	let mut hive = SeamHive::new(Some(conf))?;
	hive.register(echo_urn(), servlet, move |t| {
		let named = named.clone();
		async move {
			let inner = SeamEchoServlet::start(t, ServletConfig::cleartext()).await?;
			Ok(OutsideServlet { inner, signer: named })
		}
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Starts a hive whose outside box names the signer of `certs`, the identity
/// its servlet answers under.
async fn start_hive_naming_its_signer(
	trace: TraceCollector,
	certs: Arc<GatewayCerts>,
) -> Result<SeamHive, TightBeamError> {
	let named = signer_of(&certs.cert);
	start_outside_hive(trace, certs, named).await
}

/// Starts a hive whose outside box names the signer of a stranger, an
/// identity other than the one its servlet answers under.
async fn start_hive_naming_a_stranger(
	trace: TraceCollector,
	certs: Arc<GatewayCerts>,
) -> Result<SeamHive, TightBeamError> {
	let stranger = test_certificate(&random_signing_key());
	let named = signer_of(&stranger);
	start_outside_hive(trace, certs, named).await
}

/// Submits one echo request for [`echo_urn`] to the gateway at `addr`.
async fn submit_echo(
	certs: &GatewayCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<Frame, TightBeamError> {
	let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::clone(&certs.trust));
	let mut client = builder.build().connect(addr.to_owned()).await?;
	let message = TestMessage { content: OUTSIDE_CONTENT.into() };
	let request = Version::V0.compose().with_id(b"outside-work").with_message(message).build()?;

	client.submit_work_to(echo_urn(), &request).await
}

tb_assert_spec! {
	pub OutsideServletRoutedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(OUTSIDE_SERVLET_RAN, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// The gateway routes to an outside box that names the signer its servlet
// answers under, and the gateway's dial admits that servlet's certificate.
tb_scenario! {
	name: an_outside_servlet_box_that_names_its_signer_is_routed,
	spec: OutsideServletRoutedSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Seam Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			SeamCluster::start(Arc::new(trace.share()), seam_cluster_conf(&certs)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_hive_naming_its_signer(trace, certs)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let echoed = submit_echo(&certs, cluster.addr()).await?;

			let content: TestMessage = echoed.decode_message()?;
			assert_eq!(content.content, OUTSIDE_CONTENT, "the routed work echoes");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideServletRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(OUTSIDE_SERVLET_RAN, exactly!(0)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1)),
			(events::CLUSTER_WORK_FAILED, exactly!(1))
		]
	}
}

// The gateway's dial refuses an outside box whose registration names a signer
// other than the one its servlet answers under, before the frame leaves, and
// the client hears that no instance is available.
tb_scenario! {
	name: an_outside_servlet_box_that_names_another_signer_is_refused,
	spec: OutsideServletRefusedSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Seam Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			SeamCluster::start(Arc::new(trace.share()), seam_cluster_conf(&certs)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_hive_naming_a_stranger(trace, certs)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let refused = submit_echo(&certs, cluster.addr()).await;

			let unavailable = matches!(refused, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable)));
			assert!(unavailable, "the client hears that no instance was available");

			cluster.stop();
			Ok(())
		}
	}
}

/// The scaling cadence of the gauged hive, on its manual clock.
const SCALING_PERIOD: Duration = Duration::from_secs(5);

/// A gauge that an outside crate writes: it reads full load, so the hive
/// scales up the servlet that holds it.
struct FullLoad;

impl UtilizationGauge for FullLoad {
	fn utilization(&self) -> BasisPoints {
		BasisPoints::MAX
	}
}

/// Starts a hive on `clock` with no control plane, whose one `servlet!`
/// servlet holds the outside [`FullLoad`] gauge behind the erased handle.
async fn start_gauged_hive(clock: Arc<dyn Clock>) -> SeamHive {
	let gauge: Arc<dyn UtilizationGauge> = Arc::new(FullLoad);
	let builder = ServletConfig::<TokioListener, TestMessage>::builder().with_utilization(gauge);
	let servlet_conf = builder.allow_cleartext().build();
	let servlet = SeamEchoServlet::start(Arc::new(TraceCollector::new()), servlet_conf).await;
	let servlet = servlet.expect("the gauged servlet starts");

	let mut conf = HiveConfig { clock, ..Default::default() };
	conf.scaling.cooldown = SCALING_PERIOD;

	let mut hive = SeamHive::new(Some(conf)).expect("the hive configuration holds");
	let spawner = |t| SeamEchoServlet::start(t, ServletConfig::cleartext());
	let registered = hive.register(servlet_urn("gauged-echo"), servlet, spawner);
	registered.expect("the hive registers its servlet");

	let established = hive.establish(Arc::new(TraceCollector::new())).await;
	established.expect("the hive establishes");

	hive
}

/// A hive scales up the `servlet!` servlet whose outside gauge reads full
/// load, at the first scaling evaluation that its clock passes.
#[tokio::test]
async fn a_hive_scales_up_a_servlet_on_its_outside_gauge() {
	let clock = Arc::new(ParkingClock::default());
	let hive = start_gauged_hive(Arc::clone(&clock) as Arc<dyn Clock>).await;

	clock.parked(SCALING_PERIOD).await;
	clock.advance(SCALING_PERIOD);
	clock.parked(SCALING_PERIOD).await;

	let addresses = hive.servlet_addresses();

	hive.stop();

	assert_eq!(addresses.len(), 2);
}

/// A hive's drain stops an outside servlet that keeps the default drain, so
/// a servlet with no drain of its own still ends at the drain of its hive.
#[tokio::test]
async fn a_hive_drain_stops_an_outside_servlet_that_keeps_the_default_drain() -> TestResult {
	let (servlet, stopped) = StopProbe::new();

	// The hive scales nothing, so it calls no spawner, and the flag of the
	// probe that the spawner would start drops with it.
	let spawner = |_| async { Ok(StopProbe::new().0) };
	let mut hive = SeamHive::new(None)?;
	hive.register(servlet_urn("stop-marking"), servlet, spawner)?;
	hive.establish(Arc::new(TraceCollector::new())).await?;
	hive.drain().await?;

	assert!(stopped.load(Ordering::SeqCst));
	Ok(())
}
