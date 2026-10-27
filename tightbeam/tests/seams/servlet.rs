//! An outside crate registers a servlet here through a [`ServletBox`] of its
//! own, which names the signer the servlet answers under.
//!
//! A hive carries that signer in its registration, and the gateway's dial of
//! the servlet admits only the certificate it names (CWE-346).

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "colony"
))]

use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{Certificate, CertificateSpec};
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::{ClusterEnv, SetupEnv, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, Protocol};
use tightbeam::urn::Urn;
use tightbeam::{cluster, decode, exactly, hive, servlet, tb_assert_spec, tb_scenario, Frame, TightBeamError, Version};

use crate::common::security::{random_signing_key, test_certificate};
use crate::common::x509::GatewayCerts;

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

/// A [`ServletBox`] an outside crate writes: it holds a live servlet, and
/// its registration names `signer` as the identity that servlet answers
/// under.
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

/// The signer that names `certificate` (RFC 5652 §5.3).
pub(super) fn signer_of(certificate: &Certificate) -> SignerIdentifier {
	certificate.signer_identifier().expect("a fixture certificate names its key")
}

/// The type URN the outside servlet registers under.
fn echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("outside-echo")
		.expect("test names satisfy the mint grammar")
}

/// The certificate and key of `certs`, as a specification and a provider.
pub(super) fn identity_of(certs: &GatewayCerts) -> (CertificateSpec, Arc<Secp256k1KeyProvider>) {
	let spec = CertificateSpec::Built(Box::new(certs.cert.to_owned()));
	let provider = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));

	(spec, provider)
}

/// A gateway under `certs`, whose hive trust holds the same identity.
pub(super) fn seam_cluster_conf(certs: &GatewayCerts) -> ClusterConfig {
	let (spec, provider) = identity_of(certs);
	let tls = ClusterTlsConfig::new(spec, provider).expect("the seam certificate decodes");

	ClusterConfig::new(tls.with_hive_trust(Some(Arc::clone(&certs.trust))))
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
	let hive_tls = HiveTlsConfig::new(spec, provider, vec![])?;
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

			let content: TestMessage = decode(echoed.message())?;
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
