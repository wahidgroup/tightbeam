//! Signed control-plane helpers for one-shot peer advertisement.

use std::sync::Arc;
use std::time::Duration;

use sha3::Sha3_256;
use tightbeam::builder::TypeBuilder;
use tightbeam::colony::cluster::{Cluster, ClusterRequest};
use tightbeam::colony::common::{PeerAdvertisement, PeerAdvertisementResponse};
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::decode;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, Protocol};
use tightbeam::utils::compose as frame_compose;
use tightbeam::utils::urn::Urn;
use tightbeam::{TightBeamError, Version};

use crate::actions::{is_authz_status, AuthzClass};
use crate::events;
use crate::fixtures::ClusterTestCerts;
use crate::topology::OrgNode;

/// Fixed control order base. Paired with a wide freshness window so AFL
/// signatures stay byte-stable across runs.
pub(crate) const CONTROL_ORDER_BASE: u64 = 1_700_000_000_000;

const CLIENT_IO_TIMEOUT: Duration = Duration::from_millis(2000);

/// Sign a cluster control request with a deterministic order.
pub(crate) async fn signed_control_frame(
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
	order: u64,
) -> Result<tightbeam::Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V0)
		.with_id(id)
		.with_order(order)
		.with_message(request)
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

async fn connect_as(
	server_trust: Arc<dyn CertificateTrust>,
	identity: &ClusterTestCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	let key = Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned()));
	let cert = CertificateSpec::Built(Box::new(identity.cert.as_ref().clone()));

	Ok(ClientBuilder::<TokioListener>::builder()
		.with_timeout(CLIENT_IO_TIMEOUT)
		.with_trust_store(server_trust)
		.with_client_identity(cert, key)?
		.build()
		.connect(addr)
		.await?)
}

/// Send one signed advertisement and classify the wire outcome.
///
/// The dial validates the receiver's server certificate with the
/// receiver's own trust. Connect failures classify as
/// [`AuthzClass::InfraFail`], matching the work-path absorption rule.
///
/// The `PEER_AD_OK` / `PEER_AD_DENIED` outcome events stay the caller's
/// responsibility through `record_authz_oracle`, so every advertise path
/// emits them exactly once beside the shadow comparison.
async fn emit_advertise(
	trace: &TraceCollector,
	signer: &OrgNode,
	receiver: &OrgNode,
	gateway_addr: Vec<u8>,
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<AuthzClass, TightBeamError> {
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr, advertised_types: types });
	let frame = signed_control_frame(&signer.certs.key, b"peer-advertise", request, order).await?;
	let server_trust = Arc::clone(&receiver.certs.trust);
	let mut client = match connect_as(server_trust, &signer.certs, receiver.gateway.addr()).await {
		Ok(client) => client,
		Err(_) => return Ok(AuthzClass::InfraFail),
	};

	trace.event(events::PEER_ADVERTISE_SENT)?;

	let Some(response_frame) = client.emit(frame, None).await? else {
		return Ok(AuthzClass::InfraFail);
	};

	let response: PeerAdvertisementResponse = decode(&response_frame.message)?;
	if response.status == TransitStatus::Ok {
		trace.event_with(events::PEER_ROUTES_AFTER, &[], receiver.gateway.peer_servlets().len() as u64)?;
		return Ok(AuthzClass::Success);
	}

	if is_authz_status(response.status) {
		Ok(AuthzClass::AuthzDenied)
	} else {
		Ok(AuthzClass::InfraFail)
	}
}

/// Emit a signed advertisement of `types` from `advertiser` into `receiver`.
pub(crate) async fn advertise_peer_types(
	trace: &TraceCollector,
	advertiser: &OrgNode,
	receiver: &OrgNode,
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<AuthzClass, TightBeamError> {
	let gateway_addr: Vec<u8> = (*advertiser.gateway.addr()).into();
	emit_advertise(trace, advertiser, receiver, gateway_addr, types, order).await
}

/// Advertise a caller-chosen dial address (dead decoy or live peer).
pub(crate) async fn advertise_peer_at(
	trace: &TraceCollector,
	signer: &OrgNode,
	receiver: &OrgNode,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<AuthzClass, TightBeamError> {
	emit_advertise(trace, signer, receiver, gateway_addr.to_vec(), types, order).await
}
