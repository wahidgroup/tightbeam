//! Signed control-plane helpers for one-shot peer advertisement.

use std::sync::Arc;
use std::time::Duration;

use sha3::Sha3_256;
use tightbeam::builder::TypeBuilder;
use tightbeam::colony::cluster::{Cluster, ClusterRequest};
use tightbeam::colony::common::{PeerAdvertisement, PeerAdvertisementResponse};
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::decode;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient};
use tightbeam::utils::compose as frame_compose;
use tightbeam::utils::urn::Urn;
use tightbeam::{TightBeamError, Version};

use crate::events;
use crate::fixtures::ClusterTestCerts;
use crate::topology::{ColonyFuzzGateway, OrgNode};

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
	identity: &ClusterTestCerts,
	addr: &<TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_timeout(CLIENT_IO_TIMEOUT)
		.with_trust_store(Arc::clone(&identity.trust))
		.with_client_identity(
			CertificateSpec::Built(Box::new(identity.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned())),
		)?
		.build()
		.connect(addr)
		.await?)
}

async fn emit_advertise(
	trace: &TraceCollector,
	signer: &OrgNode,
	receiver: &ColonyFuzzGateway,
	gateway_addr: Vec<u8>,
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<bool, TightBeamError> {
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr, advertised_types: types });
	let frame = signed_control_frame(&signer.certs.key, b"peer-advertise", request, order).await?;
	let mut client = connect_as(&signer.certs, receiver.addr()).await?;

	trace.event(events::PEER_ADVERTISE_SENT)?;

	let Some(response_frame) = client.emit(frame, None).await? else {
		trace.event(events::PEER_AD_DENIED)?;
		return Ok(false);
	};

	let response: PeerAdvertisementResponse = decode(&response_frame.message)?;
	if response.status == TransitStatus::Ok {
		trace.event(events::PEER_AD_OK)?;
		trace.event_with(events::PEER_ROUTES_AFTER, &[], receiver.peer_servlets().len() as u64)?;
		Ok(true)
	} else {
		trace.event(events::PEER_AD_DENIED)?;
		Ok(false)
	}
}

/// Emit a signed advertisement of `types` from `advertiser` into `receiver`.
pub(crate) async fn advertise_peer_types(
	trace: &TraceCollector,
	advertiser: &OrgNode,
	receiver: &ColonyFuzzGateway,
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<bool, TightBeamError> {
	let gateway_addr: Vec<u8> = advertiser.gateway.addr().clone().into();
	emit_advertise(trace, advertiser, receiver, gateway_addr, types, order).await
}

/// Advertise a caller-chosen dial address (dead decoy or live peer).
pub(crate) async fn advertise_peer_at(
	trace: &TraceCollector,
	signer: &OrgNode,
	receiver: &ColonyFuzzGateway,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
	order: u64,
) -> Result<bool, TightBeamError> {
	emit_advertise(trace, signer, receiver, gateway_addr.to_vec(), types, order).await
}
