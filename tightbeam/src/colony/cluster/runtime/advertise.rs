//! The direct advertisement, the one gateway dial that admits whichever
//! gateway answers.
//!
//! A direct advertisement is owed to every beat target, and the receiver
//! decides whether to admit it.
//!
//! - [`Advertiser`] holds the pool for that dial, and its unbound connect is private to this module.
//! - The dial carries a [`SignedAdvertisement`] alone, which [`ClusterConfig::mint_ad_frame`] alone builds.
//! - Every other dial of a route-named target goes through a [`BoundDial`],
//!   and every gossip dial through a membership proof.
//!
//! [`BoundDial`]: crate::colony::bound_dial::BoundDial

use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, ColonyDialProtocol};
use crate::colony::cluster::{ClusterConfig, ClusterError};
use crate::colony::common::{ClusterRequest, PeerAdvertisement, PeerAdvertisementResponse};
use crate::decode;
use crate::policy::TransitStatus;
use crate::transport::{PooledClient, Protocol};
use crate::urn::Urn;
use crate::Frame;
use crate::{MessagePriority, Version};

/// One signed peer advertisement of this gateway's slate.
///
/// [`ClusterConfig::mint_ad_frame`] is the one constructor, so the unbound
/// dial of [`Advertiser::advertise`] carries an advertisement this gateway
/// signed, and that alone.
pub(crate) struct SignedAdvertisement(Frame);

impl SignedAdvertisement {
	/// The signed frame, which an advertisement rumor wraps.
	pub(crate) fn frame(&self) -> &Frame {
		&self.0
	}
}

impl ClusterConfig {
	/// Creates and signs one peer advertisement frame for the local slate.
	///
	/// One frame serves both delivery paths, so direct dials and gossip
	/// rumors carry the same signer-binds-to-address unit.
	///
	/// # Delivery paths
	///
	/// - A direct dial through [`Advertiser::advertise`].
	/// - An advertisement rumor through [`ClusterConfig::mint_slate_rumor`].
	pub(super) async fn mint_ad_frame<D: ClusterDigest>(
		&self,
		gateway_addr: impl AsRef<[u8]>,
		types: impl IntoIterator<Item = Urn<'static>>,
	) -> Result<SignedAdvertisement, ClusterError> {
		let gateway_addr = gateway_addr.as_ref();
		let types: Vec<Urn<'static>> = types.into_iter().collect();
		// The message type owns its bytes, so the encode boundary takes an
		// owned copy of the address.
		let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
			gateway_addr: gateway_addr.to_vec(),
			advertised_types: types,
		});

		let mut signed_frame = FrameBuilder::from(Version::V2)
			.with_id(b"peer-advertise")
			.with_order(self.clock.unix().get())
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()?;

		signed_frame.sign_with_provider(self.tls.identity()).await?;
		Ok(SignedAdvertisement(signed_frame))
	}
}

/// The pool a gateway sends its direct advertisements on.
pub(crate) struct Advertiser<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
}

impl<P: Protocol> Advertiser<P> {
	/// An advertiser that dials on `pool`.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>) -> Self {
		Self { pool }
	}
}

impl<P: ColonyDialProtocol> Advertiser<P> {
	/// Sends `advertisement` to the gateway at `peer_addr` and returns the
	/// status it answered.
	///
	/// The caller signs one advertisement per beat and fans it out, so one
	/// signature serves every dial.
	///
	/// # Errors
	///
	/// - [`ClusterError::Transport`] -- the dial or the emit failed.
	/// - [`ClusterError::NoResponse`] -- the gateway closed without answering.
	/// - [`ClusterError::Frame`] -- the answer does not decode.
	pub(crate) async fn advertise(
		&self,
		peer_addr: P::Address,
		advertisement: &SignedAdvertisement,
	) -> Result<TransitStatus, ClusterError> {
		let signed_frame = advertisement.frame().clone();
		let mut client = self.connect_unbound(peer_addr).await?;
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

		let decoded: PeerAdvertisementResponse = decode(response.message())?;
		Ok(decoded.status)
	}

	/// Connects to `address` and returns a client to the gateway that answers.
	///
	/// # Errors
	///
	/// - [`ClusterError::Transport`] -- the dial failed.
	async fn connect_unbound(&self, address: impl Into<P::Address>) -> Result<PooledClient<P>, ClusterError> {
		let client = self.pool.connect(address).await?;
		Ok(client)
	}
}
