#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{Frame, Message};

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Single `Arc` spelling for both std and no_std builds so [`crate::routes!`]
/// can emit one `dispatch` body via `$crate::router::Arc`.
#[cfg(not(feature = "std"))]
pub use alloc::sync::Arc;
#[cfg(feature = "std")]
pub use std::sync::Arc;

pub type Result<T> = core::result::Result<T, RouterError>;

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum RouterError {
	#[cfg_attr(feature = "derive", error("No route configured for provided message"))]
	UnknownRoute,
	#[cfg_attr(
		feature = "derive",
		error("Frame body failed to decode as the dispatched type: {0}")
	)]
	DecodeFailed(crate::der::Error),
	#[cfg_attr(feature = "derive", error("Frame body is encrypted; decrypt before routing"))]
	ConfidentialFrame,
	#[cfg_attr(feature = "derive", error("Frame body is compressed; inflate before routing"))]
	CompressedFrame,
}

crate::impl_error_display!(RouterError {
	UnknownRoute => "No route configured for provided message",
	DecodeFailed(source) => "Frame body failed to decode as the dispatched type: {source}",
	ConfidentialFrame => "Frame body is encrypted; decrypt before routing",
	CompressedFrame => "Frame body is compressed; inflate before routing",
});

crate::impl_from!(crate::der::Error => RouterError::DecodeFailed);

/// Reject frames whose body cannot be type-validated at routing time.
///
/// The router is strictly cleartext: an encrypted or compressed body
/// cannot be decoded as the dispatched type, so validation would be
/// impossible and misdelivery silent. Decrypt/inflate upstream, then
/// route. Hand-written [`RouterPolicy`] impls MUST call this before
/// decoding.
///
/// # Errors
///
/// - [`RouterError::ConfidentialFrame`] -- `metadata.confidentiality` is set.
/// - [`RouterError::CompressedFrame`] -- `metadata.compactness` is set.
pub fn ensure_cleartext(frame: &Frame) -> Result<()> {
	if frame.metadata.confidentiality.is_some() {
		return Err(RouterError::ConfidentialFrame);
	}
	if frame.metadata.compactness.is_some() {
		return Err(RouterError::CompressedFrame);
	}

	Ok(())
}

pub trait RouterPolicy: Send + Sync {
	/// Route `frame` to the handler registered for message type `T`,
	/// delivering the body decoded as `T`.
	///
	/// Dispatch decodes the cleartext body exactly once and hands the
	/// typed value to the handler, so a mismatched turbofish fails
	/// loudly at the dispatch site instead of silently delivering
	/// foreign bytes. Opaque payloads are rejected before any decode
	/// attempt (see [`ensure_cleartext`]).
	///
	/// Residual: two DER-structurally-identical types still cross-decode
	/// (the wire format carries no type discriminator by design -- the
	/// receiver decides the type, never the sender). [`crate::routes!`] keeps
	/// each type adjacent to its handler to confine that risk.
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- body is encrypted.
	/// - [`RouterError::CompressedFrame`] -- body is compressed.
	/// - [`RouterError::DecodeFailed`] -- body did not decode as `T`.
	/// - [`RouterError::UnknownRoute`] -- no handler registered for `T`.
	fn dispatch<T: Message + Send + 'static>(&self, frame: Arc<Frame>) -> Result<()>;
}

/// Declare a router struct and its [`RouterPolicy`] impl.
///
/// Each route pairs a message type with a handler receiving
/// `|router, frame, msg|`: the router's fields, the original
/// [`Frame`] (metadata access), and the body already decoded as the
/// registered type.
#[macro_export]
macro_rules! routes {
	(
		$RouterName:ident { $( $field:ident : $fty:ty ),* $(,)? } :
		$(
			$MsgTy:ty | $router:ident, $frame:ident, $msg:ident | $handler:block
		)+
	) => {
		struct $RouterName { $( $field : $fty ),* }

		impl $crate::router::RouterPolicy for $RouterName {
			fn dispatch<T: $crate::Message + Send + 'static>(
				&self,
				frame: $crate::router::Arc<$crate::Frame>,
			) -> $crate::router::Result<()> {
				$crate::router::ensure_cleartext(&frame)?;
				$(
					if core::any::TypeId::of::<T>() == core::any::TypeId::of::<$MsgTy>() {
						let decoded: $MsgTy = $crate::der::Decode::from_der(frame.message.as_slice())?;
						let ($router, $frame, $msg) = (self, frame, decoded);
						{ $handler }
						return Ok(());
					}
				)*
				Err($crate::router::RouterError::UnknownRoute)
			}
		}
	};
}

#[cfg(all(test, feature = "builder"))]
mod tests {
	use std::sync::{mpsc, Arc};
	use std::time::Duration;

	use crate::cms::compressed_data::CompressedData;
	use crate::cms::content_info::CmsVersion;
	use crate::cms::enveloped_data::EncryptedContentInfo;
	use crate::cms::signed_data::EncapsulatedContentInfo;
	use crate::der::asn1::OctetString;
	use crate::der::{Decode, Encode, Sequence};
	use crate::oids::{COMPRESSION_ZSTD, DATA};
	use crate::router::{RouterError, RouterPolicy};
	use crate::spki::AlgorithmIdentifier;
	use crate::Beamable;
	use crate::Frame;

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	pub struct HealthCheck {
		pub uptime: u64,
	}

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	pub struct Payment {
		pub from: String,
		pub amount: u64,
	}

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	pub struct Unrouted {
		pub note: String,
	}

	type Delivery<T> = (Arc<Frame>, T);

	routes! {
		ChannelRouter {
			payment_tx: mpsc::Sender<Delivery<Payment>>,
			health_tx: mpsc::Sender<Delivery<HealthCheck>>,
		}:
			Payment |router, frame, msg| {
				let _ = router.payment_tx.send((frame, msg));
			}
			HealthCheck |router, frame, msg| {
				let _ = router.health_tx.send((frame, msg));
			}
	}

	fn build_router() -> (
		ChannelRouter,
		mpsc::Receiver<Delivery<Payment>>,
		mpsc::Receiver<Delivery<HealthCheck>>,
	) {
		let (payment_tx, payment_rx) = mpsc::channel();
		let (health_tx, health_rx) = mpsc::channel();
		(ChannelRouter { payment_tx, health_tx }, payment_rx, health_rx)
	}

	fn compose_payment(index: u64) -> Result<Frame, Box<dyn std::error::Error>> {
		let frame = compose! {
			V0: id: format!("p-{index}"),
				order: 1u64,
				message: Payment {
					from: "alice".into(),
					amount: index
				}
		}?;
		Ok(frame)
	}

	fn compose_health(index: u64) -> Result<Frame, Box<dyn std::error::Error>> {
		let frame = compose! {
			V0: id: format!("h-{index}"),
				order: 1u64,
				message: HealthCheck { uptime: index }
		}?;
		Ok(frame)
	}

	#[test]
	fn dispatch_delivers_decoded_message_per_route() -> Result<(), Box<dyn std::error::Error>> {
		let (router, payment_rx, health_rx) = build_router();

		let n = 5u64;
		for i in 0..n {
			router.dispatch::<Payment>(Arc::new(compose_payment(i)?))?;
			router.dispatch::<HealthCheck>(Arc::new(compose_health(i)?))?;
		}

		let timeout = Duration::from_millis(200);
		for i in 0..n {
			let (payment_frame, payment) = payment_rx.recv_timeout(timeout)?;
			assert_eq!(&payment_frame.metadata.id, &format!("p-{i}").as_bytes());
			assert_eq!(payment, Payment { from: "alice".into(), amount: i });

			let (health_frame, health) = health_rx.recv_timeout(timeout)?;
			assert_eq!(&health_frame.metadata.id, &format!("h-{i}").as_bytes());
			assert_eq!(health, HealthCheck { uptime: i });
		}

		Ok(())
	}

	#[test]
	fn dispatch_rejects_misdelivered_type() -> Result<(), Box<dyn std::error::Error>> {
		let (router, payment_rx, _health_rx) = build_router();

		let result = router.dispatch::<Payment>(Arc::new(compose_health(0)?));
		assert!(matches!(result, Err(RouterError::DecodeFailed(_))));
		assert!(matches!(
			payment_rx.recv_timeout(Duration::from_millis(50)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		Ok(())
	}

	#[test]
	fn dispatch_rejects_unregistered_type() -> Result<(), Box<dyn std::error::Error>> {
		let (router, _payment_rx, _health_rx) = build_router();

		let result = router.dispatch::<Unrouted>(Arc::new(compose_payment(0)?));
		assert!(matches!(result, Err(RouterError::UnknownRoute)));
		Ok(())
	}

	#[test]
	fn dispatch_rejects_confidential_frame() -> Result<(), Box<dyn std::error::Error>> {
		let (router, payment_rx, _health_rx) = build_router();

		let mut frame = compose_payment(0)?;
		frame.metadata.confidentiality = Some(EncryptedContentInfo {
			content_type: DATA,
			content_enc_alg: AlgorithmIdentifier { oid: DATA, parameters: None },
			encrypted_content: Some(OctetString::new(vec![0; 16])?),
		});

		let result = router.dispatch::<Payment>(Arc::new(frame));
		assert!(matches!(result, Err(RouterError::ConfidentialFrame)));
		assert!(matches!(
			payment_rx.recv_timeout(Duration::from_millis(50)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		Ok(())
	}

	#[test]
	fn dispatch_rejects_compressed_frame() -> Result<(), Box<dyn std::error::Error>> {
		let (router, _payment_rx, _health_rx) = build_router();

		let mut frame = compose_payment(0)?;
		frame.metadata.compactness = Some(CompressedData {
			version: CmsVersion::V0,
			compression_alg: AlgorithmIdentifier { oid: COMPRESSION_ZSTD, parameters: None },
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: DATA,
				econtent: Some(crate::der::Any::from_der(&OctetString::new(vec![0; 8])?.to_der()?)?),
			},
		});

		let result = router.dispatch::<Payment>(Arc::new(frame));
		assert!(matches!(result, Err(RouterError::CompressedFrame)));
		Ok(())
	}
}
