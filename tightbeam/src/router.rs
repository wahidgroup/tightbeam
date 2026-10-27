#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::asn1::admission::DerAdmission;
use crate::der::Decode;
use crate::frame::BodyTransform;
use crate::Errorizable;
use crate::{Frame, Message};

/// Single `Arc` spelling for both std and no_std builds so [`crate::routes!`]
/// can emit one `dispatch` body via `$crate::router::Arc`.
#[cfg(not(feature = "std"))]
pub use alloc::sync::Arc;
#[cfg(feature = "std")]
pub use std::sync::Arc;

pub type Result<T> = core::result::Result<T, RouterError>;

#[derive(Errorizable, Debug)]
pub enum RouterError {
	#[error("No route configured for provided message")]
	UnknownRoute,
	#[error("Frame body failed to decode as the dispatched type: {0}")]
	DecodeFailed(crate::der::Error),
	#[error("Frame body is encrypted; decrypt before routing")]
	ConfidentialFrame,
	#[error("Frame body is compressed; inflate before routing")]
	CompressedFrame,
}

crate::impl_from!(crate::der::Error => RouterError::DecodeFailed);

/// A frame whose body a router may decode.
///
/// [`CleartextFrame::admit`] is the one constructor. An encrypted or
/// compressed body is opaque bytes, so a decode against the dispatched type
/// either fails confusingly or succeeds against a structurally similar type
/// and misdelivers in silence.
pub struct CleartextFrame(Arc<Frame>);

impl CleartextFrame {
	/// Admit `frame` for routing.
	///
	/// Decrypt or inflate upstream through
	/// [`Frame::prepare_typed`](crate::Frame::prepare_typed), then admit.
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- `metadata.confidentiality` is set.
	/// - [`RouterError::CompressedFrame`] -- `metadata.compactness` is set.
	pub fn admit(frame: Arc<Frame>) -> Result<Self> {
		match frame.body_transform() {
			Some(BodyTransform::Decrypt) => Err(RouterError::ConfidentialFrame),
			Some(BodyTransform::Inflate) => Err(RouterError::CompressedFrame),
			None => Ok(Self(frame)),
		}
	}

	/// The admitted frame, for the decode and for metadata reads.
	#[must_use]
	pub fn frame(&self) -> &Frame {
		&self.0
	}

	/// The admitted frame as the shared handle a handler keeps.
	#[must_use]
	pub fn into_shared(self) -> Arc<Frame> {
		self.0
	}

	/// Decode the body of the admitted frame as `T`.
	///
	/// The body arrived from a peer, so every universal SET in it MUST hold its
	/// elements in DER order (X.690 § 11.6), which the decode checks before it
	/// sorts one (CWE-407).
	///
	/// # Errors
	///
	/// - [`RouterError::DecodeFailed`] -- the body is no DER encoding of `T`,
	///   or a SET in it holds its elements out of DER order.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::der::Sequence;
	/// use tightbeam::router::CleartextFrame;
	/// use tightbeam::{compose, Beamable};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     sequence: u64,
	/// }
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let frame = compose! { V0: id: "ping", order: 1u64, message: Ping { sequence: 7 } }?;
	/// let admitted = CleartextFrame::admit(Arc::new(frame))?;
	///
	/// let ping: Ping = admitted.decode()?;
	/// assert_eq!(ping, Ping { sequence: 7 });
	/// # Ok(())
	/// # }
	/// ```
	///
	/// # Sources
	///
	/// - ITU-T X.690 (02/2021) § 11.6, set-of components: <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
	pub fn decode<'a, T: Decode<'a>>(&'a self) -> Result<T> {
		let body = self.0.message();
		DerAdmission::SetOrder.admit(body)?;

		Ok(T::from_der(body)?)
	}
}

pub trait RouterPolicy: Send + Sync {
	/// Route `frame` to the handler registered for message type `T`, and
	/// deliver the body decoded as `T`.
	///
	/// Dispatch decodes the cleartext body exactly once and hands the typed
	/// value to the handler, so a mismatched turbofish fails loudly at the
	/// dispatch site, and foreign bytes never reach the handler.
	/// [`CleartextFrame::admit`] rejects an opaque payload before any decode.
	///
	/// # Errors
	///
	/// - The errors of [`CleartextFrame::admit`], for a body still opaque.
	/// - [`RouterError::DecodeFailed`] -- the body did not decode as `T`.
	/// - [`RouterError::UnknownRoute`] -- no handler is registered for `T`.
	fn dispatch<T: Message + Send + 'static>(&self, frame: Arc<Frame>) -> Result<()> {
		self.dispatch_cleartext::<T>(CleartextFrame::admit(frame)?)
	}

	/// Deliver a frame the [`CleartextFrame`] boundary already admitted.
	///
	/// Implementations decode the body through [`CleartextFrame::decode`] and
	/// route it. The parameter type is the proof, so this method cannot be
	/// reached with an opaque body, even by a direct call (CWE-345).
	///
	/// # Errors
	///
	/// - [`RouterError::DecodeFailed`] -- the body did not decode as `T`.
	/// - [`RouterError::UnknownRoute`] -- no handler is registered for `T`.
	fn dispatch_cleartext<T: Message + Send + 'static>(&self, frame: CleartextFrame) -> Result<()>;
}

/// Declare a router struct and its [`RouterPolicy`] impl.
///
/// Each route pairs a message type with a handler that receives
/// `|router, frame, msg|`: the router's fields, the original [`Frame`] for
/// metadata reads, and the body already decoded as the registered type.
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
			fn dispatch_cleartext<T: $crate::Message + Send + 'static>(
				&self,
				frame: $crate::router::CleartextFrame,
			) -> $crate::router::Result<()> {
				$(
					if core::any::TypeId::of::<T>() == core::any::TypeId::of::<$MsgTy>() {
						let decoded: $MsgTy = frame.decode()?;
						let ($router, $frame, $msg) = (self, frame.into_shared(), decoded);
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

	use crate::der::asn1::SetOfVec;
	use crate::der::{Decode, Encode, ErrorKind, Sequence};
	use crate::router::{RouterError, RouterPolicy};
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

	/// A tally whose counts travel as a DER `SET OF`.
	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	pub struct Tally {
		pub counts: SetOfVec<u8>,
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

	routes! {
		TallyRouter {
			tally_tx: mpsc::Sender<Tally>,
		}:
			Tally |router, _frame, msg| {
				let _ = router.tally_tx.send(msg);
			}
	}

	/// The set of counts 1 and 2 in DER order, as it travels inside a `Tally`
	/// body.
	const ASCENDING_COUNTS: [u8; 8] = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];

	/// The same set with its counts in descending order.
	const DESCENDING_COUNTS: [u8; 8] = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];

	/// A frame whose `Tally` body holds its counts in descending order, as a
	/// peer that skips DER order sends it.
	fn descending_tally() -> Result<Frame, Box<dyn std::error::Error>> {
		let counts = SetOfVec::try_from(vec![1u8, 2])?;
		let frame = compose! { V0: id: "tally", order: 1u64, message: Tally { counts } }?;
		let mut der = frame.to_der()?;
		let at = der
			.windows(ASCENDING_COUNTS.len())
			.position(|window| window == ASCENDING_COUNTS);

		let at = at.ok_or("the encoded frame carries the counts in DER order")?;
		der[at..at + DESCENDING_COUNTS.len()].copy_from_slice(&DESCENDING_COUNTS);

		Ok(Frame::from_der(&der)?)
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
			assert_eq!(payment_frame.metadata().id(), format!("p-{i}").as_bytes());
			assert_eq!(payment, Payment { from: "alice".into(), amount: i });

			let (health_frame, health) = health_rx.recv_timeout(timeout)?;
			assert_eq!(health_frame.metadata().id(), format!("h-{i}").as_bytes());
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

	/// A routed body arrives from a peer, so a SET in it out of DER order is
	/// refused before the decode sorts it (X.690 § 11.6, CWE-407).
	#[test]
	fn dispatch_refuses_a_body_whose_set_is_out_of_der_order() -> Result<(), Box<dyn std::error::Error>> {
		let (tally_tx, _tally_rx) = mpsc::channel();
		let router = TallyRouter { tally_tx };

		let refused = router.dispatch::<Tally>(Arc::new(descending_tally()?));
		assert!(matches!(refused, Err(RouterError::DecodeFailed(error)) if error.kind() == ErrorKind::SetOrdering));
		Ok(())
	}

	#[test]
	fn dispatch_rejects_unregistered_type() -> Result<(), Box<dyn std::error::Error>> {
		let (router, _payment_rx, _health_rx) = build_router();
		let result = router.dispatch::<Unrouted>(Arc::new(compose_payment(0)?));
		assert!(matches!(result, Err(RouterError::UnknownRoute)));
		Ok(())
	}

	/// A policy that counts every frame it is handed, with no guard of its own.
	///
	/// It stands in for a consumer that implements [`RouterPolicy`] by hand, so
	/// the guard must come from the provided `dispatch`, not from this
	/// implementation.
	struct NaiveRouter {
		seen: std::sync::Mutex<usize>,
	}

	impl RouterPolicy for NaiveRouter {
		fn dispatch_cleartext<T: crate::Message + Send + 'static>(
			&self,
			frame: crate::router::CleartextFrame,
		) -> crate::router::Result<()> {
			let _ = frame.into_shared();
			let mut seen = self.seen.lock().unwrap_or_else(|err| err.into_inner());
			*seen += 1;
			Ok(())
		}
	}

	/// A V1 payment whose body is encrypted, so it still needs a decrypt before
	/// a decode.
	#[cfg(feature = "aead")]
	fn confidential_payment(index: u64) -> Result<Frame, Box<dyn std::error::Error>> {
		use crate::testing::TestKey;

		let (_, cipher) = TestKey::insecure_fixed_cipher();
		let frame = compose! {
			V1: id: format!("p-{index}"),
				order: 1u64,
				message: Payment {
					from: "alice".into(),
					amount: index
				},
				confidentiality: cipher
		}?;
		Ok(frame)
	}

	#[cfg(feature = "aead")]
	#[test]
	fn hand_written_policy_never_sees_a_confidential_frame() -> Result<(), Box<dyn std::error::Error>> {
		let router = NaiveRouter { seen: std::sync::Mutex::new(0) };
		let opaque = router.dispatch::<Payment>(Arc::new(confidential_payment(0)?));
		assert!(matches!(opaque, Err(RouterError::ConfidentialFrame)));
		assert_eq!(*router.seen.lock().unwrap_or_else(|err| err.into_inner()), 0);
		Ok(())
	}

	#[cfg(feature = "aead")]
	#[test]
	fn admit_refuses_a_confidential_body() -> Result<(), Box<dyn std::error::Error>> {
		let frame = Arc::new(confidential_payment(0)?);
		assert!(matches!(
			crate::router::CleartextFrame::admit(frame),
			Err(RouterError::ConfidentialFrame)
		));
		Ok(())
	}

	#[cfg(feature = "aead")]
	#[test]
	fn dispatch_rejects_confidential_frame() -> Result<(), Box<dyn std::error::Error>> {
		let (router, payment_rx, _health_rx) = build_router();

		let frame = confidential_payment(0)?;
		let result = router.dispatch::<Payment>(Arc::new(frame));
		assert!(matches!(result, Err(RouterError::ConfidentialFrame)));
		assert!(matches!(
			payment_rx.recv_timeout(Duration::from_millis(50)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		Ok(())
	}

	#[cfg(feature = "zstd")]
	#[test]
	fn dispatch_rejects_compressed_frame() -> Result<(), Box<dyn std::error::Error>> {
		use crate::compress::ZstdCompression;

		let (router, _payment_rx, _health_rx) = build_router();
		let frame = compose! {
			V0: id: "p-compressed",
				order: 1u64,
				message: Payment {
					from: "alice".into(),
					amount: 0
				},
				compactness: ZstdCompression::default()
		}?;

		let result = router.dispatch::<Payment>(Arc::new(frame));
		assert!(matches!(result, Err(RouterError::CompressedFrame)));
		Ok(())
	}
}
