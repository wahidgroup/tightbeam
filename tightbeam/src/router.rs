#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::core::{FrameShape, Inflator, RequirementError};
use crate::frame::BodyTransform;
use crate::Errorizable;
use crate::{Frame, Message};

#[cfg(feature = "aead")]
use crate::crypto::aead::Decryptor;

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
	/// The frame, as it arrived, fails a requirement of the dispatched type.
	#[error("Frame fails a requirement of the dispatched type: {0}")]
	#[source]
	Requirement(RequirementError),
}

crate::impl_from!(crate::der::Error => RouterError::DecodeFailed);
crate::impl_from!(RequirementError => RouterError::Requirement);

impl RouterError {
	/// The refusal of a body that still needs `transform` before a decode.
	fn opaque(transform: BodyTransform) -> Self {
		match transform {
			BodyTransform::Decrypt => Self::ConfidentialFrame,
			BodyTransform::Inflate => Self::CompressedFrame,
		}
	}
}

/// A frame whose body a router may decode, beside the shape that the frame
/// arrived in.
///
/// An encrypted or compressed body is opaque bytes, so a decode against the
/// dispatched type either fails confusingly or succeeds against a
/// structurally similar type and misdelivers in silence. Each constructor
/// leaves a cleartext body:
///
/// - [`CleartextFrame::admit`] takes a frame that arrived in cleartext.
/// - [`CleartextFrame::decrypt`] decrypts the body of a frame that arrived encrypted.
/// - [`CleartextFrame::inflate`] inflates the body of a frame that arrived compressed.
pub struct CleartextFrame {
	frame: Arc<Frame>,
	arrived: FrameShape,
}

impl CleartextFrame {
	/// Admit `frame`, which arrived in cleartext, for routing.
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- `metadata.confidentiality` is
	///   set, so the frame enters through [`Self::decrypt`].
	/// - [`RouterError::CompressedFrame`] -- `metadata.compactness` is set, so
	///   the frame enters through [`Self::inflate`].
	pub fn admit(frame: Arc<Frame>) -> Result<Self> {
		let arrived = frame.cleartext_shape().map_err(RouterError::opaque)?;
		Ok(Self { frame, arrived })
	}

	/// Decrypt the body of `frame`, which arrived encrypted, and inflate it
	/// after when it is also compressed, for routing.
	///
	/// The open takes the FI digest and the signature out of the frame, and
	/// the routed frame drops both. The shape of the frame as it arrived keeps
	/// each protection for [`Self::decode`].
	///
	/// # Errors
	///
	/// - The errors of [`Frame::decrypt_in_place`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::der::Sequence;
	/// use tightbeam::router::CleartextFrame;
	/// use tightbeam::testing::TestKey;
	/// use tightbeam::{compose, Beamable};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// #[beam(confidential)]
	/// struct Secret {
	///     code: u64,
	/// }
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
	/// # runtime.block_on(async {
	/// let (_, cipher) = TestKey::insecure_fixed_cipher();
	/// let frame = compose! { V1: id: "secret", order: 1u64, message: Secret { code: 7 }, confidentiality: cipher }?;
	///
	/// // The frame arrived encrypted, so the type that requires it decodes.
	/// let (_, key) = TestKey::insecure_fixed_cipher();
	/// let opened = CleartextFrame::decrypt(frame, &key, None).await?;
	/// assert_eq!(opened.decode::<Secret>()?, Secret { code: 7 });
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// # })?;
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	#[cfg(feature = "aead")]
	pub async fn decrypt(
		mut frame: Frame,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&(dyn Inflator + Sync)>,
	) -> crate::error::Result<Self> {
		let arrived = FrameShape::from(&frame);
		// The shape keeps what the digest and the signature protected, so the
		// two drop with the open.
		let _opened = frame.decrypt_in_place(decryptor, inflator).await?;

		Ok(Self { frame: Arc::new(frame), arrived })
	}

	/// Inflate the body of `frame`, which arrived compressed in cleartext,
	/// for routing.
	///
	/// The inflate takes the FI digest and the signature out of the frame,
	/// and the routed frame drops both. The shape of the frame as it arrived
	/// keeps each protection for [`Self::decode`].
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- `metadata.confidentiality` is
	///   set, so the frame enters through [`Self::decrypt`].
	/// - The errors of [`Frame::inflate_in_place`].
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(feature = "zstd")]
	/// # {
	/// use tightbeam::compress::ZstdCompression;
	/// use tightbeam::der::Sequence;
	/// use tightbeam::router::CleartextFrame;
	/// use tightbeam::{compose, Beamable};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// #[beam(compressed)]
	/// struct Bulk {
	///     count: u64,
	/// }
	///
	/// let packed = ZstdCompression::default();
	/// let frame = compose! { V0: id: "bulk", order: 1u64, message: Bulk { count: 7 }, compactness: packed }?;
	///
	/// // The frame arrived compressed, so the type that requires it decodes.
	/// let inflated = CleartextFrame::inflate(frame, &ZstdCompression::default())?;
	/// assert_eq!(inflated.decode::<Bulk>()?, Bulk { count: 7 });
	/// # }
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn inflate(mut frame: Frame, inflator: &dyn Inflator) -> crate::error::Result<Self> {
		if frame.body_transform() == Some(BodyTransform::Decrypt) {
			return Err(RouterError::ConfidentialFrame.into());
		}

		let arrived = FrameShape::from(&frame);
		// The shape keeps what the digest and the signature protected, so the
		// two drop with the inflate.
		let _opened = frame.inflate_in_place(inflator)?;

		Ok(Self { frame: Arc::new(frame), arrived })
	}

	/// The admitted frame, for the decode and for metadata reads.
	#[must_use]
	pub fn frame(&self) -> &Frame {
		&self.frame
	}

	/// The admitted frame as the shared handle a handler keeps.
	#[must_use]
	pub fn into_shared(self) -> Arc<Frame> {
		self.frame
	}

	/// Decode the body of the admitted frame as `T`, after the shape that the
	/// frame arrived in meets the requirements of `T`
	/// ([`Frame::validate_for`]).
	///
	/// The body arrived from a peer, so every universal SET in it MUST hold its
	/// elements in DER order (X.690 § 11.6), which the decode checks before it
	/// sorts one (CWE-407).
	///
	/// # Errors
	///
	/// - [`RouterError::Requirement`] -- the frame, as it arrived, fails a requirement of `T`.
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
	pub fn decode<T: Message>(&self) -> Result<T> {
		self.arrived.decode::<T, RouterError>(self.frame.message())
	}
}

pub trait RouterPolicy: Send + Sync {
	/// Route `frame`, which arrived in cleartext, to the handler registered
	/// for message type `T`, and deliver the body decoded as `T`.
	///
	/// Dispatch decodes the cleartext body exactly once and hands the typed
	/// value to the handler, so a mismatched turbofish fails loudly at the
	/// dispatch site, and foreign bytes never reach the handler.
	/// [`CleartextFrame::admit`] rejects an opaque payload before any decode.
	///
	/// # Errors
	///
	/// - The errors of [`CleartextFrame::admit`], for a body still opaque.
	/// - The errors of [`CleartextFrame::decode`], for a frame that fails a
	///   requirement of `T` or a body that is no `T`.
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
	/// - The errors of [`CleartextFrame::decode`], for a frame that fails a
	///   requirement of `T` or a body that is no `T`.
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

	use crate::core::{Requirement, RequirementError};
	use crate::der::asn1::SetOfVec;
	use crate::der::{ErrorKind, Sequence};
	use crate::router::{CleartextFrame, RouterError, RouterPolicy};
	use crate::testing::{TestFrame, TestResult};
	use crate::{Beamable, Frame, Version};

	#[cfg(all(feature = "aead", feature = "zstd"))]
	use crate::TightBeamError;

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
				// The test reads its receiver, so a failed send shows there as
				// a missing delivery.
				let _ = router.payment_tx.send((frame, msg));
			}
			HealthCheck |router, frame, msg| {
				// The test reads its receiver, so a failed send shows there as
				// a missing delivery.
				let _ = router.health_tx.send((frame, msg));
			}
	}

	routes! {
		TallyRouter {
			tally_tx: mpsc::Sender<Tally>,
		}:
			Tally |router, _frame, msg| {
				// The test reads the refusal alone, so a failed send is moot.
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
	fn descending_tally() -> Frame {
		let counts = SetOfVec::try_from(vec![1u8, 2]).expect("two distinct counts form a set");
		let frame = compose! { V0: id: "tally", order: 1u64, message: Tally { counts } };
		let frame = frame.expect("a V0 frame carries a tally");
		TestFrame::tamper(&frame, ASCENDING_COUNTS, DESCENDING_COUNTS)
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

	/// The V0 frame `p-<index>` of a payment of `index` from alice.
	fn compose_payment(index: u64) -> Frame {
		let frame = compose! {
			V0: id: format!("p-{index}"),
				order: 1u64,
				message: Payment {
					from: "alice".into(),
					amount: index
				}
		};
		frame.expect("a V0 frame carries a payment")
	}

	/// The V0 frame `h-<index>` of a health check of an uptime of `index`.
	fn compose_health(index: u64) -> Frame {
		let frame = compose! {
			V0: id: format!("h-{index}"),
				order: 1u64,
				message: HealthCheck { uptime: index }
		};
		frame.expect("a V0 frame carries a health check")
	}

	/// Dispatches the payment and then the health check of each index below
	/// `count` through `router`, in order of index.
	fn dispatch_in_turn(router: &ChannelRouter, count: u64) {
		for index in 0..count {
			let payment = router.dispatch::<Payment>(Arc::new(compose_payment(index)));
			payment.expect("a payment routes");

			let health = router.dispatch::<HealthCheck>(Arc::new(compose_health(index)));
			health.expect("a health check routes");
		}
	}

	/// The id and the message of each delivery that waits on `deliveries`, in
	/// the order they arrived.
	fn delivered<T>(deliveries: &mpsc::Receiver<Delivery<T>>) -> Vec<(Vec<u8>, T)> {
		let waiting = deliveries.try_iter();
		waiting
			.map(|(frame, message)| (frame.metadata().id().to_vec(), message))
			.collect()
	}

	/// Each route delivers the frames of its own type, decoded, in the order
	/// of their dispatch.
	#[test]
	fn dispatch_delivers_decoded_message_per_route() {
		let (router, payment_rx, health_rx) = build_router();

		dispatch_in_turn(&router, 5);

		let payments = [
			(b"p-0".to_vec(), Payment { from: "alice".into(), amount: 0 }),
			(b"p-1".to_vec(), Payment { from: "alice".into(), amount: 1 }),
			(b"p-2".to_vec(), Payment { from: "alice".into(), amount: 2 }),
			(b"p-3".to_vec(), Payment { from: "alice".into(), amount: 3 }),
			(b"p-4".to_vec(), Payment { from: "alice".into(), amount: 4 }),
		];
		let health_checks = [
			(b"h-0".to_vec(), HealthCheck { uptime: 0 }),
			(b"h-1".to_vec(), HealthCheck { uptime: 1 }),
			(b"h-2".to_vec(), HealthCheck { uptime: 2 }),
			(b"h-3".to_vec(), HealthCheck { uptime: 3 }),
			(b"h-4".to_vec(), HealthCheck { uptime: 4 }),
		];
		assert_eq!(delivered(&payment_rx), payments);
		assert_eq!(delivered(&health_rx), health_checks);
	}

	/// A frame whose body decodes as no `Payment` is refused, and the payment
	/// route delivers nothing.
	#[test]
	fn dispatch_rejects_misdelivered_type() {
		let (router, payment_rx, _health_rx) = build_router();
		let result = router.dispatch::<Payment>(Arc::new(compose_health(0)));
		assert!(matches!(result, Err(RouterError::DecodeFailed(_))));
		assert!(matches!(payment_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
	}

	/// A routed body arrives from a peer, so a SET in it out of DER order is
	/// refused before the decode sorts it (X.690 § 11.6, CWE-407).
	#[test]
	fn dispatch_refuses_a_body_whose_set_is_out_of_der_order() {
		let (tally_tx, _tally_rx) = mpsc::channel();
		let router = TallyRouter { tally_tx };

		let refused = router.dispatch::<Tally>(Arc::new(descending_tally()));
		assert!(matches!(refused, Err(RouterError::DecodeFailed(error)) if error.kind() == ErrorKind::SetOrdering));
	}

	/// A payment whose type requires confidentiality. Its DER is the DER of
	/// [`Payment`].
	#[cfg(feature = "aead")]
	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	#[beam(confidential)]
	pub struct SealedPayment {
		pub from: String,
		pub amount: u64,
	}

	/// A health check whose type requires V2 or later. Its DER is the DER of
	/// [`HealthCheck`].
	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	#[beam(min_version = "V2")]
	pub struct RecentHealthCheck {
		pub uptime: u64,
	}

	#[cfg(feature = "aead")]
	routes! {
		SealedRouter {
			sealed_tx: mpsc::Sender<SealedPayment>,
		}:
			SealedPayment |router, _frame, msg| {
				// The test reads the refusal alone, so a failed send is moot.
				let _ = router.sealed_tx.send(msg);
			}
	}

	routes! {
		RecentRouter {
			recent_tx: mpsc::Sender<RecentHealthCheck>,
		}:
			RecentHealthCheck |router, _frame, msg| {
				// The test reads the refusal alone, so a failed send is moot.
				let _ = router.recent_tx.send(msg);
			}
	}

	/// A router of sealed payments, beside the receiver of its deliveries.
	#[cfg(feature = "aead")]
	fn sealed_router() -> (SealedRouter, mpsc::Receiver<SealedPayment>) {
		let (sealed_tx, sealed_rx) = mpsc::channel();
		(SealedRouter { sealed_tx }, sealed_rx)
	}

	/// A cleartext frame carries no `confidentiality`, so the router refuses it
	/// as a carrier of a type that requires confidentiality.
	#[cfg(feature = "aead")]
	#[test]
	fn a_cleartext_frame_of_a_confidential_type_is_refused() {
		let (router, _sealed_rx) = sealed_router();

		let refused = router.dispatch::<SealedPayment>(Arc::new(compose_payment(0)));
		let unprotected = RequirementError::Unprotected(Requirement::Confidentiality);
		assert!(matches!(refused, Err(RouterError::Requirement(error)) if error == unprotected));
	}

	/// A V0 frame is below the V2 minimum of its type, so the router
	/// refuses it.
	#[test]
	fn a_frame_below_the_minimum_version_of_its_type_is_refused() {
		let (recent_tx, _recent_rx) = mpsc::channel();
		let router = RecentRouter { recent_tx };

		let refused = router.dispatch::<RecentHealthCheck>(Arc::new(compose_health(0)));
		let below = RequirementError::Version((Version::V0, Version::V2).into());
		assert!(matches!(refused, Err(RouterError::Requirement(error)) if error == below));
	}

	/// A frame that arrived encrypted keeps that shape across its decrypt, so a
	/// type that requires confidentiality routes.
	#[cfg(feature = "aead")]
	#[tokio::test]
	async fn a_decrypted_frame_of_a_confidential_type_routes() -> TestResult {
		let (router, sealed_rx) = sealed_router();

		let (_, key) = crate::testing::TestKey::insecure_fixed_cipher();
		let opened = CleartextFrame::decrypt(confidential_payment(3), &key, None).await?;
		router.dispatch_cleartext::<SealedPayment>(opened)?;

		let delivered = sealed_rx.try_recv()?;
		assert_eq!(delivered, SealedPayment { from: "alice".into(), amount: 3 });
		Ok(())
	}

	/// A decrypt in place outside the router takes the confidentiality out of
	/// the frame, so the router refuses the frame it then admits.
	#[cfg(feature = "aead")]
	#[tokio::test]
	async fn a_frame_decrypted_before_admission_loses_its_confidentiality() -> TestResult {
		let (router, _sealed_rx) = sealed_router();

		let (_, key) = crate::testing::TestKey::insecure_fixed_cipher();
		let mut frame = confidential_payment(3);
		let _opened = frame.decrypt_in_place(&key, None).await?;

		let refused = router.dispatch::<SealedPayment>(Arc::new(frame));
		let unprotected = RequirementError::Unprotected(Requirement::Confidentiality);
		assert!(matches!(refused, Err(RouterError::Requirement(error)) if error == unprotected));
		Ok(())
	}

	/// An encrypted body needs a decrypt before an inflate, so the inflate
	/// refuses it.
	#[cfg(all(feature = "aead", feature = "zstd"))]
	#[test]
	fn an_inflate_refuses_an_encrypted_body() {
		use crate::compress::ZstdCompression;

		let inflated = CleartextFrame::inflate(confidential_payment(3), &ZstdCompression::default());
		let refused = matches!(inflated, Err(TightBeamError::RouterError(RouterError::ConfidentialFrame)));
		assert!(refused);
	}

	/// A frame of a type that no route names is refused as an unknown route.
	#[test]
	fn dispatch_rejects_unregistered_type() {
		let (router, _payment_rx, _health_rx) = build_router();
		let result = router.dispatch::<Unrouted>(Arc::new(compose_payment(0)));
		assert!(matches!(result, Err(RouterError::UnknownRoute)));
	}

	/// A policy whose `dispatch_cleartext` records each frame it is handed.
	///
	/// It stands in for a consumer that implements [`RouterPolicy`] by hand, so
	/// the guard must come from the provided `dispatch`, not from this
	/// implementation.
	struct NaiveRouter {
		seen: std::sync::Mutex<Vec<Arc<Frame>>>,
	}

	impl RouterPolicy for NaiveRouter {
		fn dispatch_cleartext<T: crate::Message + Send + 'static>(
			&self,
			frame: crate::router::CleartextFrame,
		) -> crate::router::Result<()> {
			let mut seen = self.seen.lock().unwrap_or_else(|err| err.into_inner());
			seen.push(frame.into_shared());
			Ok(())
		}
	}

	/// A V1 payment whose body is encrypted, so it still needs a decrypt before
	/// a decode.
	#[cfg(feature = "aead")]
	fn confidential_payment(index: u64) -> Frame {
		let payment = Payment { from: "alice".into(), amount: index };
		TestFrame::sealed_with(payment, format!("p-{index}"))
	}

	/// The provided `dispatch` refuses a confidential frame before a policy
	/// written by hand is handed it.
	#[cfg(feature = "aead")]
	#[test]
	fn hand_written_policy_never_sees_a_confidential_frame() -> TestResult {
		let router = NaiveRouter { seen: std::sync::Mutex::new(Vec::new()) };
		let opaque = router.dispatch::<Payment>(Arc::new(confidential_payment(0)));
		assert!(matches!(opaque, Err(RouterError::ConfidentialFrame)));
		assert!(router.seen.into_inner()?.is_empty());
		Ok(())
	}

	/// The admission of a frame refuses a body that still needs a decrypt.
	#[cfg(feature = "aead")]
	#[test]
	fn admit_refuses_a_confidential_body() {
		let frame = Arc::new(confidential_payment(0));
		let refused = CleartextFrame::admit(frame);
		assert!(matches!(refused, Err(RouterError::ConfidentialFrame)));
	}

	/// The router refuses a confidential frame before its route, which
	/// delivers nothing.
	#[cfg(feature = "aead")]
	#[test]
	fn dispatch_rejects_confidential_frame() {
		let (router, payment_rx, _health_rx) = build_router();

		let frame = confidential_payment(0);
		let result = router.dispatch::<Payment>(Arc::new(frame));
		assert!(matches!(result, Err(RouterError::ConfidentialFrame)));
		assert!(matches!(payment_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
	}

	/// The router refuses a compressed frame, whose body still needs an
	/// inflate before a decode.
	#[cfg(feature = "zstd")]
	#[test]
	fn dispatch_rejects_compressed_frame() -> TestResult {
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
