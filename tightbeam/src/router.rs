#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::{Frame, Message};

#[cfg(feature = "derive")]
use crate::Errorizable;

pub type Result<T> = core::result::Result<T, RouterError>;

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum RouterError {
	#[cfg_attr(feature = "derive", error("No route configured for provided message"))]
	UnknownRoute,
}

crate::impl_error_display!(RouterError {
	UnknownRoute => "No route configured for provided message",
});

pub trait RouterPolicy: Send + Sync {
	fn dispatch<T: Message + Send + 'static>(&self, message: Arc<Frame>) -> Result<()>;
}

#[macro_export]
macro_rules! routes {
	// Helper for generating dispatch logic
	(@dispatch $self:ident, $message:ident, [ $( ($MsgTy:ty, $this:ident, $arg:pat_param, $handler:block) ),* ]) => {
		$(
			if std::any::TypeId::of::<T>() == std::any::TypeId::of::<$MsgTy>() {
				let $arg = $message;
				let $this = $self;
				{ $handler }
				return Ok(());
			}
		)*
		Err($crate::router::RouterError::UnknownRoute)
	};

	// Helper for generating dispatch logic (1-arg form)
	(@dispatch $self:ident, $message:ident, [ $( ($MsgTy:ty, $arg:pat_param, $handler:block) ),* ]) => {
		$(
			if std::any::TypeId::of::<T>() == std::any::TypeId::of::<$MsgTy>() {
				let $arg = $message;
				{ $handler }
			 return Ok(());
			}
		)*
		Err($crate::router::RouterError::UnknownRoute)
	};

	(
		$RouterName:ident { $( $field:ident : $fty:ty ),* $(,)? } :
		$(
			$MsgTy:ty | $($arg:ident),* | $handler:block
		)+
	) => {
		struct $RouterName { $( $field : $fty ),* }
		impl $crate::router::RouterPolicy for $RouterName {
			#[cfg(not(feature = "std"))]
			fn dispatch<T: $crate::Message + Send + 'static>(&self, message: alloc::sync::Arc<$crate::Frame>) -> $crate::router::Result<()> {
				$(
					if std::any::TypeId::of::<T>() == std::any::TypeId::of::<$MsgTy>() {
						let ($($arg),*) = (self, message);
						$handler;
						return Ok(());
					}
				)*
				Err($crate::router::RouterError::UnknownRoute)
			}

			#[cfg(feature = "std")]
			fn dispatch<T: $crate::Message + Send + 'static>(&self, message: std::sync::Arc<$crate::Frame>) -> $crate::router::Result<()> {
				$(
					if std::any::TypeId::of::<T>() == std::any::TypeId::of::<$MsgTy>() {
						let ($($arg),*) = (self, message);
						$handler;
						return Ok(());
					}
				)*
				Err($crate::router::RouterError::UnknownRoute)
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use std::sync::{mpsc, Arc};
	use std::time::Duration;

	use crate::compose;
	use crate::der::Sequence;
	use crate::router::RouterPolicy;
	use crate::Beamable;
	use crate::Frame;

	#[cfg(not(feature = "derive"))]
	use crate::router::RouterPolicy;

	#[cfg_attr(feature = "derive", derive(Beamable))]
	#[derive(Sequence, Clone, Debug, PartialEq)]
	pub struct HealthCheck {
		pub uptime: u64,
	}

	#[cfg(not(feature = "derive"))]
	impl crate::Message for HealthCheck {
		const MUST_BE_CONFIDENTIAL: bool = false;
		const MUST_BE_NON_REPUDIABLE: bool = false;
		const MUST_BE_COMPRESSED: bool = false;
		const MUST_BE_PRIORITIZED: bool = false;
		const MIN_VERSION: crate::Version = crate::Version::V0;
	}

	#[cfg_attr(feature = "derive", derive(Beamable))]
	#[derive(Sequence, Clone, Debug, PartialEq)]
	pub struct Payment {
		pub from: String,
		pub amount: u64,
	}

	#[cfg(not(feature = "derive"))]
	impl crate::Message for Payment {
		const MUST_BE_CONFIDENTIAL: bool = false;
		const MUST_BE_NON_REPUDIABLE: bool = false;
		const MUST_BE_COMPRESSED: bool = false;
		const MUST_BE_PRIORITIZED: bool = false;
		const MIN_VERSION: crate::Version = crate::Version::V0;
	}

	#[test]
	fn test_mpsc_channel_routing() -> Result<(), Box<dyn std::error::Error>> {
		#[cfg(feature = "derive")]
		routes! {
			ChannelRouter {
				payment_tx: mpsc::Sender<Arc<Frame>>,
				health_tx: mpsc::Sender<Arc<Frame>>,
			}:
				Payment |router, msg| {
					let _ = router.payment_tx.send(msg);
				}
				HealthCheck |router, msg| {
					let _ = router.health_tx.send(msg);
				}
		}

		#[cfg(not(feature = "derive"))]
		struct ChannelRouter {
			payment_tx: mpsc::Sender<Arc<Frame>>,
			health_tx: mpsc::Sender<Arc<Frame>>,
		}

		#[cfg(not(feature = "derive"))]
		impl super::RouterPolicy for ChannelRouter {
			fn dispatch<M: Message>(&self, message: Arc<Frame>) -> crate::router::Result<()> {
				if std::any::TypeId::of::<M>() == std::any::TypeId::of::<Payment>() {
					let _ = self.payment_tx.send(message);
					return Ok(());
				}

				if std::any::TypeId::of::<M>() == std::any::TypeId::of::<HealthCheck>() {
					let _ = self.health_tx.send(message);
					return Ok(());
				}

				Err(super::RouterError::UnknownRoute)
			}
		}

		let (payment_tx, payment_rx) = mpsc::channel::<Arc<Frame>>();
		let (health_tx, health_rx) = mpsc::channel::<Arc<Frame>>();
		let router = ChannelRouter { payment_tx, health_tx };

		let n = 5usize;
		for i in 0..n {
			// Compose Payment
			let payment = compose! {
				V0: id: format!("p-{i}"),
					order: 1u64,
					message: Payment {
						from: "alice".into(),
						amount: i as u64
					}
			}?;
			// Route
			router.dispatch::<Payment>(Arc::new(payment))?;

			// Compose HealthCheck
			let health = compose! {
				V0: id: format!("h-{i}"),
					order: 1u64,
					message: HealthCheck {
						uptime: i as u64
					}
			}?;
			// Route
			router.dispatch::<HealthCheck>(Arc::new(health))?;
		}

		// Verify n messages per channel
		let timeout = Duration::from_millis(200);
		for i in 0..n {
			let received_payment = payment_rx.recv_timeout(timeout)?;
			let message: Payment = crate::decode(&received_payment.message)?;
			assert_eq!(&received_payment.metadata.id, &format!("p-{i}").as_bytes());
			assert_eq!(message, Payment { from: "alice".into(), amount: i as u64 });

			let received_health = health_rx.recv_timeout(timeout)?;
			let message: HealthCheck = crate::decode(&received_health.message)?;
			assert_eq!(received_health.metadata.id, format!("h-{i}").as_bytes());
			assert_eq!(message, HealthCheck { uptime: i as u64 });
		}

		Ok(())
	}
}
