#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::asn1::Frame;
#[cfg(feature = "transport-policy")]
use crate::transport::policy::PolicyConf;
use crate::transport::{Protocol, TransportResult};
use core::marker::PhantomData;

#[cfg(feature = "builder")]
use crate::transport::{MessageCollector, MessageEmitter};

#[cfg(feature = "builder")]
pub struct GenericClient<P: Protocol> {
	transport: P::Transport,
	_ph: PhantomData<P>,
}

#[cfg(feature = "builder")]
impl<P: Protocol> GenericClient<P> {
	pub fn from_transport(transport: P::Transport) -> Self {
		Self { transport, _ph: PhantomData }
	}
	pub fn transport(&self) -> &P::Transport {
		&self.transport
	}
	pub fn into_transport(self) -> P::Transport {
		self.transport
	}
	#[allow(async_fn_in_trait)]
	pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
	where
		P::Transport: MessageEmitter,
	{
		self.transport.emit(frame, attempt).await
	}
}
