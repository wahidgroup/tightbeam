//! Properties of the transport envelope and of the reader that frames it off
//! a byte stream.

use std::io::{Error as IoError, ErrorKind};

use proptest::prelude::*;
use tokio::runtime::Builder;

use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::{
	GoAwayPackage, MuxCancelPackage, MuxCreditPackage, MuxDataPackage, MuxEndPackage, MuxOpenPackage, MuxPingPackage,
	MuxStreamKind,
};
use tightbeam::transport::{
	AsyncByteRead, AsyncReadStream, ResponsePackage, TransportEnvelope, TransportError, TransportFailure,
};
use tightbeam::utils::urn::Urn;

use super::any_frame;

/// Every status the wire carries.
fn any_status() -> impl Strategy<Value = TransitStatus> {
	(0u8..=16).prop_map(|code| TransitStatus::try_from(code).expect("every code up to 16 names a status"))
}

/// An envelope from every arm but the two handshake containers.
fn any_envelope() -> impl Strategy<Value = TransportEnvelope> {
	let payload = || prop::collection::vec(any::<u8>(), 0..64);
	let kind = prop_oneof![
		Just(MuxStreamKind::Unary),
		Just(MuxStreamKind::Streaming),
		Just(MuxStreamKind::Duplex)
	];
	let target = prop::option::of("[a-z]{2,8}:[a-z]{1,16}".prop_map(|urn| format!("urn:{urn}")));
	prop_oneof![
		any_frame().prop_map(TransportEnvelope::new_request),
		(any_status(), prop::option::of(any_frame()))
			.prop_map(|(status, frame)| ResponsePackage::new(status, frame).into()),
		(any::<u32>(), any::<bool>(), kind, payload(), target, any::<u8>()).prop_map(
			|(id, last, kind, payload, target, hops)| {
				let target = target.map(|urn| urn.parse::<Urn<'static>>().expect("the pattern is a URN"));
				let open = MuxOpenPackage::new(id, last, kind, payload).expect("a short payload fits");
				open.with_route(target, hops).into()
			}
		),
		(any::<u32>(), any::<bool>(), payload()).prop_map(|(id, last, payload)| {
			let data = MuxDataPackage::new(id, last, payload).expect("a short payload fits");
			data.into()
		}),
		(any::<u32>(), any_status(), payload()).prop_map(|(id, status, payload)| {
			let end = MuxEndPackage::new(id, status, payload).expect("a short payload fits");
			end.into()
		}),
		(any::<u32>(), any::<u64>()).prop_map(|(id, limit)| MuxCreditPackage::new(id, limit).into()),
		(any::<u32>(), any::<u32>()).prop_map(|(id, code)| MuxCancelPackage::new(id, code).into()),
		(any::<bool>(), any::<u64>()).prop_map(|(ack, opaque)| MuxPingPackage::new(ack, opaque).into()),
		(any::<u32>(), any::<u32>()).prop_map(|(id, code)| GoAwayPackage::new(id, code).into()),
	]
}

/// A byte stream that replays `wire` and then reports end of file.
struct WireBytes {
	wire: Vec<u8>,
	read: usize,
}

impl AsyncByteRead for WireBytes {
	type Error = TransportError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		let end = self.read + buf.len();
		let chunk = self
			.wire
			.get(self.read..end)
			.ok_or(TransportError::IoError(IoError::from(ErrorKind::UnexpectedEof)))?;
		buf.copy_from_slice(chunk);
		self.read = end;
		Ok(())
	}
}

/// The frame the reader recovers from `wire` under `cap`, or the failure it
/// refused the frame with. A refusal that names no failure reads as `None`.
fn read_frame(wire: impl Into<Vec<u8>>, cap: usize) -> Result<Vec<u8>, Option<TransportFailure>> {
	let mut stream = WireBytes { wire: wire.into(), read: 0 };
	let runtime = Builder::new_current_thread().build().expect("a current-thread runtime builds");
	runtime.block_on(stream.read_frame(cap)).map_err(|error| match error {
		TransportError::OperationFailed(failure) => Some(failure),
		_ => None,
	})
}

proptest! {
	/// Every arm of the envelope decodes back to the envelope that was
	/// encoded.
	#[test]
	fn an_envelope_survives_a_der_round_trip(envelope in any_envelope()) {
		prop_assert_eq!(TransportEnvelope::from_der(&envelope.to_der()?)?, envelope);
	}

	/// A frame whose declared length is within the cap reads back byte for
	/// byte.
	#[test]
	fn a_frame_within_the_cap_reads_back(
		content in prop::collection::vec(any::<u8>(), 0..600),
		headroom in 0usize..=2,
	) {
		let cap = content.len() + headroom;
		let wire = OctetString::new(content)?.to_der()?;
		let read = read_frame(wire.clone(), cap);
		prop_assert_eq!(read, Ok(wire));
	}

	/// A frame one byte longer than the cap is refused as too large.
	#[test]
	fn a_frame_over_the_cap_is_refused(content in prop::collection::vec(any::<u8>(), 1..600)) {
		let cap = content.len() - 1;
		let wire = OctetString::new(content)?.to_der()?;
		let read = read_frame(wire, cap);
		prop_assert_eq!(read, Err(Some(TransportFailure::SizeExceeded)));
	}
}
