#![cfg(feature = "full")]
use fake::{faker, Fake};

use tightbeam::prelude::*;

use policy::PolicyConfiguration;

tightbeam::mutex! {
	CRYPTO_CHAINS: Vec<IntegrityInfo> = vec![],
}

tightbeam::rwlock! {
	SIGNING_KEY: Option<crypto::schnorr::SigningKey>,
}

#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
#[beam("confidential")]
struct Mail {
	subject: String,
	body: Vec<u8>,
}

#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
#[beam("confidential")]
struct Address {
	street: Vec<String>,
	city: String,
	country: String,
	postal_code: String,
}

#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
#[beam("nonrepudiable")]
struct Block {
	id: u64,
	transactions: Vec<Mail>,
}

mod helpers {
	use super::*;

	pub fn _generate_mail() -> Mail {
		Mail {
			subject: faker::lorem::en::Sentence(3..6).fake(),
			body: faker::lorem::en::Paragraph(1..3).fake::<String>().into_bytes(),
		}
	}

	pub fn _generate_address() -> Result<Address, Box<dyn std::error::Error>> {
		Ok(Address {
			street: vec![
				faker::address::en::StreetName().fake(),
				faker::address::en::StreetSuffix().fake(),
			],
			city: faker::address::en::CityName().fake(),
			country: faker::address::en::CountryName().fake(),
			postal_code: faker::address::en::PostCode().fake(),
		})
	}

	pub fn _generate_block(id: u64, count: usize) -> Block {
		let mut transactions = Vec::with_capacity(count);
		for _ in 0..count {
			transactions.push(_generate_mail());
		}
		Block { id, transactions }
	}
}

#[cfg(all(feature = "std", feature = "tokio"))]
#[tokio::test]
async fn test_macro_integration_full() -> core::result::Result<(), Box<dyn core::error::Error>> {
	// Listener
	let listener = collect::TokioListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;

	// Channels
	let (error_tx, mut error_rx) = mpsc::channel(8);
	let (ok_tx, mut ok_rx) = mpsc::channel(8);

	// Server
	let server_handle = tb::server! {
		protocol collect::TokioListener: listener,
		channels: {
			error: error_tx.clone(),
			ok: ok_tx.clone()
		},
		policies: {
			with_collector_gate: policy::AcceptAllGate,
		},
		handle: |msg: Frame| async move {
			eprintln!("Server received (ignored) id={:?}", msg.metadata.id);
			None
		}
	};

	// Client
	let _client = tb::client! {
		connect collect::TokioListener: addr,
		policies: {
			gate: policy::AcceptAllGate,
			restart: policy::RestartLinearBackoff::default(),
		}
	};

	// No ok signals expected yet
	assert!(ok_rx.try_recv().is_err());
	// Ensure no unexpected errors
	assert!(error_rx.try_recv().is_err());

	server_handle.abort();
	Ok(())
}
