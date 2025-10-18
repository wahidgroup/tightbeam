use tightbeam::asn1::{Metadata, Version};
use tightbeam::error::Result;
use tightbeam::{encode, job, policy, worker, Frame, TightBeamError};
use tightbeam::{prelude::*, Null};

/// Compressed public key (33 bytes)
type LedgerPublicKey = [u8; 33];

/// Result type for ledger operations
type LedgerResult<T> = ::core::result::Result<T, LedgerError>;

type MerkleComputeRootRequest = HashSequence;
type MerkleVerifyPathRequest = MerkleVerifyPath;
type MerkleHash = [u8; 32];

#[derive(Clone, Debug, Default)]
struct MerkleState;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct MerkleVerifyPath {
	pub leaf: asn1::OctetString,
	pub path: HashSequence,
}

/// Sequence of hashes for Merkle tree operations
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct HashSequence {
	pub items: Vec<asn1::OctetString>,
}

/// Request types for Merkle tree operations
#[derive(Beamable, Clone, Debug, PartialEq, Eq, asn1::Choice)]
enum MerkleRequest {
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
	ComputeRoot(HashSequence),

	#[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
	VerifyPath(MerkleVerifyPath),
}

/// Response types for Merkle tree operations
#[derive(Clone, Debug, PartialEq, Eq, asn1::Choice)]
pub enum MerkleResponse {
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
	Root(asn1::OctetString),

	#[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
	Verified(asn1::OctetString),

	#[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
	InvalidEmptySequence(asn1::Null),

	#[asn1(context_specific = "3", tag_mode = "IMPLICIT")]
	InvalidLeafLength(asn1::Null),

	#[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
	InvalidSiblingLength(asn1::Null),

	#[asn1(context_specific = "5", tag_mode = "IMPLICIT")]
	InvalidEncoding(asn1::Null),
}

#[derive(asn1::Enumerated, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum LedgerError {
	DuplicateKeys = 0,
	CountMismatch = 1,
	PubkeyFormat = 2,
	PubkeyMismatch = 3,
}

#[derive(asn1::Choice, Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerState {
	/// Full ledger
	Full(Null),
	// Number of epochs to maintain
	Last(u64),
}

/// A key-value balance entry in the ledger
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct BalanceEntry {
	/// Compressed public key of an asset
	pub pubkey: LedgerPublicKey,
	/// Account balance
	pub balance: u64,
}

/// A ledger containing local account balances
#[derive(Beamable, Default, Clone, Debug, PartialEq, Eq, Sequence)]
struct Ledger {
	pub entries: Vec<LedgerPublicKey>,
	pub balances: Vec<BalanceEntry>,
}

/// General Ledger message containing account balances
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(nonrepudiable, frame_integrity, min_version = "V1")]
struct GeneralLedger {
	/// Vector of balance entries
	pub entries: Vec<Ledger>,
}

#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(nonrepudiable, frame_integrity, min_version = "V1")]
struct Transaction {
	pub to: LedgerPublicKey,
	pub asset: LedgerPublicKey,
	pub amount: u64,
}

fn octet_to_hash(value: &asn1::OctetString) -> Result<MerkleHash> {
	let bytes = value.as_bytes();
	if bytes.len() != 32 {
		return Err(TightBeamError::InvalidBody);
	}

	let mut hash = [0u8; 32];
	hash.copy_from_slice(bytes);
	Ok(hash)
}

fn hash_to_octet(hash: &MerkleHash) -> Result<asn1::OctetString> {
	asn1::OctetString::new(hash.as_slice().to_vec()).map_err(|_| TightBeamError::InvalidBody)
}

fn build_merkle_frame(id: &[u8], order: u64, response: MerkleResponse) -> Result<Frame> {
	let metadata = Metadata {
		id: id.to_vec(),
		order,
		compactness: None,
		integrity: None,
		confidentiality: None,
		priority: None,
		lifetime: None,
		previous_frame: None,
		matrix: None,
	};

	let message = encode(&response)?;

	Ok(Frame { version: Version::V0, metadata, message, integrity: None, nonrepudiation: None })
}

/// Maps a compressed public key (33 bytes) to a region of the matrix
///
/// Requires a 5x7 region (35 cells) to store a 33-byte compressed public key
///
/// # Arguments
/// * `pubkey` - Compressed public key (33 bytes)
/// * `matrix` - Any matrix implementing the MatrixLike trait
/// * `start_row` - Starting row for mapping
/// * `start_col` - Starting column for mapping
///
/// # Errors
/// Returns MatrixError::OutOfBounds if the region would extend beyond matrix bounds
pub fn map_pubkey_to_matrix<M: MatrixLike>(
	pubkey: &LedgerPublicKey,
	matrix: &mut M,
	start_row: u8,
	start_col: u8,
) -> MatrixResult<()> {
	// Ensure the target region fits within matrix bounds
	let n = matrix.n();
	if start_row + 5 > n || start_col + 7 > n {
		return Err(MatrixError::LengthMismatch { n, len: ((start_row + 5) * (start_col + 7)) as usize });
	}

	// Convert 33-byte pubkey to 5x7 matrix region (35 cells)
	// Each cell is u8 (0-255)
	let mut idx = 0;
	for row_offset in 0..5 {
		for col_offset in 0..7 {
			if idx < 33 {
				// Map byte directly
				matrix.set(start_row + row_offset, start_col + col_offset, pubkey[idx]);
				idx += 1;
			} else {
				// Fill remaining cells with zeros
				matrix.set(start_row + row_offset, start_col + col_offset, 0);
			}
		}
	}

	Ok(())
}

/// Extracts a compressed public key from a region of the matrix
///
/// # Arguments
/// * `matrix` - Any matrix implementing the MatrixLike trait
/// * `start_row` - Starting row for extraction
/// * `start_col` - Starting column for extraction
///
/// # Errors
/// Returns MatrixError::OutOfBounds if the region would extend beyond matrix bounds
pub fn extract_pubkey_from_matrix<M: MatrixLike>(matrix: &M, start_row: u8, start_col: u8) -> MatrixResult<LedgerPublicKey> {
	// Ensure the target region fits within matrix bounds
	let n = matrix.n();
	if start_row + 5 > n || start_col + 7 > n {
		return Err(MatrixError::LengthMismatch { n, len: ((start_row + 5) * (start_col + 7)) as usize });
	}

	// Extract 33-byte pubkey from 5x7 matrix region
	let mut pubkey = [0u8; 33];
	let mut idx = 0;
	for row_offset in 0..5 {
		for col_offset in 0..7 {
			if idx < 33 {
				pubkey[idx] = matrix.get(start_row + row_offset, start_col + col_offset);
				idx += 1;
			}
		}
	}

	Ok(pubkey)
}
job! {
	name: MerkleComputeRootJob,
	fn run(sequence: MerkleComputeRootRequest) -> MerkleResponse {
		use tightbeam::crypto::hash::{Digest, Sha3_256};

		if sequence.items.is_empty() {
			return MerkleResponse::InvalidEmptySequence(asn1::Null);
		}

		let mut level = Vec::with_capacity(sequence.items.len());
		for item in &sequence.items {
			match octet_to_hash(item) {
				Ok(hash) => level.push(hash),
				Err(_) => return MerkleResponse::InvalidLeafLength(asn1::Null),
			}
		}

		while level.len() > 1 {
			let mut next = Vec::with_capacity((level.len() + 1) / 2);
			for chunk in level.chunks(2) {
				let left = chunk[0];
				let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };

				let mut hasher = Sha3_256::new();
				hasher.update(left);
				hasher.update(right);
				let digest = hasher.finalize();

				let mut combined = [0u8; 32];
				combined.copy_from_slice(&digest[..32]);
				next.push(combined);
			}
			level = next;
		}

		match hash_to_octet(&level[0]) {
			Ok(root) => MerkleResponse::Root(root),
			Err(_) => MerkleResponse::InvalidEncoding(asn1::Null),
		}
	}
}

job! {
	name: MerkleVerifyPathJob,
	fn run(params: MerkleVerifyPathRequest) -> MerkleResponse {
		use tightbeam::crypto::hash::{Digest, Sha3_256};

		let mut current = match octet_to_hash(&params.leaf) {
			Ok(hash) => hash,
			Err(_) => return MerkleResponse::InvalidLeafLength(asn1::Null),
		};

		for sibling in &params.path.items {
			let sibling_hash = match octet_to_hash(sibling) {
				Ok(hash) => hash,
				Err(_) => return MerkleResponse::InvalidSiblingLength(asn1::Null),
			};

			let mut hasher = Sha3_256::new();
			hasher.update(current);
			hasher.update(sibling_hash);
			let digest = hasher.finalize();

			current.copy_from_slice(&digest[..32]);
		}

		match hash_to_octet(&current) {
			Ok(octet) => MerkleResponse::Verified(octet),
			Err(_) => MerkleResponse::InvalidEncoding(asn1::Null),
		}
	}
}

job! {
	name: LedgerStateJob,
	fn run(ledger: Ledger) -> LedgerResult<()> {
		if ledger.entries.len() != ledger.balances.len() {
			return Err(LedgerError::CountMismatch);
		}

		let mut seen = Vec::with_capacity(ledger.entries.len());
		for (index, pubkey) in ledger.entries.iter().enumerate() {
			if seen.iter().any(|existing| existing == pubkey) {
				return Err(LedgerError::DuplicateKeys);
			}

			seen.push(*pubkey);

			let entry = &ledger.balances[index];
			let bytes = entry.pubkey;
			if bytes.len() != 33 {
				return Err(LedgerError::PubkeyFormat);
			}

			if &bytes != pubkey {
				return Err(LedgerError::PubkeyMismatch);
			}
		}

		Ok(())
	}
}

worker! {
	name: MerkleWorker<MerkleRequest, MerkleResponse>,
	handle: |message| async move {
		Ok(match message {
			MerkleRequest::ComputeRoot(sequence) => MerkleComputeRootJob::run(sequence),
			MerkleRequest::VerifyPath(params) => MerkleVerifyPathJob::run(params),
		})
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use rand_core::OsRng;

	use super::*;

	use tightbeam::cms::signed_data::SignerIdentifier;
	use tightbeam::crypto::hash::{Digest, Sha3_256};
	use tightbeam::crypto::sign::ecdsa::k256::elliptic_curve::sec1::ToEncodedPoint;
	use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	use tightbeam::matrix::MatrixLike;
	use tightbeam::policy::TransitStatus;
	use tightbeam::prelude::policy::PolicyConf;
	use tightbeam::{rwlock, servlet};

	#[cfg(feature = "tokio")]
	use tightbeam::transport::tcp::r#async::TokioListener as Listener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = TcpListener<std::net::TcpListener>;

	const KEY_PUBLIC: LedgerPublicKey = tightbeam::hex!("0289f6f78e3bf63a847b3217a8f205ecb4f55abad95d4b3b3d9ca2d6b9a0f31461");
	const KEY_PRIVATE: [u8; 32] = tightbeam::hex!("093acfdf59fe9769b4aa2ea7ab5548239806e76b428decfc7408ffb4d6340165");

	rwlock! {
		EPOCHS: Vec<Frame> = Vec::new(),
		LEDGERS: HashMap<LedgerPublicKey, Ledger> = HashMap::new(),
		FUNCS: HashMap<LedgerPublicKey, Vec<u8>> = HashMap::new(),
	}

	policy! {
		GatePolicy: AssertAcceptedFunctions |frame| {
			// Ensure we have the ledger
			let ledger = LEDGERS();
			let Ok(ledger) = ledger.read() else {
				return policy::TransitStatus::Forbidden
			};

			// Ensure the frame's matrix is an accepted function
			let Some(matrix) = frame.metadata.matrix.as_ref() else {
				return policy::TransitStatus::Forbidden
			};

			// Determine position in reality
			let Ok(matrix) = MatrixDyn::try_from(matrix) else {
				return policy::TransitStatus::Forbidden
			};

			// Extract the public key from the position
			let Ok(function) = extract_pubkey_from_matrix(&matrix, 0, 0) else {
				return policy::TransitStatus::Forbidden
			};

			// Ensure the function is supported
			if !ledger.contains_key(&function) {
				return policy::TransitStatus::Forbidden;
			}

			policy::TransitStatus::Accepted
		}
	}

	// Fast accept/eventual reject
	policy! {
		GatePolicy: AssertSufficientFunds |frame| {
			// Ensure we have the ledger
			let ledger = LEDGERS();
			let Ok(ledger) = ledger.read() else {
				return policy::TransitStatus::Forbidden
			};

			// Decode the message and extract the sender's public key
			let Ok(decoded) = tightbeam::decode::<Transaction>(&frame.message) else {
				return policy::TransitStatus::Forbidden
			};

			// Ensure the sender has sufficient funds to cover the transaction
			let Some(ref sender) = frame.nonrepudiation else {
				return policy::TransitStatus::Forbidden;
			};

            // Extract the public key from the signer info
			let public_key_bytes = match &sender.sid {
				SignerIdentifier::SubjectKeyIdentifier(ski) => {
					ski.0.as_bytes().to_vec()
				}
				SignerIdentifier::IssuerAndSerialNumber(_) => {
					return policy::TransitStatus::Forbidden;
				}
			};

			// Convert slice to array
			let public_key: LedgerPublicKey = match public_key_bytes.try_into() {
				Ok(arr) => arr,
				Err(_) => return policy::TransitStatus::Forbidden,
			};

            // Ensure the sender is in the ledger
			let Some(sender_ledger) = ledger.get(&public_key) else {
				return policy::TransitStatus::Forbidden;
			};

            // Get the sender's balance for the asset
            let Some(sender_balance) = sender_ledger.balances.iter().find(|entry| entry.pubkey == decoded.asset) else {
				return policy::TransitStatus::Forbidden;
			};

            // Ensure the sender has sufficient funds
			if sender_balance.balance < decoded.amount {
				return policy::TransitStatus::Unauthorized;
			}

			let asset = decoded.asset;
			let amount = decoded.amount;

			policy::TransitStatus::Accepted
		}
	}

	// 538e0b06dc8f91e125660f582510f7edef7f0043fe452fe9950fd15f053bbde2
	servlet! {
		name: TransactionServlet,
		protocol: Listener,
		policies: {
			with_collector_gate: [
				AssertAcceptedFunctions,
				AssertSufficientFunds
			],
		},
		config: {
			ledger_state: LedgerState,
		},
		workers: |config| {

		},
		init: |config| {

		},
		handle: |message, _config, workers| async move {

		}
	}

	struct TestMatrix {
		n: u8,
		data: Vec<u8>,
	}

	impl TestMatrix {
		fn new(n: u8) -> Self {
			Self { n, data: vec![0; (n as usize) * (n as usize)] }
		}

		fn idx(&self, row: u8, col: u8) -> usize {
			(row as usize * self.n as usize) + col as usize
		}
	}

	impl MatrixLike for TestMatrix {
		fn n(&self) -> u8 {
			self.n
		}

		fn get(&self, row: u8, col: u8) -> u8 {
			self.data[self.idx(row, col)]
		}

		fn set(&mut self, row: u8, col: u8, value: u8) {
			let idx = self.idx(row, col);
			self.data[idx] = value;
		}

		fn fill(&mut self, value: u8) {
			for b in &mut self.data {
				*b = value;
			}
		}
	}

	fn to_hex(bytes: &[u8]) -> String {
		use core::fmt::Write;
		let mut out = String::with_capacity(bytes.len() * 2);
		for byte in bytes {
			write!(&mut out, "{:02x}", byte).unwrap();
		}
		out
	}

	#[test]
	fn test_seeded_secp_matrix_points() {
		// Signing key
		let signing_key = Secp256k1SigningKey::from_slice(&KEY_PRIVATE).expect("valid private key");
		println!("signing key hex: {}", to_hex(&KEY_PRIVATE));
		// Verifying Key
		let verifying_key = signing_key.verifying_key();
		let encoded = verifying_key.to_encoded_point(true);
		let derived_pub = encoded.as_bytes();
		assert_eq!(derived_pub, KEY_PUBLIC.as_slice());
		println!("compressed pubkey hex: {}", to_hex(&KEY_PUBLIC));

		let mut matrix = TestMatrix::new(8);
		map_pubkey_to_matrix(&KEY_PUBLIC, &mut matrix, 0, 0).unwrap();

		let mut points = Vec::with_capacity(35);
		let mut matrix_hash = Sha3_256::new();
		for row in 0..5 {
			for col in 0..7 {
				let value = matrix.get(row, col);
				points.push((row, col, value));
				matrix_hash.update([row, col, value]);
			}
		}
		println!("matrix points: {:?}", points);

		let digest = matrix_hash.finalize();
		let matrix_hash_bytes: [u8; 32] = digest.into();

		// Address of contract
		println!("matrix hash hex: {}", to_hex(&matrix_hash_bytes));

		let extracted = extract_pubkey_from_matrix(&matrix, 0, 0).unwrap();
		assert_eq!(extracted, KEY_PUBLIC);
	}
}
