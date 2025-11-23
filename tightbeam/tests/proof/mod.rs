#![allow(dead_code)]

use std::sync::Arc;
use tightbeam::asn1::{Metadata, Version};
use tightbeam::error::Result;
use tightbeam::{encode, job, policy, worker, Frame, TightBeamError};
use tightbeam::trace::TraceCollector;
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

impl Default for LedgerState {
	fn default() -> Self {
		Self::Full(Null)
	}
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
pub fn extract_pubkey_from_matrix<M: MatrixLike>(
	matrix: &M,
	start_row: u8,
	start_col: u8,
) -> MatrixResult<LedgerPublicKey> {
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
			let mut next = Vec::with_capacity(level.len().div_ceil(2));
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

// Compute Merkle root for an epoch of frames
job! {
	name: ComputeEpochRootJob,
	fn run(epoch_frames: Vec<Frame>) -> Result<MerkleHash> {
		use tightbeam::crypto::hash::{Digest, Sha3_256};
		use tightbeam::der::Encode;

		if epoch_frames.is_empty() {
			return Err(TightBeamError::InvalidBody);
		}

		// Hash each frame in the epoch
		let mut hashes = Vec::with_capacity(epoch_frames.len());
		for frame in &epoch_frames {
			let frame_der = frame.to_der()?;
			let mut hasher = Sha3_256::new();
			hasher.update(&frame_der);
			let digest = hasher.finalize();

			let mut hash = [0u8; 32];
			hash.copy_from_slice(&digest[..32]);
			hashes.push(hash);
		}

		// Convert to OctetString sequence
		let mut items = Vec::with_capacity(hashes.len());
		for hash in hashes {
			items.push(asn1::OctetString::new(hash.to_vec())?);
		}

		// Compute Merkle root
		let sequence = HashSequence { items };
		let response = MerkleComputeRootJob::run(sequence);

		match response {
			MerkleResponse::Root(root) => octet_to_hash(&root),
			_ => Err(TightBeamError::InvalidBody),
		}
	}
}

// Verify a frame is part of an epoch using Merkle proof
job! {
	name: VerifyEpochMembershipJob,
	fn run(frame: Frame, merkle_path: Vec<MerkleHash>, expected_root: MerkleHash) -> Result<bool> {
		use tightbeam::crypto::hash::{Digest, Sha3_256};
		use tightbeam::der::Encode;

		// Hash the frame
		let frame_der = frame.to_der()?;
		let mut hasher = Sha3_256::new();
		hasher.update(&frame_der);
		let digest = hasher.finalize();

		let mut leaf_hash = [0u8; 32];
		leaf_hash.copy_from_slice(&digest[..32]);

		// Convert to OctetString
		let leaf = asn1::OctetString::new(leaf_hash.to_vec())?;

		// Convert path to OctetString sequence
		let mut path_items = Vec::with_capacity(merkle_path.len());
		for hash in merkle_path {
			path_items.push(asn1::OctetString::new(hash.to_vec())?);
		}

		// Verify the path
		let verify_request = MerkleVerifyPath {
			leaf,
			path: HashSequence { items: path_items },
		};

		let response = MerkleVerifyPathJob::run(verify_request);

		match response {
			MerkleResponse::Verified(computed_root) => {
				let computed = octet_to_hash(&computed_root)?;
				Ok(computed == expected_root)
			}
			_ => Ok(false),
		}
	}
}

worker! {
	name: MerkleWorker<MerkleRequest, MerkleResponse>,
	handle: |message, _trace| async move {
		match message {
			MerkleRequest::ComputeRoot(sequence) => MerkleComputeRootJob::run(sequence),
			MerkleRequest::VerifyPath(params) => MerkleVerifyPathJob::run(params),
		}
	}
}

#[cfg(test)]
mod tests {
	use rand_core::OsRng;
	use std::collections::HashMap;

	use super::*;

	use tightbeam::asn1::{AlgorithmIdentifier, OctetString};
	use tightbeam::cms::signed_data::SignerIdentifier;
	use tightbeam::crypto::hash::Sha3_256;
	use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use tightbeam::matrix::MatrixLike;
	use tightbeam::prelude::policy::PolicyConf;
	use tightbeam::DigestInfo;
	use tightbeam::{compose, decode, rwlock, servlet};

	#[cfg(feature = "tokio")]
	use tightbeam::transport::tcp::r#async::TokioListener as Listener;
	#[cfg(not(feature = "tokio"))]
	type Listener = TcpListener<std::net::TcpListener>;

	// A Genesis Key is known
	const GENESIS_KEY: [u8; 32] = tightbeam::hex!("9175e9c61095aaf899f687a7d50d566950ed8c706bce50e6400cdd62bc474e7d");
	const GENESIS_BLOCK: [u8; 2712] = tightbeam::hex!("30820a940a0102305f302702016702016502016e02016502017302016902017302012d02016202016c02016f02016302016b020101a431302f300b0609608648016503040208042000000000000000000000000000000000000000000000000000000000000000003082095202013002020082020102020200f202013002020082020102020200ee02013002020081020200f7020130020176020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02013002017d02013002017b020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02010202010302010f02014202014002013002020081020200f7020130020176020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02013002017d02013002017b020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02010202010302010f02014202014002013002020081020200f7020130020176020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02013002017d02013002017b020130020174020102020101020103020102020102020100020200ac020102020101020131020102020102020100020200e8020102020102020100020200ce020102020102020100020200b802010202010102010102010202010102011902010202010202010002020083020102020102020100020200b60201020201010201610201020201020201000202008502010202010102012d020102020101020157020102020102020100020200820201020201010201350201020201010201670201020201020201000202008002010202010102016c02010202010102013d02010202010102017b020102020101020143020102020102020100020200b3020102020102020100020200c9020102020102020100020200b0020102020102020100020200e802010202010102017e020102020102020100020200d1020102020102020100020200b1020102020102020100020200c002010202010102013d0201020201020201000202009302010202010102015e02010202010302010f020142020140a031302f300b060960864801650304020804207ab691bfe1eecccd96af4365ffd3806f54b18bd55ba872c7e9b28ffae5cf64faa181a43081a102010180410433bb8295cb8fc19c88ad0187dbbc3120f15bcd93682967bf91c41eb0c2d0e171d51143e6c3122bd586e995bbec5e6682e1939c2ace7d369351bbaa59e556aa34300b0609608648016503040208300a06082a8648ce3d04030204402bfa104a25151e50181cc56c07183789b5b9996de91457d76693e54d4303d1bb6400fe190161dce660a13c6b0243568959eebbe1c07722453dda8fbcbca33862");

	const USD: LedgerPublicKey = tightbeam::hex!("03ac31e8ceb8011983b661852d57823567806c3d7b43b3c9b0e87ed1b1c03d935e");
	const KEY_PUBLIC: LedgerPublicKey =
		tightbeam::hex!("0289f6f78e3bf63a847b3217a8f205ecb4f55abad95d4b3b3d9ca2d6b9a0f31461");
	const KEY_PRIVATE: [u8; 32] = tightbeam::hex!("093acfdf59fe9769b4aa2ea7ab5548239806e76b428decfc7408ffb4d6340165");
	const FUNDED_TEST_ACCOUNTS: [[u8; 32]; 3] = [
		tightbeam::hex!("b4925a8641325173191bdbd35e20ce152bed20734714eae858056d658077da84"),
		tightbeam::hex!("a5b93caf6bc960c50f50528f6a0845b702fb9dd9c75abffd2d647e3c65bc1a13"),
		tightbeam::hex!("25cd0bb6d564753cb8d7ffd894ba61acfa34477d95ae25330f79a16e8438bc9b"),
	];

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

	job! {
		name: ComputeGenesisBlockJob,
		fn run() -> Result<Frame> {
			let Ok(signing_key) = Secp256k1SigningKey::from_bytes(&GENESIS_KEY.into()) else {
				panic!("Unable to reconstruct genesis signing key")
			};

			// Create ledgers for each funded test account
			let mut genesis_balances = Vec::new();
			for account_private_key in &FUNDED_TEST_ACCOUNTS {
				// Create signing key from private key
				let Ok(account_signing_key) = Secp256k1SigningKey::from_bytes(&(*account_private_key).into()) else {
					panic!("Unable to create signing key for test account")
				};

				// Get the compressed public key
				let verifying_key = account_signing_key.verifying_key();
				let encoded = verifying_key.to_encoded_point(true);
				let bytes = encoded.as_bytes();
				let mut account_pubkey = [0u8; 33];
				account_pubkey.copy_from_slice(bytes);

				// Create balance entry for USD
				let balance_entry = BalanceEntry {
					pubkey: USD,
					balance: 1000000,
				};

				// Create ledger for this account
				let account_ledger = Ledger {
					entries: vec![USD],
					balances: vec![balance_entry],
				};

				// Add to genesis ledgers
				genesis_balances.push(account_ledger);
			}

			compose! {
				V2: id: b"genesis-block",
					order: 1,
					message: GeneralLedger {
						entries: genesis_balances,
					},
					frame_integrity: type Sha3_256,
					nonrepudiation<Secp256k1Signature, _>: &signing_key,
					previous_frame: DigestInfo {
						algorithm: AlgorithmIdentifier {
							oid: tightbeam::oids::HASH_SHA3_256,
							parameters: None,
						},
						digest: OctetString::new([0; 32])?
					}
			}
		}
	}

	// 538e0b06dc8f91e125660f582510f7edef7f0043fe452fe9950fd15f053bbde2
	servlet! {
		BFTLedgerServlet,
		protocol: Listener,
		policies: {
			with_collector_gate: [
				AssertAcceptedFunctions,
				AssertSufficientFunds
			],
		},
		config: {
			ledger_state: LedgerState,
			epoch_size: usize,
		},
		// workers: |config| {

		// },
		init: |_config| {
			// Ensure we have the ledger
			let ledger = LEDGERS();
			let Ok(mut ledger) = ledger.write() else {
				panic!("Unable to lock ledger")
			};

			// Compute the genesis block
			let genesis = ComputeGenesisBlockJob::run()?;
			let genesis_ledger: GeneralLedger = decode(&genesis.message)?;
			genesis_ledger.entries.iter().for_each(|account| {
				ledger.insert(account.entries[0], account.clone());
			});

			// Verify the genesis block matches the expected value
			if genesis.to_der()? != GENESIS_BLOCK {
				panic!("Genesis block mismatch");
			}

			// Initialize epoch with genesis block
			let epochs = EPOCHS();
			let Ok(mut epochs) = epochs.write() else {
				panic!("Unable to lock epochs")
			};
			epochs.push(genesis);

			println!("BFT Ledger initialized with genesis block");

			Ok(())
		},
		handle: |message, _trace, config| async move {
			// Add frame to current epoch
			let epochs = EPOCHS();
			let Ok(mut epochs) = epochs.write() else {
				return None;
			};

			epochs.push(message.clone());

			// Check if epoch is complete
			if epochs.len() % config.epoch_size == 0 {
				let epoch_number = epochs.len() / config.epoch_size;
				let epoch_start = (epoch_number - 1) * config.epoch_size;
				let epoch_frames = epochs[epoch_start..].to_vec();

				// Compute Merkle root for the epoch
				match ComputeEpochRootJob::run(epoch_frames) {
					Ok(root) => {
						println!("Epoch {} complete. Merkle root: {}", epoch_number, to_hex(&root));
						// TODO: Anchor to Bitcoin
					}
					Err(e) => {
						eprintln!("Failed to compute epoch root: {:?}", e);
					}
				}
			}

			Some(message)
		}
	}

	#[tokio::test]
	async fn test_basic() -> Result<()> {
		BFTLedgerServlet::start(
			Arc::new(TraceCollector::new()),
			Arc::new(BFTLedgerServletConf { ledger_state: Default::default(), epoch_size: 1000 }),
		).await?;

		Ok(())
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
			write!(&mut out, "{byte:02x}").unwrap();
		}
		out
	}

	#[test]
	fn test_random_secp_matrix_points() -> ::core::result::Result<(), Box<dyn std::error::Error>> {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		let sk_bytes = signing_key.to_bytes();
		println!("signing key hex: {}", to_hex(sk_bytes.as_slice()));

		let verifying_key = signing_key.verifying_key();
		let encoded = verifying_key.to_encoded_point(true);
		let bytes = encoded.as_bytes();
		let mut pubkey = [0u8; 33];
		pubkey.copy_from_slice(bytes);
		println!("compressed pubkey hex: {}", to_hex(&pubkey));

		let mut matrix = TestMatrix::new(8);
		map_pubkey_to_matrix(&pubkey, &mut matrix, 0, 0)?;

		let mut points = Vec::with_capacity(35);
		for row in 0..5 {
			for col in 0..7 {
				points.push((row, col, matrix.get(row, col)));
			}
		}
		println!("matrix points: {points:?}");

		let extracted = extract_pubkey_from_matrix(&matrix, 0, 0)?;
		assert_eq!(extracted, pubkey);
		Ok(())
	}
}
