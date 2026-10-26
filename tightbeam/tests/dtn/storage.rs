//! The frame storage and chain verification of the DTN tests.

use std::collections::HashMap;
use std::path::PathBuf;
use tightbeam::asn1::{DigestInfo, Frame};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode, Sequence};
use tightbeam::random::{OsRng, RngCore};
use tightbeam::{Beamable, TightBeamError};

/// The DTN payload that the multi-hop tests carry.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct DtnPayload {
	/// The application bytes of the payload.
	pub content: OctetString,
	/// The identifier of the node that sent the payload.
	pub source_node: String,
	/// The identifier of the node the payload is for.
	pub dest_node: String,
	/// The number of hops the payload has crossed, which tracks its path.
	pub hop_count: u32,
}

impl DtnPayload {
	/// A payload of `content` that `source_node` sends to `dest_node`, after
	/// `hop_count` hops.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- `content` is longer than an OCTET STRING holds.
	pub fn new(
		content: impl Into<Vec<u8>>,
		source_node: impl Into<String>,
		dest_node: impl Into<String>,
		hop_count: u32,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			content: OctetString::new(content)?,
			source_node: source_node.into(),
			dest_node: dest_node.into(),
			hop_count,
		})
	}
}

/// The verdict of a cryptographic chain verification.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainVerdict {
	/// Whether every link of the chain verifies.
	pub valid: bool,
	/// The broken links, each as the frame index and an error message.
	pub broken_links: Vec<(usize, String)>,
	/// The number of frames minus the number of broken links. The first frame
	/// starts the chain and counts as verified.
	pub verified_count: usize,
}

/// The filesystem frame storage of the DTN simulation.
///
/// The store shows that tightbeam frames persist and load back across
/// network delays without a custody transfer protocol.
///
/// Each frame is self-contained and chains to the previous frame through its
/// `previous_frame` hash, so a receiver verifies the path end to end without
/// trusting the intermediate hops.
pub struct FrameStore {
	storage_dir: PathBuf,
	frames: HashMap<String, Frame>,
}

impl FrameStore {
	/// Creates a frame store over `storage_dir`, and creates the directory
	/// when it is absent.
	pub fn new(storage_dir: PathBuf) -> Result<Self, TightBeamError> {
		std::fs::create_dir_all(&storage_dir).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(
				e.kind(),
				format!("Failed to create storage directory: {}", e),
			))
		})?;

		Ok(Self { storage_dir, frames: HashMap::new() })
	}

	/// Writes `frame` to disk under its metadata ID, caches it in memory, and
	/// returns the ID.
	pub fn persist(&mut self, frame: &Frame) -> Result<String, TightBeamError> {
		let frame_id = String::from_utf8_lossy(frame.metadata().id()).to_string();
		let file_path = self.storage_dir.join(format!("{}.frame", frame_id));
		let frame_bytes = frame.to_der()?;

		std::fs::write(&file_path, &frame_bytes).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to write frame: {}", e)))
		})?;

		self.frames.insert(frame_id.to_owned(), frame.to_owned());
		Ok(frame_id)
	}

	/// Retrieves the frame with `id` from the memory cache, or else from disk,
	/// and caches a frame it reads from disk.
	pub fn retrieve(&mut self, id: impl AsRef<str>) -> Result<Frame, TightBeamError> {
		let id = id.as_ref();
		if let Some(frame) = self.frames.get(id) {
			return Ok(frame.to_owned());
		}

		let file_path = self.storage_dir.join(format!("{}.frame", id));
		let frame_bytes = std::fs::read(&file_path)?;
		let frame = Frame::from_der(&frame_bytes)?;

		self.frames.insert(id.to_string(), frame.to_owned());
		Ok(frame)
	}

	/// Retrieves the frame whose SHA3-256 hash is `hash`. The search reads the
	/// memory cache first, and then every frame on disk.
	pub fn retrieve_by_hash(&mut self, hash: impl AsRef<[u8]>) -> Result<Option<Frame>, TightBeamError> {
		let hash = hash.as_ref();
		let cached = self.frames.values().find_map(|frame| {
			frame
				.to_der()
				.ok()
				.filter(|bytes| Sha3_256::digest(bytes).as_slice() == hash)
				.map(|_| frame.to_owned())
		});

		if cached.is_some() {
			return Ok(cached);
		}

		self.list_frames()?
			.into_iter()
			.find_map(|id| {
				self.retrieve(&id).ok().filter(|frame| {
					frame
						.to_der()
						.ok()
						.map(|bytes| Sha3_256::digest(&bytes).as_slice() == hash)
						.unwrap_or(false)
				})
			})
			.map_or(Ok(None), |frame| Ok(Some(frame)))
	}

	/// Verifies the cryptographic chain of `frames`.
	///
	/// The `previous_frame` digest of each frame must match the SHA3-256 hash
	/// of the DER of the previous frame, which proves integrity without a
	/// trusted intermediary.
	pub fn verify_chain(&self, frames: impl AsRef<[Frame]>) -> Result<ChainVerdict, TightBeamError> {
		let frames = frames.as_ref();
		let broken_links: Vec<(usize, String)> = frames
			.iter()
			.enumerate()
			.skip(1) // The first frame starts the chain.
			.filter_map(|(i, frame)| {
				let prev_frame = &frames[i - 1];
				let prev_hash = prev_frame.to_der().ok().map(|bytes| Sha3_256::digest(&bytes))?;

				match frame.metadata().previous_frame() {
					Some(digest_info) if verify_digest(prev_hash, digest_info) => None,
					Some(_) => Some((i, "Hash mismatch".to_string())),
					None => Some((i, "Missing previous_frame".to_string())),
				}
			})
			.collect();

		let verified_count = frames.len() - broken_links.len();
		Ok(ChainVerdict { valid: broken_links.is_empty(), broken_links, verified_count })
	}

	/// Lists the ID of every frame on disk.
	pub fn list_frames(&self) -> Result<Vec<String>, TightBeamError> {
		Ok(std::fs::read_dir(&self.storage_dir)?
			.filter_map(Result::ok)
			.filter_map(|entry| {
				let path = entry.path();
				(path.extension()?.to_str()? == "frame").then(|| path.file_stem()?.to_str().map(String::from))?
			})
			.collect())
	}

	/// Removes every stored frame from the memory cache and from disk.
	pub fn clear(&mut self) -> Result<(), TightBeamError> {
		self.frames.clear();

		std::fs::read_dir(&self.storage_dir)?
			.filter_map(Result::ok)
			.map(|entry| entry.path())
			.filter(|path| path.extension().and_then(|s| s.to_str()) == Some("frame"))
			.try_for_each(std::fs::remove_file)?;

		Ok(())
	}
}

/// Whether `computed` matches the digest that `expected` carries.
fn verify_digest(computed: impl AsRef<[u8]>, expected: &DigestInfo) -> bool {
	let computed = computed.as_ref();
	computed == expected.digest.as_bytes()
}

/// A storage directory that one test owns alone.
///
/// Each [`FrameStore`] of a test sits under that test's root. The root's name
/// joins the process id and a random suffix, so two runs of the suite, or two
/// tests in one run, write into separate trees. Drop removes the tree.
pub struct StorageRoot {
	path: PathBuf,
}

impl StorageRoot {
	/// Creates an empty root under the system temporary directory.
	///
	/// # Errors
	///
	/// - [`TightBeamError::IoError`] -- the call fails to create the directory,
	///   as it does when a directory of that name exists.
	pub fn create() -> Result<Self, TightBeamError> {
		let suffix = OsRng.next_u64();
		let name = format!("tightbeam-dtn-{}-{suffix:016x}", std::process::id());
		let path = std::env::temp_dir().join(name);
		std::fs::create_dir(&path)?;

		Ok(Self { path })
	}

	/// The storage directory of the node `name`, inside this root.
	pub fn node(&self, name: impl AsRef<str>) -> PathBuf {
		self.path.join(name.as_ref())
	}
}

impl Drop for StorageRoot {
	fn drop(&mut self) {
		// Drop cannot return the fault, and a tree left behind is harmless,
		// because each test reads only the root it created.
		let _ = std::fs::remove_dir_all(&self.path);
	}
}

#[cfg(test)]
mod tests {
	use super::super::ordering::OutOfOrderBuffer;
	use super::*;
	use tightbeam::compose;

	#[test]
	fn frame_store_persist_retrieve() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;

		let payload = DtnPayload::new(b"test payload", "test", "test", 0)?;

		let frame = compose! {
			V0: id: "test-frame",
			order: 1,
			message: payload
		}?;

		let frame_id = store.persist(&frame)?;
		assert_eq!(frame_id, "test-frame");

		let retrieved = store.retrieve(&frame_id)?;
		let retrieved_payload = DtnPayload::from_der(retrieved.message())?;
		assert_eq!(retrieved_payload.content.as_bytes(), b"test payload");

		store.clear()?;

		Ok(())
	}

	// The tests of `dtn/delay_tolerant.rs` cover `FrameStore::verify_chain`.
	// A unit test of a valid chain here needs `DigestInfo::try_from`, which
	// the crate lacks.

	#[test]
	fn storage_ordering_consensus_integration() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;
		let mut order_buffer = OutOfOrderBuffer::new(10);

		// The five frames carry the orders 1 to 5.
		let mut frames = Vec::new();
		for i in 1..=5 {
			let payload = DtnPayload::new(format!("message-{}", i), "test", "test", 0)?;
			let frame = compose! {
				V0: id: format!("frame-{}", i),
				order: i,
				message: payload
			}?;

			frames.push(frame);
		}

		// The store receives the frames out of order: 1, 3, 2, 5, 4.
		let receive_order = [0usize, 2, 1, 4, 3]; // The entries index `frames`.
		let mut processed_frames = Vec::new();

		for &idx in &receive_order {
			let frame = frames[idx].to_owned();

			// 1. Persist the frame to storage.
			store.persist(&frame)?;

			// 2. Hand the frame to the order buffer, which holds it while it is out of order.
			let frames_to_process = order_buffer.insert(frame)?;
			if let Some(ordered_frames) = frames_to_process {
				// 3. Process the frames the buffer releases, in order.
				for ordered_frame in ordered_frames {
					processed_frames.push(ordered_frame);
				}
			}
		}

		// The buffer releases all five frames, in order.
		assert_eq!(processed_frames.len(), 5, "All 5 frames should be processed");
		for (i, frame) in processed_frames.iter().enumerate() {
			assert_eq!(
				frame.metadata().order(),
				(i + 1) as u64,
				"Frame {} should have order {}",
				i,
				i + 1
			);
		}

		// The store holds all five frames.
		let stored_frames = store.list_frames()?;
		assert_eq!(stored_frames.len(), 5, "All 5 frames should be stored");

		store.clear()?;

		Ok(())
	}
}
