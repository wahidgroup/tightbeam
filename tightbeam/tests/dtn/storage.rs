//! The frame storage and chain verification of the DTN tests.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::io::ErrorKind;
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
/// It shows that tightbeam frames persist and load back across network delays
/// with no custody transfer protocol.
///
/// Each frame is self-contained and chains to the previous frame through its
/// `previous_frame` hash, so a receiver verifies the path end to end without
/// trusting the intermediate hops.
pub struct FrameStore {
	storage_dir: PathBuf,
	frames: HashMap<FrameKey, Frame>,
}

/// The place of a frame in a [`FrameStore`]: its chain position and its id.
///
/// Two frames of one id at two chain positions take two places, so neither
/// overwrites the other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrameKey {
	/// The order of the frame, its position in the chain.
	order: u64,
	/// The metadata ID of the frame.
	id: Vec<u8>,
}

impl FrameKey {
	/// The place of `frame`.
	pub fn of(frame: &Frame) -> Self {
		let order = frame.metadata().order();
		let id = frame.metadata().id().to_owned();
		Self { order, id }
	}

	/// The file name of the frame on disk. The id is in hex, so each id names
	/// one file in the store.
	pub fn file_name(&self) -> String {
		let id: String = self.id.iter().map(|byte| format!("{byte:02x}")).collect();
		format!("{}-{id}.frame", self.order)
	}

	/// The place that the stem of a file name on disk names, if it names one.
	fn from_file_stem(stem: &str) -> Option<Self> {
		let (order, id) = stem.split_once('-')?;
		let order = order.parse().ok()?;
		let pairs = id.as_bytes().chunks_exact(2);
		if !pairs.remainder().is_empty() {
			return None;
		}

		let id = pairs.map(Self::hex_byte).collect::<Option<Vec<u8>>>()?;
		Some(Self { order, id })
	}

	/// The byte that two hex digits name.
	fn hex_byte(pair: &[u8]) -> Option<u8> {
		let digits = core::str::from_utf8(pair).ok()?;
		if !digits.bytes().all(|digit| digit.is_ascii_hexdigit()) {
			return None;
		}

		u8::from_str_radix(digits, 16).ok()
	}
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

	/// Writes `frame` to disk under its [`FrameKey`], keeps it in the memory
	/// cache, and returns the key.
	pub fn persist(&mut self, frame: Frame) -> Result<FrameKey, TightBeamError> {
		let key = FrameKey::of(&frame);
		let file_path = self.storage_dir.join(key.file_name());
		let frame_bytes = frame.to_der()?;

		std::fs::write(&file_path, &frame_bytes).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to write frame: {}", e)))
		})?;

		self.frames.insert(key.to_owned(), frame);
		Ok(key)
	}

	/// Retrieves the frame at `key` from the memory cache, or else from disk,
	/// and caches a frame it reads from disk.
	///
	/// # Errors
	///
	/// - [`TightBeamError::IoError`] -- the store holds no frame at `key`, or its file fails to read.
	/// - [`TightBeamError`] -- the file fails to decode as a frame.
	pub fn retrieve(&mut self, key: &FrameKey) -> Result<Frame, TightBeamError> {
		let frame = self.load(key)?.cloned();
		frame.ok_or_else(|| TightBeamError::IoError(ErrorKind::NotFound.into()))
	}

	/// Whether the store holds `frame` itself at its chain position.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the file at the place of the frame fails to read or to decode.
	pub fn holds(&mut self, frame: &Frame) -> Result<bool, TightBeamError> {
		let stored = self.load(&FrameKey::of(frame))?;
		Ok(stored == Some(frame))
	}

	/// Removes `frame` from disk and from the memory cache.
	///
	/// # Errors
	///
	/// - [`TightBeamError::IoError`] -- the file of the frame fails to delete.
	pub fn remove(&mut self, frame: &Frame) -> Result<(), TightBeamError> {
		let key = FrameKey::of(frame);
		std::fs::remove_file(self.storage_dir.join(key.file_name()))?;
		self.frames.remove(&key);

		Ok(())
	}

	/// The frame at `key`, from the memory cache or else from disk, when the
	/// store holds one. A frame that the store reads from disk enters the
	/// cache.
	fn load(&mut self, key: &FrameKey) -> Result<Option<&Frame>, TightBeamError> {
		if self.frames.contains_key(key) {
			return Ok(self.frames.get(key));
		}

		let file_path = self.storage_dir.join(key.file_name());
		let frame_bytes = match std::fs::read(&file_path) {
			Ok(frame_bytes) => frame_bytes,
			Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error.into()),
		};

		let frame = Frame::from_der(&frame_bytes)?;
		let cached = self.frames.entry(key.to_owned()).or_insert(frame);
		Ok(Some(&*cached))
	}

	/// Retrieves the frame whose SHA3-256 hash is `hash`. It searches the
	/// memory cache first, then every frame on disk.
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
			.find_map(|key| {
				self.retrieve(&key).ok().filter(|frame| {
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
	pub fn verify_chain(&self, frames: &[impl Borrow<Frame>]) -> Result<ChainVerdict, TightBeamError> {
		let broken_links: Vec<(usize, String)> = frames
			.iter()
			.enumerate()
			.skip(1) // The first frame starts the chain.
			.filter_map(|(i, frame)| {
				let prev_frame: &Frame = frames[i - 1].borrow();
				let prev_hash = prev_frame.to_der().ok().map(|bytes| Sha3_256::digest(&bytes))?;

				match frame.borrow().metadata().previous_frame() {
					Some(digest_info) if verify_digest(prev_hash, digest_info) => None,
					Some(_) => Some((i, "Hash mismatch".to_string())),
					None => Some((i, "Missing previous_frame".to_string())),
				}
			})
			.collect();

		let verified_count = frames.len() - broken_links.len();
		Ok(ChainVerdict { valid: broken_links.is_empty(), broken_links, verified_count })
	}

	/// Lists the key of every frame on disk.
	pub fn list_frames(&self) -> Result<Vec<FrameKey>, TightBeamError> {
		Ok(std::fs::read_dir(&self.storage_dir)?
			.filter_map(Result::ok)
			.filter_map(|entry| {
				let path = entry.path();
				(path.extension()?.to_str()? == "frame")
					.then(|| FrameKey::from_file_stem(path.file_stem()?.to_str()?))?
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
	use super::super::ordering::{Admission, OutOfOrderBuffer};
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

		let frame_key = store.persist(frame)?;
		assert_eq!(frame_key, FrameKey { order: 1, id: b"test-frame".to_vec() });

		let retrieved = store.retrieve(&frame_key)?;
		let retrieved_payload = DtnPayload::from_der(retrieved.message())?;
		assert_eq!(retrieved_payload.content.as_bytes(), b"test payload");

		store.clear()?;

		Ok(())
	}

	// The tests of `dtn/delay_tolerant.rs` cover `FrameStore::verify_chain`, on
	// a valid chain and on a chain with a wrong `previous_frame` hash.

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
			store.persist(frame.to_owned())?;

			// 2. Hand the frame to the order buffer, which holds it while it is out of order.
			let frames_to_process = order_buffer.insert(frame)?;
			if let Admission::Released(ordered_frames) = frames_to_process {
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

	/// The store keys each frame by its chain position as well as its id, so
	/// two frames of one id at two positions both stay on disk.
	#[test]
	fn a_store_keeps_two_frames_of_one_id_at_two_positions() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;
		let first = compose! {
			V0: id: "telemetry",
				order: 1,
				message: DtnPayload::new(b"first", "test", "test", 0)?
		}?;
		let second = compose! {
			V0: id: "telemetry",
				order: 2,
				message: DtnPayload::new(b"second", "test", "test", 0)?
		}?;

		store.persist(first.to_owned())?;
		store.persist(second)?;

		let mut reopened = FrameStore::new(root.node("store"))?;
		assert!(reopened.holds(&first)?);
		Ok(())
	}

	/// A frame at `order` under `id` that carries a test payload.
	fn frame_of(id: &[u8], order: u64) -> Frame {
		let payload = DtnPayload::new(b"payload", "test", "test", 0).expect("a short payload fits");
		let frame = compose! {
			V0: id: id,
				order: order,
				message: payload
		};

		frame.expect("a V0 frame with an order composes")
	}

	/// A frame whose id holds a path separator stays inside the store.
	#[test]
	fn a_frame_id_with_a_path_separator_stays_in_the_store() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;
		let frame = frame_of(b"../escape", 1);

		store.persist(frame.to_owned())?;

		let mut reopened = FrameStore::new(root.node("store"))?;
		assert!(reopened.holds(&frame)?);
		Ok(())
	}

	/// Two ids that differ in invalid UTF-8 take two places in the store.
	#[test]
	fn two_ids_that_differ_in_invalid_utf8_take_two_places() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;
		let first = frame_of(&[0xff], 1);
		store.persist(first.to_owned())?;
		store.persist(frame_of(&[0xfe], 1))?;

		let mut reopened = FrameStore::new(root.node("store"))?;
		assert!(reopened.holds(&first)?);
		Ok(())
	}

	/// A reopened store lists the key of each frame on disk.
	#[test]
	fn a_reopened_store_lists_the_key_of_each_frame() -> Result<(), TightBeamError> {
		let root = StorageRoot::create()?;
		let mut store = FrameStore::new(root.node("store"))?;
		let key = store.persist(frame_of(b"telemetry", 1))?;

		let reopened = FrameStore::new(root.node("store"))?;
		assert_eq!(reopened.list_frames()?, [key]);
		Ok(())
	}
}
