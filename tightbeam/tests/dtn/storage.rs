//! Frame storage and chain verification utilities for DTN testing

use std::collections::HashMap;
use std::path::PathBuf;
use tightbeam::asn1::Frame;
use tightbeam::der::Decode;
use tightbeam::pkcs12::digest_info::DigestInfo;
use tightbeam::TightBeamError;

/// Verdict from cryptographic chain verification
#[derive(Debug, Clone, PartialEq)]
pub struct ChainVerdict {
	/// Whether the chain is valid
	pub valid: bool,
	/// Broken links: (frame_index, error_message)
	pub broken_links: Vec<(usize, String)>,
	/// Number of successfully verified frames
	pub verified_count: usize,
}

/// Filesystem-based frame storage for DTN simulation
///
/// Demonstrates that tightbeam frames can be persisted and retrieved
/// across network delays without requiring custody transfer protocols.
///
/// Each frame is self-contained and cryptographically chained via
/// `previous_frame` hash, enabling end-to-end verification without
/// trusting intermediate hops.
pub struct FrameStore {
	storage_dir: PathBuf,
	frames: HashMap<String, Frame>,
}

impl FrameStore {
	/// Create new frame store with given storage directory
	pub fn new(storage_dir: PathBuf) -> Result<Self, TightBeamError> {
		std::fs::create_dir_all(&storage_dir).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(
				e.kind(),
				format!("Failed to create storage directory: {}", e),
			))
		})?;

		Ok(Self { storage_dir, frames: HashMap::new() })
	}

	/// Persist a frame to storage and return its ID
	pub fn persist(&mut self, frame: &Frame) -> Result<String, TightBeamError> {
		use tightbeam::der::Encode;

		// Use frame metadata ID from frame metadata
		let frame_id = String::from_utf8_lossy(&frame.metadata.id).to_string();

		// Write to disk
		let file_path = self.storage_dir.join(format!("{}.frame", frame_id));
		let frame_bytes = frame.to_der()?;
		std::fs::write(&file_path, &frame_bytes).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to write frame: {}", e)))
		})?;

		// Cache in memory
		self.frames.insert(frame_id.clone(), frame.clone());

		Ok(frame_id)
	}

	/// Retrieve a frame by its ID
	pub fn retrieve(&mut self, id: &str) -> Result<Frame, TightBeamError> {
		// Check memory cache first
		if let Some(frame) = self.frames.get(id) {
			return Ok(frame.clone());
		}

		// Read from disk
		let file_path = self.storage_dir.join(format!("{}.frame", id));
		let frame_bytes = std::fs::read(&file_path).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to read frame: {}", e)))
		})?;

		let frame = Frame::from_der(&frame_bytes)?;

		// Cache for future retrievals
		self.frames.insert(id.to_string(), frame.clone());

		Ok(frame)
	}

	/// Verify cryptographic chain of frames
	///
	/// Validates that each frame's `previous_frame` hash matches the
	/// actual hash of the previous frame, proving integrity without
	/// requiring trusted intermediaries.
	pub fn verify_chain(&self, frames: &[Frame]) -> Result<ChainVerdict, TightBeamError> {
		use tightbeam::crypto::hash::{Digest, Sha3_256};
		use tightbeam::der::Encode;

		let mut verdict = ChainVerdict { valid: true, broken_links: Vec::new(), verified_count: 0 };

		for (i, frame) in frames.iter().enumerate() {
			if i == 0 {
				// First frame has no previous
				verdict.verified_count += 1;
				continue;
			}

			let prev_frame = &frames[i - 1];
			let prev_bytes = prev_frame.to_der()?;
			let prev_hash = Sha3_256::digest(&prev_bytes);

			// Check if current frame references previous frame
			let expected_digest = frame.metadata.previous_frame.as_ref();

			match expected_digest {
				Some(digest_info) => {
					if verify_digest(&prev_hash, digest_info) {
						verdict.verified_count += 1;
					} else {
						verdict.valid = false;
						verdict.broken_links.push((i, "Hash mismatch".to_string()));
					}
				}
				None => {
					verdict.valid = false;
					verdict.broken_links.push((i, "Missing previous_frame".to_string()));
				}
			}
		}

		Ok(verdict)
	}

	/// List all stored frame IDs
	pub fn list_frames(&self) -> Result<Vec<String>, TightBeamError> {
		let mut frame_ids = Vec::new();

		let entries = std::fs::read_dir(&self.storage_dir).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to read directory: {}", e)))
		})?;

		for entry in entries {
			let entry = entry.map_err(|e| {
				TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to read directory entry: {}", e)))
			})?;
			let path = entry.path();

			if path.extension().and_then(|s| s.to_str()) == Some("frame") {
				if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
					frame_ids.push(stem.to_string());
				}
			}
		}

		Ok(frame_ids)
	}

	/// Clear all stored frames
	pub fn clear(&mut self) -> Result<(), TightBeamError> {
		self.frames.clear();

		let entries = std::fs::read_dir(&self.storage_dir).map_err(|e| {
			TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to read directory: {}", e)))
		})?;

		for entry in entries {
			let entry = entry.map_err(|e| {
				TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to read directory entry: {}", e)))
			})?;
			let path = entry.path();

			if path.extension().and_then(|s| s.to_str()) == Some("frame") {
				std::fs::remove_file(&path).map_err(|e| {
					TightBeamError::IoError(std::io::Error::new(e.kind(), format!("Failed to remove file: {}", e)))
				})?;
			}
		}

		Ok(())
	}
}

/// Verify that a computed hash matches the expected DigestInfo
fn verify_digest(computed: &[u8], expected: &DigestInfo) -> bool {
	computed == expected.digest.as_bytes()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dtn::types::DtnPayload;
	use tightbeam::compose;

	#[test]
	fn frame_store_persist_retrieve() -> Result<(), TightBeamError> {
		let temp_dir = std::env::temp_dir().join("tightbeam_dtn_test");
		let mut store = FrameStore::new(temp_dir.clone())?;

		// Create test frame
		let payload = DtnPayload {
			content: b"test payload".to_vec(),
			source_node: "test".to_string(),
			dest_node: "test".to_string(),
			hop_count: 0,
		};

		let frame = compose! {
			V0: id: "test-frame",
			order: 1,
			message: payload
		}?;

		// Persist
		let frame_id = store.persist(&frame)?;
		assert_eq!(frame_id, "test-frame");

		// Retrieve
		let retrieved = store.retrieve(&frame_id)?;
		let retrieved_payload = DtnPayload::from_der(retrieved.message.as_slice())?;
		assert_eq!(retrieved_payload.content, b"test payload");

		// Cleanup
		store.clear()?;
		std::fs::remove_dir_all(temp_dir)?;

		Ok(())
	}

	#[test]
	fn chain_verification_valid() -> Result<(), TightBeamError> {
		use tightbeam::crypto::hash::{Digest, Sha3_256};
		use tightbeam::der::Encode;

		let temp_dir = std::env::temp_dir().join("tightbeam_chain_test");
		let store = FrameStore::new(temp_dir.clone())?;

		// Create chain of 3 frames
		let frame1 = compose! {
			V0: id: "frame-1",
			order: 1,
			message: b"first".to_vec()
		}?;

		// Frame 2 references frame 1
		let frame1_bytes = frame1.to_der()?;
		let frame1_hash = Sha3_256::digest(&frame1_bytes);
		let digest_info = DigestInfo::try_from(frame1_hash.as_slice())?;

		let frame2 = compose! {
			V0: id: "frame-2",
			order: 2,
			previous_frame: digest_info.clone(),
			message: b"second".to_vec()
		}?;

		// Frame 3 references frame 2
		let frame2_bytes = frame2.to_der()?;
		let frame2_hash = Sha3_256::digest(&frame2_bytes);
		let digest_info2 = DigestInfo::try_from(frame2_hash.as_slice())?;

		let frame3 = compose! {
			V0: id: "frame-3",
			order: 3,
			previous_frame: digest_info2,
			message: b"third".to_vec()
		}?;

		let frames = vec![frame1, frame2, frame3];

		// Verify chain
		let verdict = store.verify_chain(&frames)?;
		assert!(verdict.valid);
		assert_eq!(verdict.verified_count, 3);
		assert!(verdict.broken_links.is_empty());

		// Cleanup
		std::fs::remove_dir_all(temp_dir)?;

		Ok(())
	}
}
