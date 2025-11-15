//! ```text
//!     ╔════════════════════════════════════════════════════════════════╗
//!     ║                        T I G H T B E A M                       ║
//!     ║             Efficient Exchange-Compute Interconnect            ║
//!     ╚════════════════════════════════════════════════════════════════╝
//!
//!                              ┌─────────────┐
//!                              │   CLUSTER   │
//!                              │  Controller │
//!                              └──────┬──────┘
//!                                     │
//!                     ┌───────────────┼───────────────┐
//!                     │               │               │
//!               ┌─────▼─────┐    ┌────▼────┐    ┌─────▼─────┐
//!               │   HIVE    │    │  DRONE  │    │   HIVE    │
//!               │ Orchestr. │    │ Morpher │    │ Orchestr. │
//!               └─────┬─────┘    └────┬────┘    └────┬──────┘
//!                     │               │              │
//!          ┌──────────┼──────────┐    │    ┌─────────┼──────────┐
//!          │          │          │    │    │         │          │
//!     ┌────▼───┐  ┌───▼────┐ ┌───▼────▼────▼───┐ ┌───▼────┐ ┌───▼────┐
//!     │Servlet │  │Servlet │ │     Active      │ │Servlet │ │Servlet │
//!     │  :8001 │  │  :8002 │ │     Servlet     │ │  :8003 │ │  :8004 │
//!     └────┬───┘  └────┬───┘ └────────┬────────┘ └───┬────┘ └───┬────┘
//!          │           │              │              │          │
//!    ┌─────┴─────┬─────┴─────┬─────┬──┴──┬─────┬─────┴─────┬────┴┬─────┐
//!    │     │     │     │     │     │     │     │     │     │     │     │
//!  ┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐┌─▼──┐
//!  │Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr││Wrkr│
//!  └────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘
//! ┌──┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌──┐
//! │Wr││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││W││Wr│
//! └──┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└──┘
//!
//! ╔════════════════════════════════════════════════════════════════════════╗
//! ║   Protocol-Agnostic • Zero-Copy • Zero-Panic • ASN.1 DER • RustCrypto  ║
//! ╚════════════════════════════════════════════════════════════════════════╝
//!
//!         ┌──────────────────────────────────────────────────────┐
//!         │  🔐 Security Model: Sign-Then-Encrypt                │
//!         │  ├─ Hash:    Integrity verification on plaintext     │
//!         │  ├─ Sign:    Non-repudiation & authentication        │
//!         │  └─ Encrypt: Confidentiality of transmitted data     │
//!         └──────────────────────────────────────────────────────┘
//!
//!         ┌──────────────────────────────────────────────────────┐
//!         │  📦 Protocol Versions                                │
//!         │  ├─ V0: Basic metadata (id, order, hash)             │
//!         │  ├─ V1: Secure messaging (encryption + signature)    │
//!         │  └─ V2: Extended (priority, TTL, headers, chaining)  │
//!         └──────────────────────────────────────────────────────┘
//!
//!         ┌──────────────────────────────────────────────────────┐
//!         │  🕸️  Efficient Exchange-Compute Interconnect (EECI)  |
//!         │  ├─ Hives:    Multi-servlet orchestrators            │
//!         │  ├─ Drones:   Single-servlet morphers                │
//!         │  ├─ Servlets: Self-contained message processors      │
//!         │  └─ Cluster:  Centralized control & routing          │
//!         └──────────────────────────────────────────────────────┘
//!
//!         ┌──────────────────────────────────────────────────────┐
//!         │  ⚡ Features                                          │
//!         │  ├─ Protocol-agnostic transport layer                │
//!         │  ├─ Dynamic port allocation (OS-managed)             │
//!         │  ├─ Policy-driven message gates                      │
//!         │  ├─ Lifecycle management (start/stop/join)           │
//!         │  └─ Service discovery & health monitoring            │
//!         └──────────────────────────────────────────────────────┘
//!
//!    ┌────────────────────────────────────────────────────────────────┐
//!    │  Quick Start Example                                           │
//!    ├────────────────────────────────────────────────────────────────┤
//!    │  use tightbeam::{Message, Beamable, compose};                  │
//!    │  use tightbeam::der::Sequence;                                 │
//!    │                                                                │
//!    │  #[derive(Beamable, Clone, Debug, Sequence)]                   │
//!    │  struct MyMessage { value: u64 }                               │
//!    │                                                                │
//!    │  let frame = compose! {                                        │
//!    │      V0: id: "msg-001", order: 1, message: MyMessage { .. }    │
//!    │  }?;                                                           │
//!    │                                                                │
//!    │  let decode: MyMessage = tightbeam::decode(&frame.message)?;   │
//!    └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TightBeam Protocol
//!
//! A lightweight, versioned messaging protocol with cryptographic primitives
//! built on ASN.1 DER encoding.

// TODO Find a way
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub(crate) mod frame;
/// The Version is a fundamental constraint
pub(crate) mod version;

pub mod asn1;
pub mod constants;
pub mod core;
pub mod error;
pub mod flags;
pub mod helpers;
pub mod matrix;
pub mod oids;
pub mod prelude;
pub mod utils;

#[cfg(all(feature = "testing", feature = "std"))]
pub mod instrumentation;

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "colony")]
pub mod colony;
#[cfg(feature = "compress")]
pub mod compress;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "doc")]
pub mod doc;
#[cfg(feature = "builder")]
pub mod macros;
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "random")]
pub mod random;
#[cfg(feature = "router")]
pub mod router;
#[cfg(feature = "standards")]
pub mod standards;
#[cfg(feature = "transport")]
pub mod transport;
#[cfg(feature = "rayon")]
pub use rayon;
#[cfg(feature = "zeroize")]
pub use zeroize;

// Re-export
pub use asn1::*;
pub use cms;
pub use der;
pub use paste;
pub use pkcs12;
pub use spki;
pub use x509_cert as x509;

#[cfg(feature = "hex")]
pub use hex_literal::hex;
#[cfg(all(feature = "std", not(feature = "tokio")))]
pub use std::sync::mpsc;
#[cfg(feature = "time")]
pub use time;
#[cfg(feature = "tokio")]
pub use tokio::sync::mpsc;

pub use utils::{decode, encode};

#[cfg(feature = "derive")]
pub use tightbeam_derive::{Beamable, Errorizable, Flaggable};

extern crate self as tightbeam;

pub use crate::core::*;
pub use crate::error::TightBeamError;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(feature = "builder")]
tightbeam_derive::generate_builders!();

/// Secure bytes type
pub type ZeroizingBytes = zeroize::Zeroizing<Vec<u8>>;
pub type ZeroizingArray<const N: usize> = zeroize::Zeroizing<[u8; N]>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn frame_size_calc() -> Result<(), Box<dyn std::error::Error>> {
		use crate::asn1::*;
		use crate::cms::cert::IssuerAndSerialNumber;
		use crate::cms::compressed_data::CompressedData;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::enveloped_data::EncryptedContentInfo;
		use crate::cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier, SignerInfo};
		use crate::der::{Decode, Encode};
		use crate::oids::*;
		use crate::pkcs12::digest_info::DigestInfo;
		use crate::spki::AlgorithmIdentifier;
		use crate::x509::name::Name;
		use crate::x509::serial_number::SerialNumber;

		// Create a square matrix with all zeros (data length must equal n*n)
		let matrix_size: u8 = 16;
		let matrix = Asn1Matrix { n: matrix_size, data: vec![0; (matrix_size as usize) * (matrix_size as usize)] };

		// Create metadata with all optional fields
		let metadata = Metadata {
			id: vec![0; 16], // 16-byte ID
			order: 0,
			compactness: Some(CompressedData {
				version: CmsVersion::V0,
				compression_alg: AlgorithmIdentifier { oid: COMPRESSION_ZLIB, parameters: None },
				encap_content_info: EncapsulatedContentInfo {
					econtent_type: DATA,
					econtent: Some(der::Any::from_der(&der::asn1::OctetString::new(vec![0; 10])?.to_der()?)?),
				},
			}),
			integrity: Some(DigestInfo {
				algorithm: AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None },
				digest: der::asn1::OctetString::new(vec![0; 32])?,
			}),
			confidentiality: Some(EncryptedContentInfo {
				content_type: DATA,
				content_enc_alg: AlgorithmIdentifier { oid: COMPRESSION_ZLIB, parameters: None },
				encrypted_content: Some(der::asn1::OctetString::new(vec![0; 50])?),
			}),
			priority: Some(MessagePriority::Normal),
			lifetime: Some(3600),
			previous_frame: Some(DigestInfo {
				algorithm: AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None },
				digest: der::asn1::OctetString::new(vec![0; 32])?,
			}),
			matrix: Some(matrix),
		};

		// Create frame with empty message
		// Compile-time validation built into Frame: V3 must support matrix since metadata has matrix
		// This will fail to compile if V3 doesn't support matrix
		const _: () = {
			const VERSION: Version = Version::V3;
			const HAS_MATRIX: bool = true; // metadata has matrix
								  // Use Frame's built-in compile-time validation method
			let _ = [(); 1][!Frame::const_validate_version_fields(VERSION, HAS_MATRIX) as usize];
		};

		let frame = Frame {
			version: Version::V3,
			metadata,
			message: vec![], // empty message
			integrity: Some(DigestInfo {
				algorithm: AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None },
				digest: der::asn1::OctetString::new(vec![0; 32])?,
			}),
			nonrepudiation: Some(SignerInfo {
				version: CmsVersion::V1,
				sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
					issuer: Name::default(),
					serial_number: SerialNumber::new(&[0; 8])?,
				}),
				digest_alg: AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None },
				signed_attrs: None,
				signature_algorithm: AlgorithmIdentifier { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None },
				signature: der::asn1::OctetString::new(vec![0; 64])?,
				unsigned_attrs: None,
			}),
		};

		// Encode to DER
		let der_bytes = der::Encode::to_der(&frame)?;
		println!("DER-encoded frame size: {} bytes", der_bytes.len());
		assert!(!der_bytes.is_empty());
		Ok(())
	}
}
