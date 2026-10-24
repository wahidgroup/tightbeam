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
//!         │  ├─ V0: Core metadata (id, order, message)           │
//!         │  ├─ V1: + integrity, confidentiality, signature      │
//!         │  ├─ V2: + priority, TTL, previous_frame chaining     │
//!         │  └─ V3: + matrix control                             │
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
//!    │  let decode: MyMessage = tightbeam::decode(frame.message())?;  │
//!    └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TightBeam Protocol
//!
//! TightBeam is a lightweight, versioned messaging protocol with cryptographic
//! primitives, built on ASN.1 DER encoding.

#![deny(unsafe_code)]
// Zero-panic: the crate denies raw `unwrap()` everywhere, tests included.
#![deny(clippy::unwrap_used)]
#![cfg_attr(
	not(test),
	deny(
		clippy::expect_used,
		clippy::panic,
		clippy::unreachable,
		clippy::todo,
		clippy::unimplemented
	)
)]
#![cfg_attr(test, allow(clippy::clone_on_ref_ptr))]
// The workspace denies an index or an integer operation that can panic. Tests
// are exempt from both, as they are from `expect`.
#![cfg_attr(test, allow(clippy::indexing_slicing, clippy::arithmetic_side_effects))]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("features.md")]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), feature = "zeroize"))]
use alloc::vec::Vec;

mod wire;

// This module compiles every README example as a doctest, so a renamed item
// fails the build instead of leaving the README stale.
#[cfg(doctest)]
#[doc = include_str!("../../README.md")]
mod readme {}

// `compose!` is in textual scope for every module declared after this one.
#[cfg(feature = "builder")]
#[macro_use]
mod compose;

pub(crate) mod frame;
pub(crate) mod version;

pub mod asn1;
pub mod constants;
pub mod core;
pub mod error;
pub mod flags;
pub mod helpers;
pub mod macros;
pub mod matrix;
pub mod oids;
pub mod prelude;
pub mod urn;
pub mod utils;

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "colony")]
pub mod colony;
#[cfg(feature = "compress")]
pub mod compress;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "std")]
pub mod instrumentation;
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "random")]
pub mod random;
#[cfg(feature = "router")]
pub mod router;
#[cfg(feature = "std")]
pub mod runtime;
#[cfg(feature = "standards")]
pub mod standards;
#[cfg(feature = "std")]
pub mod trace;
#[cfg(feature = "transport")]
pub mod transport;
#[cfg(feature = "zeroize")]
pub use zeroize;

pub use asn1::{
	AlgorithmIdentifier, CompressedData, DigestInfo, EncryptedContentInfo, Frame, MessagePriority, Metadata,
	ObjectIdentifier, SignerInfo, Version,
};
pub use cms;
pub use der;
pub use pkcs12;
pub use spki;
pub use utils::{decode, encode};

#[doc(hidden)]
pub use paste;

pub use tightbeam_derive::Errorizable;

#[cfg(feature = "hex")]
pub use hex_literal::hex;
pub use tightbeam_derive::{Beamable, Flaggable};
#[cfg(feature = "time")]
pub use time;
#[cfg(feature = "x509")]
pub use x509_cert as x509;

/// Multi-producer, single-consumer channel endpoints for the compiled runtime.
#[cfg(feature = "std")]
pub mod mpsc {
	pub use crate::runtime::rt::{channel, Receiver, Sender};
}

extern crate self as tightbeam;

pub use crate::core::Message;
pub use crate::error::TightBeamError;

#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub use crate::crypto::sign::ecdsa::Secp256k1SigningKey as SigningKey;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// A byte vector that zeroizes its contents on drop.
#[cfg(feature = "zeroize")]
pub type ZeroizingBytes = zeroize::Zeroizing<Vec<u8>>;
/// A fixed-size byte array that zeroizes its contents on drop.
#[cfg(feature = "zeroize")]
pub type ZeroizingArray<const N: usize> = zeroize::Zeroizing<[u8; N]>;
