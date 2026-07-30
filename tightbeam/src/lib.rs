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
//!    │  let decode: MyMessage = tightbeam::decode(&frame.message)?;   │
//!    └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # TightBeam Protocol
//!
//! A lightweight, versioned messaging protocol with cryptographic primitives
//! built on ASN.1 DER encoding.

#![deny(unsafe_code)]
// Zero-panic: raw `unwrap()` is banned everywhere, tests included. Test
// helpers state their invariant through `expect`, test cases propagate
// with `?`. The remaining panic paths are banned in production code, while
// tests are exempt, and the `testing` fixture surface carries its own
// scoped allowance (see `src/testing/mod.rs`).
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
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), feature = "zeroize"))]
use alloc::vec::Vec;

// Before other modules so `compose!` is in crate-wide textual scope.
#[cfg(feature = "builder")]
#[macro_use]
mod compose;

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
mod wire;

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
#[cfg(feature = "instrument")]
pub mod instrumentation;
pub mod macros;
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

#[cfg(feature = "hex")]
pub use hex_literal::hex;
#[cfg(all(feature = "std", not(feature = "tokio")))]
pub use std::sync::mpsc;
#[cfg(feature = "time")]
pub use time;
#[cfg(feature = "tokio")]
pub use tokio::sync::mpsc;
#[cfg(feature = "x509")]
pub use x509_cert as x509;

pub use utils::{decode, encode};

#[cfg(feature = "derive")]
pub use tightbeam_derive::{Beamable, Errorizable, Flaggable};

extern crate self as tightbeam;

pub use crate::core::*;
pub use crate::error::TightBeamError;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Secure bytes type
#[cfg(feature = "zeroize")]
pub type ZeroizingBytes = zeroize::Zeroizing<Vec<u8>>;
#[cfg(feature = "zeroize")]
pub type ZeroizingArray<const N: usize> = zeroize::Zeroizing<[u8; N]>;
