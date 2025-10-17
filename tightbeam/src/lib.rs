//! ```text
//!     ╔════════════════════════════════════════════════════════════════╗
//!     ║                        T I G H T B E A M                       ║
//!     ║             Efficient Exchange-Compute Interconnect            ║
//!     ║           Mycelial Networking for Distributed Systems          ║
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
//!   Mycelial Network: Workers connect directly to servlets (no routing)
//!
//!    ╔═══════════════════════════════════════════════════════════════════╗
//!    ║  Protocol-Agnostic • Zero-Copy • ASN.1 DER • Sign-Then-Encrypt    ║
//!    ╚═══════════════════════════════════════════════════════════════════╝
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
//!         │  🕸️  Mycelial Architecture                           │
//!         │  ├─ Hives:    Multi-servlet orchestrators            │
//!         │  ├─ Drones:   Single-servlet morphers                │
//!         │  ├─ Servlets: Self-contained message processors      │
//!         │  └─ Direct:   Client-to-servlet connections          │
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
//!    │                                                                │
//!    │  #[derive(Beamable, Clone, Debug, der::Sequence)]              │
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
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod asn1;
pub mod core;
pub mod error;
pub mod flags;
pub mod helpers;
pub mod matrix;
pub mod prelude;
pub mod utils;

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "colony")]
pub mod colony;
#[cfg(feature = "constants")]
pub mod constants;
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

// Re-export
pub use asn1::*;
pub use der;
pub use spki;
pub use cms;
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
