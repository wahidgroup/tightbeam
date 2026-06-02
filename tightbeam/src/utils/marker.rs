//! Target-conditional `Send`/`Sync` markers for async traits.
//!
//! Native targets run on multi-threaded executors and MUST stay `Send`/`Sync`.
//! `wasm32` is single-threaded and its JS-backed futures and handles are
//! `!Send`, so these markers collapse to no-op bounds there.

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::future::Future;
use core::pin::Pin;

/// Requires `Send` on every target except `wasm32`, where it is a no-op.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// Requires `Send` on every target except `wasm32`, where it is a no-op.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// Requires `Sync` on every target except `wasm32`, where it is a no-op.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync> MaybeSync for T {}

/// Requires `Sync` on every target except `wasm32`, where it is a no-op.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSync for T {}

/// Boxed future whose `Send` requirement is relaxed on `wasm32`.
///
/// A `dyn` trait object cannot carry the non-auto [`MaybeSend`] bound, so the
/// `Send` bound is target-gated directly here while keeping the owning trait
/// dyn-compatible.
#[cfg(not(target_arch = "wasm32"))]
pub type MaybeSendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed future whose `Send` requirement is relaxed on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub type MaybeSendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
