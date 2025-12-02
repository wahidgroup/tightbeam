//! Job macro for creating reusable frame composition functions
//!
//! Jobs are stateless units of work that transform input into output.
//! They can be sync or async and return a Result<T, TightBeamError>.
//!
//! # Traits
//!
//! - [`Job`] - Marker trait for synchronous jobs
//! - [`AsyncJob`] - Marker trait for asynchronous jobs
//!
//! # Example
//!
//! ```ignore
//! use tightbeam::{job, TightBeamError};
//!
//! job! {
//!     /// Adds two numbers together.
//!     name: AddNumbers,
//!     fn run((a, b): (u32, u32)) -> Result<u32, TightBeamError> {
//!         Ok(a + b)
//!     }
//! }
//!
//! // Jobs implement the Job trait
//! let result = AddNumbers::run((1, 2))?;
//! ```

/// Marker trait for synchronous job types.
///
/// Jobs are stateless units of work (zero-sized types) with a static `run` method.
/// This trait is automatically implemented by the `job!` macro for sync jobs.
pub trait Job {
	/// The input type for this job
	type Input;
	/// The output type for this job (typically `Result<T, TightBeamError>`)
	type Output;

	/// Execute the job with the given input
	fn run(input: Self::Input) -> Self::Output;
}

/// Marker trait for asynchronous job types.
///
/// Async jobs are stateless units of work with an async `run` method.
/// This trait is automatically implemented by the `job!` macro for async jobs.
pub trait AsyncJob {
	/// The input type for this job
	type Input;
	/// The output type for this job (typically `Result<T, TightBeamError>`)
	type Output;

	/// Execute the job asynchronously with the given input
	fn run(input: Self::Input) -> impl core::future::Future<Output = Self::Output> + Send;
}

#[macro_export]
macro_rules! test_job {
	(
		name: $test_name:ident,
		job: $job:expr,
		assertions: |$frame:ident| $assertions:block
	) => {
		#[test]
		fn $test_name() -> ::core::result::Result<(), ::std::boxed::Box<dyn ::std::error::Error>> {
			let $frame = $job;
			$assertions
		}
	};

	(
		name: $test_name:ident,
		job: $job:expr,
		assertions: |$frame:ident| async move $assertions:block
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() -> ::core::result::Result<(), ::std::boxed::Box<dyn ::std::error::Error>> {
			let $frame = $job;
			$assertions
		}
	};
}

#[macro_export]
macro_rules! job {
	// Sync job with tuple-destructured parameter (implements Job trait)
	// Pattern: fn run((a, b, c): (A, B, C)) -> ...
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		fn run(($($param_inner:tt)*) : $param_ty:ty $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::utils::task::Job for $job_name {
			type Input = $param_ty;
			type Output = $return_ty;

			fn run(($($param_inner)*): Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub fn run(($($param_inner)*): $param_ty) -> $return_ty {
				<Self as $crate::utils::task::Job>::run(($($param_inner)*))
			}
		}
	};

	// Sync job with no parameters (implements Job trait with Input = ())
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		fn run() -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::utils::task::Job for $job_name {
			type Input = ();
			type Output = $return_ty;

			fn run(_: Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub fn run() -> $return_ty {
				<Self as $crate::utils::task::Job>::run(())
			}
		}
	};

	// Sync job with named parameters (no trait impl - may have references)
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		fn run($($param:ident : $param_ty:ty),+ $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $job_name {
			pub fn run($($param: $param_ty),+) -> $return_ty $body
		}
	};

	// Async job with tuple-destructured parameter (implements AsyncJob trait)
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		async fn run(($($param_inner:tt)*) : $param_ty:ty $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::utils::task::AsyncJob for $job_name {
			type Input = $param_ty;
			type Output = $return_ty;

			async fn run(($($param_inner)*): Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub async fn run(($($param_inner)*): $param_ty) -> $return_ty {
				<Self as $crate::utils::task::AsyncJob>::run(($($param_inner)*)).await
			}
		}
	};

	// Async job with no parameters
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		async fn run() -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::utils::job::AsyncJob for $job_name {
			type Input = ();
			type Output = $return_ty;

			async fn run(_: Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub async fn run() -> $return_ty {
				<Self as $crate::utils::job::AsyncJob>::run(()).await
			}
		}
	};

	// Async job with named parameters (no trait impl - may have references)
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		async fn run($($param:ident : $param_ty:ty),+ $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $job_name {
			pub async fn run($($param: $param_ty),+) -> $return_ty $body
		}
	};
}

#[cfg(test)]
mod tests {
	use crate::colony::{HiveManagementRequest, ListServletsParams, SpawnServletParams, StopServletParams};
	use crate::compose;
	use crate::error::Result;
	use crate::Frame;

	job! {
		name: SpawnServletJob,
		fn run(servlet_type: &str, config: Option<Vec<u8>>) -> Result<Frame> {
			compose! {
				V0: id: "spawn-req",
					message: HiveManagementRequest {
						spawn: Some(SpawnServletParams {
							servlet_type: servlet_type.as_bytes().to_vec(),
							config,
						}),
						list: None,
						stop: None,
					}
			}
		}
	}

	job! {
		name: ListServletsJob,
		fn run() -> Result<Frame> {
			compose! {
				V0: id: "list-req",
					message: HiveManagementRequest {
						spawn: None,
						list: Some(ListServletsParams { filter: None }),
						stop: None,
					}
			}
		}
	}

	job! {
		name: StopServletJob,
		fn run(servlet_id: &str) -> Result<Frame> {
			compose! {
				V0: id: "stop-req",
					message: HiveManagementRequest {
						spawn: None,
						list: None,
						stop: Some(StopServletParams {
							servlet_id: servlet_id.as_bytes().to_vec(),
						}),
					}
			}
		}
	}

	job! {
		name: AsyncCalculationJob,
		async fn run(x: u64, y: u64) -> Result<Frame> {
			// Simulate async work
			let result = x + y;
			compose! {
				V0: id: "calc-result",
					message: crate::testing::TestMessage { content: result.to_string() }
			}
		}
	}

	test_job! {
		name: test_spawn_servlet_job,
		job: SpawnServletJob::run("worker_servlet", None),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata.id, b"spawn-req");

			let request: HiveManagementRequest = crate::decode(&frame.message)?;
			assert!(request.spawn.is_some());
			assert_eq!(request.spawn.expect("spawn should be Some").servlet_type, b"worker_servlet");
			Ok(())
		}
	}

	test_job! {
		name: test_list_servlets_job,
		job: ListServletsJob::run(),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata.id, b"list-req");

			let request: HiveManagementRequest = crate::decode(&frame.message)?;
			assert!(request.list.is_some());
			Ok(())
		}
	}

	test_job! {
		name: test_stop_servlet_job,
		job: StopServletJob::run("worker_servlet_127.0.0.1:8080"),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata.id, b"stop-req");

			let request: HiveManagementRequest = crate::decode(&frame.message)?;
			assert!(request.stop.is_some());
			assert_eq!(request.stop.expect("stop should be Some").servlet_id, b"worker_servlet_127.0.0.1:8080");
			Ok(())
		}
	}

	test_job! {
		name: test_async_job,
		job: AsyncCalculationJob::run(10, 32),
		assertions: |frame| async move {
			let frame = frame.await?;
			assert_eq!(frame.metadata.id, b"calc-result");

			let result: crate::testing::TestMessage = crate::decode(&frame.message)?;
			assert_eq!(result.content, "42");
			Ok(())
		}
	}
}
