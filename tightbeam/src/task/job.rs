//! The reusable frame composition functions that the `job!` macro defines.
//!
//! A job transforms an input into an output, typically
//! `Result<T, TightBeamError>`, and is sync or async.
//!
//! # Traits
//!
//! - [`Job`] is the trait of a synchronous job.
//! - [`AsyncJob`] is the trait of an asynchronous job.
//!
//! # Examples
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

/// The trait of a synchronous job type.
///
/// A job is a stateless unit of work, a zero-sized type with a static `run`
/// method. The `job!` macro implements this trait for a sync job.
pub trait Job {
	/// The input type of this job.
	type Input;
	/// The output type of this job, typically `Result<T, TightBeamError>`.
	type Output;

	/// The name of the job, the name of its struct, which a traced pipeline
	/// step names its events by ([`TracedResult::then_job`]).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::task::Job;
	/// use tightbeam::{job, TightBeamError};
	///
	/// job! {
	///     name: AddNumbers,
	///     fn run((a, b): (u32, u32)) -> Result<u32, TightBeamError> {
	///         Ok(a.saturating_add(b))
	///     }
	/// }
	///
	/// assert_eq!(<AddNumbers as Job>::NAME, "AddNumbers");
	/// ```
	///
	/// [`TracedResult::then_job`]: crate::task::TracedResult::then_job
	const NAME: &'static str;

	/// Runs the job on `input`.
	fn run(input: Self::Input) -> Self::Output;
}

/// The trait of an asynchronous job type.
///
/// An async job is a stateless unit of work with an async `run` method. The
/// `job!` macro implements this trait for an async job.
pub trait AsyncJob {
	/// The input type of this job.
	type Input;
	/// The output type of this job, typically `Result<T, TightBeamError>`.
	type Output;

	/// The name of the job, the name of its struct.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::task::AsyncJob;
	/// use tightbeam::{job, TightBeamError};
	///
	/// job! {
	///     name: Ping,
	///     async fn run() -> Result<&'static str, TightBeamError> {
	///         Ok("pong")
	///     }
	/// }
	///
	/// assert_eq!(<Ping as AsyncJob>::NAME, "Ping");
	/// ```
	const NAME: &'static str;

	/// Runs the job on `input` asynchronously.
	fn run(input: Self::Input) -> impl core::future::Future<Output = Self::Output> + Send;
}

/// Defines a `#[test]` function `name` that binds the value of `job` to the
/// parameter of `assertions` and runs the `assertions` block, which returns
/// `Result<(), Box<dyn Error>>`.
///
/// An `async move` block defines a `#[tokio::test]` function instead, which
/// exists in a build of this crate with the `tokio` feature.
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
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() -> ::core::result::Result<(), ::std::boxed::Box<dyn ::std::error::Error>> {
				let $frame = $job;
				$assertions
			}
		}
	};
}

/// Defines a job: a unit struct `name` with an inherent `run` function, and an
/// implementation of `Job` for `fn run` or of `AsyncJob` for `async fn run`.
///
/// The parameter of `run` is a tuple pattern with its tuple type, or no
/// parameter at all, which gives the trait the input `()`. The attributes and
/// docs ahead of `name` go onto the struct.
#[macro_export]
macro_rules! job {
	// A sync job with a tuple-destructured parameter implements `Job`. The arm
	// matches `fn run((a, b, c): (A, B, C)) -> R`.
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		fn run(($($param_inner:tt)*) : $param_ty:ty $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::task::Job for $job_name {
			type Input = $param_ty;
			type Output = $return_ty;

			const NAME: &'static str = stringify!($job_name);

			fn run(($($param_inner)*): Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub fn run(($($param_inner)*): $param_ty) -> $return_ty {
				<Self as $crate::task::Job>::run(($($param_inner)*))
			}
		}
	};

	// A sync job with no parameters implements `Job` with `Input = ()`.
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		fn run() -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::task::Job for $job_name {
			type Input = ();
			type Output = $return_ty;

			const NAME: &'static str = stringify!($job_name);

			fn run(_: Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub fn run() -> $return_ty {
				<Self as $crate::task::Job>::run(())
			}
		}
	};

	// An async job with a tuple-destructured parameter implements `AsyncJob`.
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		async fn run(($($param_inner:tt)*) : $param_ty:ty $(,)?) -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::task::AsyncJob for $job_name {
			type Input = $param_ty;
			type Output = $return_ty;

			const NAME: &'static str = stringify!($job_name);

			async fn run(($($param_inner)*): Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub async fn run(($($param_inner)*): $param_ty) -> $return_ty {
				<Self as $crate::task::AsyncJob>::run(($($param_inner)*)).await
			}
		}
	};

	// An async job with no parameters implements `AsyncJob` with `Input = ()`.
	(
		$(#[$meta:meta])*
		name: $job_name:ident,
		async fn run() -> $return_ty:ty $body:block
	) => {
		$(#[$meta])*
		pub struct $job_name;

		impl $crate::task::AsyncJob for $job_name {
			type Input = ();
			type Output = $return_ty;

			const NAME: &'static str = stringify!($job_name);

			async fn run(_: Self::Input) -> Self::Output $body
		}

		impl $job_name {
			#[inline]
			pub async fn run() -> $return_ty {
				<Self as $crate::task::AsyncJob>::run(()).await
			}
		}
	};

}

#[cfg(test)]
mod tests {
	#[cfg(feature = "colony")]
	use crate::colony::protocol::{HiveManagement, ListServletsParams, SpawnServletParams, StopServletParams};
	#[cfg(feature = "colony")]
	use crate::colony::urn::ColonyNamespace;
	#[cfg(any(feature = "colony", feature = "tokio"))]
	use crate::error::Result;
	#[cfg(feature = "colony")]
	use crate::urn::Urn;
	#[cfg(any(feature = "colony", feature = "tokio"))]
	use crate::Frame;

	// A sync job with a tuple input, which implements `Job`.
	#[cfg(feature = "colony")]
	job! {
		name: SpawnServletJob,
		fn run((servlet_type, config): (Urn<'static>, Option<Vec<u8>>)) -> Result<Frame> {
			compose! {
				V0: id: "spawn-req",
					message: HiveManagement::Spawn(SpawnServletParams {
						servlet_type,
						config,
					})
			}
		}
	}

	// A sync job with no parameters, which implements `Job` with `Input = ()`.
	#[cfg(feature = "colony")]
	job! {
		name: ListServletsJob,
		fn run() -> Result<Frame> {
			compose! {
				V0: id: "list-req",
					message: HiveManagement::List(ListServletsParams { filter: None })
			}
		}
	}

	// A sync job with a one-element tuple input.
	#[cfg(feature = "colony")]
	job! {
		name: StopServletJob,
		fn run((servlet_id,): (Urn<'static>,)) -> Result<Frame> {
			compose! {
				V0: id: "stop-req",
					message: HiveManagement::Stop(StopServletParams { servlet_id })
			}
		}
	}

	// An async job with a tuple input, which implements `AsyncJob`.
	#[cfg(feature = "tokio")]
	job! {
		name: AsyncCalculationJob,
		async fn run((x, y): (u64, u64)) -> Result<Frame> {
			let result = x + y;
			compose! {
				V0: id: "calc-result",
					message: crate::testing::TestMessage { content: result.to_string() }
			}
		}
	}

	// An async job with no parameters, which implements `AsyncJob` with
	// `Input = ()`.
	#[cfg(feature = "tokio")]
	job! {
		name: AsyncPingJob,
		async fn run() -> Result<Frame> {
			compose! {
				V0: id: "async-ping",
					message: crate::testing::TestMessage { content: "pong".to_string() }
			}
		}
	}

	#[cfg(feature = "colony")]
	fn worker_type() -> crate::urn::Urn<'static> {
		ColonyNamespace::default()
			.servlet("worker")
			.expect("test names satisfy the mint grammar")
	}

	#[cfg(feature = "colony")]
	fn worker_instance() -> crate::urn::Urn<'static> {
		worker_type()
			.servlet_instance("127.0.0.1:8080")
			.expect("a servlet type URN yields an instance URN")
	}

	#[cfg(feature = "colony")]
	test_job! {
		name: test_spawn_servlet_job,
		job: SpawnServletJob::run((worker_type(), None)),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata().id(), b"spawn-req");

			let request: HiveManagement = frame.decode_message()?;
			let HiveManagement::Spawn(spawn) = request else {
				return Err(crate::testing::error::TestingError::InvariantViolated.into());
			};
			assert_eq!(spawn.servlet_type, worker_type());
			Ok(())
		}
	}

	#[cfg(feature = "colony")]
	test_job! {
		name: test_list_servlets_job,
		job: ListServletsJob::run(),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata().id(), b"list-req");

			let request: HiveManagement = frame.decode_message()?;
			if !matches!(request, HiveManagement::List(_)) {
				return Err(crate::testing::error::TestingError::InvariantViolated.into());
			}
			Ok(())
		}
	}

	#[cfg(feature = "colony")]
	test_job! {
		name: test_stop_servlet_job,
		job: StopServletJob::run((worker_instance(),)),
		assertions: |frame| {
			let frame = frame.unwrap_or_else(|e| panic!("Error: {e:?}"));
			assert_eq!(frame.metadata().id(), b"stop-req");

			let request: HiveManagement = frame.decode_message()?;
			let HiveManagement::Stop(stop) = request else {
				return Err(crate::testing::error::TestingError::InvariantViolated.into());
			};
			assert_eq!(stop.servlet_id, worker_instance());
			Ok(())
		}
	}

	#[cfg(all(feature = "tokio", feature = "router"))]
	test_job! {
		name: test_async_job,
		job: AsyncCalculationJob::run((10, 32)),
		assertions: |frame| async move {
			let frame = frame.await?;
			assert_eq!(frame.metadata().id(), b"calc-result");

			let result: crate::testing::TestMessage = frame.decode_message()?;
			assert_eq!(result.content, "42");
			Ok(())
		}
	}

	#[cfg(all(feature = "tokio", feature = "router"))]
	test_job! {
		name: test_async_job_with_no_parameters,
		job: AsyncPingJob::run(),
		assertions: |frame| async move {
			let frame = frame.await?;
			assert_eq!(frame.metadata().id(), b"async-ping");

			let result: crate::testing::TestMessage = frame.decode_message()?;
			assert_eq!(result.content, "pong");
			Ok(())
		}
	}
}
