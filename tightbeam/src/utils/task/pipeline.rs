//! Job orchestration pipeline engine
//!
//! Implements a Pipeline trait for Result<T, E> and closures, making Result
//! itself a pipeline. Jobs compose seamlessly with standard Rust code using
//! familiar Result methods.

use std::borrow::Cow;
use std::sync::Arc;

use crate::error::TightBeamError;
use crate::trace::TraceCollector;
use crate::utils::urn::Urn;

/// Pipeline trait - extends Result with trace and retry capabilities
///
/// This trait is implemented for Result<T, E>, making standard Rust Results
/// composable with jobs. The familiar Result methods (and_then, map, or_else)
/// work exactly as expected, with optional extensions for retry logic and tracing.
pub trait Pipeline: Sized {
	type Output;
	type Error;

	/// Chain another computation (like Result::and_then)
	fn and_then<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce(Self::Output) -> Result<U, Self::Error>;

	/// Transform the success value (like Result::map)
	fn map<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce(Self::Output) -> U;

	/// Handle errors (like Result::or_else)
	fn or_else<F>(self, f: F) -> impl Pipeline<Output = Self::Output, Error = Self::Error>
	where
		F: FnOnce(Self::Error) -> Result<Self::Output, Self::Error>;

	/// Execute the pipeline
	fn run(self) -> Result<Self::Output, Self::Error>;
}

// Result<T, E> is a Pipeline
impl<T, E> Pipeline for Result<T, E> {
	type Output = T;
	type Error = E;

	fn and_then<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = E>
	where
		F: FnOnce(T) -> Result<U, E>,
	{
		self.and_then(f)
	}

	fn map<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = E>
	where
		F: FnOnce(T) -> U,
	{
		// Use built-in Result::map
		self.map(f)
	}

	fn or_else<F>(self, f: F) -> impl Pipeline<Output = T, Error = E>
	where
		F: FnOnce(E) -> Result<T, E>,
	{
		// Use built-in Result::or_else
		self.or_else(f)
	}

	fn run(self) -> Result<T, E> {
		self // Already a Result
	}
}

/// Closures that return Result are also Pipelines
impl<F, T, E> Pipeline for F
where
	F: FnOnce() -> Result<T, E>,
{
	type Output = T;
	type Error = E;

	fn and_then<G, U>(self, g: G) -> impl Pipeline<Output = U, Error = E>
	where
		G: FnOnce(T) -> Result<U, E>,
	{
		self().and_then(g)
	}

	fn map<G, U>(self, g: G) -> impl Pipeline<Output = U, Error = E>
	where
		G: FnOnce(T) -> U,
	{
		self().map(g)
	}

	fn or_else<G>(self, g: G) -> impl Pipeline<Output = T, Error = E>
	where
		G: FnOnce(E) -> Result<T, E>,
	{
		self().or_else(g)
	}

	fn run(self) -> Result<T, E> {
		self()
	}
}

/// Extract Job struct name from type_name and convert to snake_case for trace events
///
/// Handles Job::run function paths like `crate::module::CreateTestFrame::run`
/// by extracting the struct name (second-to-last segment) and converting to snake_case.
///
/// Examples:
/// - `suite::jobs::CreateTestFrame::run` -> `create_test_frame`
/// - `my_crate::ValidateConfig::run` -> `validate_config`
/// - `CreateHandshakeRequest` -> `create_handshake_request` (fallback)
fn to_snake_case(type_name: &str) -> String {
	// Split by "::" and collect segments
	let segments: Vec<&str> = type_name.split("::").collect();
	// For Job::run paths, the struct name is second-to-last (before "run")
	// e.g., ["suite", "jobs", "CreateTestFrame", "run"] -> "CreateTestFrame"
	let name = if segments.len() >= 2 && segments.last() == Some(&"run") {
		segments[segments.len() - 2]
	} else {
		// Fallback: use last segment
		segments.last().copied().unwrap_or(type_name)
	};

	// Worst case: every char is uppercase → "ABC" becomes "a_b_c" (2n - 1 chars)
	let capacity = name.len().saturating_mul(2);
	let mut result = String::with_capacity(capacity);
	for (i, ch) in name.chars().enumerate() {
		if ch.is_uppercase() {
			if i > 0 {
				result.push('_');
			}
			result.push(ch.to_ascii_lowercase());
		} else {
			result.push(ch);
		}
	}

	result
}

/// Create a tightbeam instrumentation event URN
///
/// Format: `urn:tightbeam:instrumentation:event/<job_name>_<suffix>`
fn make_event_urn(job_name: &str, suffix: &str) -> Urn<'static> {
	Urn {
		nid: Cow::Borrowed("tightbeam"),
		nss: Cow::Owned(format!("instrumentation:event/{}_{}", job_name, suffix)),
	}
}

/// Result with trace context for auto-trace events
///
/// TracedResult wraps a Result and automatically emits trace events when jobs execute.
/// Job names are automatically derived from their type names using snake_case conversion.
pub struct TracedResult<T, E> {
	result: Result<T, E>,
	trace: Arc<TraceCollector>,
}

impl<T, E> TracedResult<T, E> {
	/// Create a new TracedResult
	pub fn new(result: Result<T, E>, trace: Arc<TraceCollector>) -> Self {
		Self { result, trace }
	}

	/// Get a reference to the trace collector
	pub fn trace(&self) -> &Arc<TraceCollector> {
		&self.trace
	}
}

impl<T, E> Pipeline for TracedResult<T, E>
where
	E: From<TightBeamError>,
{
	type Output = T;
	type Error = E;

	fn and_then<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = E>
	where
		F: FnOnce(T) -> Result<U, E>,
	{
		// Extract job name from closure type (e.g., "crate::CreateTestFrame::run" -> "create_test_frame")
		let job_name = to_snake_case(core::any::type_name::<F>());
		TracedResult {
			result: self.result.and_then(|val| {
				// Auto-emit: urn:tightbeam:instrumentation:event/<job_name>_start
				if let Err(e) = self.trace.event(make_event_urn(&job_name, "start")) {
					return Err(E::from(e));
				}

				// Auto-emit: urn:tightbeam:instrumentation:event/<job_name>_success|error
				let res = f(val);
				match &res {
					Ok(_) => {
						if let Err(e) = self.trace.event(make_event_urn(&job_name, "success")) {
							return Err(E::from(e));
						}
					}
					Err(_) => {
						let _ = self.trace.event(make_event_urn(&job_name, "error"));
					}
				}

				res
			}),
			trace: self.trace,
		}
	}

	fn map<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = E>
	where
		F: FnOnce(T) -> U,
	{
		TracedResult { result: self.result.map(f), trace: self.trace }
	}

	fn or_else<F>(self, f: F) -> impl Pipeline<Output = T, Error = E>
	where
		F: FnOnce(E) -> Result<T, E>,
	{
		TracedResult { result: self.result.or_else(f), trace: self.trace }
	}

	fn run(self) -> Result<T, E> {
		self.result
	}
}

/// Builder for creating traced pipelines
///
/// PipelineBuilder initializes a pipeline with trace context, enabling automatic
/// trace event emission for all jobs in the pipeline.
pub struct PipelineBuilder {
	trace: Arc<TraceCollector>,
}

impl PipelineBuilder {
	/// Create a new pipeline builder with trace context
	pub fn new(trace: Arc<TraceCollector>) -> Self {
		Self { trace }
	}

	/// Start a pipeline with an initial value
	pub fn start<T, E>(self, value: T) -> TracedResult<T, E> {
		TracedResult { result: Ok(value), trace: self.trace }
	}
}

/// Join type for parallel execution of two pipelines
pub struct Join<P1, P2> {
	left: P1,
	right: P2,
}

impl<P1, P2> Pipeline for Join<P1, P2>
where
	P1: Pipeline,
	P2: Pipeline<Error = P1::Error>,
{
	type Output = (P1::Output, P2::Output);
	type Error = P1::Error;

	fn and_then<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce((P1::Output, P2::Output)) -> Result<U, Self::Error>,
	{
		self.run().and_then(f)
	}

	fn map<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce((P1::Output, P2::Output)) -> U,
	{
		self.run().map(f)
	}

	fn or_else<F>(self, f: F) -> impl Pipeline<Output = (P1::Output, P2::Output), Error = Self::Error>
	where
		F: FnOnce(Self::Error) -> Result<(P1::Output, P2::Output), Self::Error>,
	{
		self.run().or_else(f)
	}

	fn run(self) -> Result<(P1::Output, P2::Output), Self::Error> {
		// Execute both pipelines
		let left_result = self.left.run()?;
		let right_result = self.right.run()?;
		Ok((left_result, right_result))
	}
}

/// Parallel execution of two pipelines (like tokio::join!)
///
/// Executes both pipelines and returns a tuple of their results.
/// If either pipeline fails, the error is propagated.
///
/// # Examples
///
/// ```rust,ignore
/// use tightbeam::pipeline::join;
///
/// let (encrypted, signed) = join(
///     EncryptPayload::run(payload),
///     SignPayload::run(payload)
/// ).run()?;
/// ```
pub fn join<P1, P2>(pipe1: P1, pipe2: P2) -> Join<P1, P2>
where
	P1: Pipeline,
	P2: Pipeline<Error = P1::Error>,
{
	Join { left: pipe1, right: pipe2 }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_to_snake_case() {
		// Simple type names (fallback behavior)
		assert_eq!(to_snake_case("CreateHandshakeRequest"), "create_handshake_request");
		assert_eq!(to_snake_case("ValidateConfig"), "validate_config");
		assert_eq!(to_snake_case("HTTPRequest"), "h_t_t_p_request");
		assert_eq!(to_snake_case("simple"), "simple");

		// Job::run paths - extracts struct name (second-to-last segment)
		assert_eq!(to_snake_case("suite::jobs::CreateTestFrame::run"), "create_test_frame");
		assert_eq!(to_snake_case("my_crate::ValidateFrame::run"), "validate_frame");
		assert_eq!(to_snake_case("TransformContent::run"), "transform_content");
	}

	#[test]
	fn test_make_event_urn() {
		assert_eq!(
			make_event_urn("create_handshake_request", "start").to_string(),
			"urn:tightbeam:instrumentation:event/create_handshake_request_start"
		);
		assert_eq!(
			make_event_urn("validate_config", "success").to_string(),
			"urn:tightbeam:instrumentation:event/validate_config_success"
		);
		assert_eq!(
			make_event_urn("send_request", "error").to_string(),
			"urn:tightbeam:instrumentation:event/send_request_error"
		);
	}

	#[test]
	fn test_result_is_pipeline() {
		let result: Result<i32, &str> = Ok(42);

		let doubled = result.map(|x| x * 2).run();
		assert_eq!(doubled, Ok(84));
	}

	#[test]
	fn test_pipeline_and_then() {
		let result: Result<i32, &str> = Ok(10);

		let computed = result.map(|x| x + 5).map(|x| x * 2).run();
		assert_eq!(computed, Ok(30));
	}

	#[test]
	fn test_pipeline_or_else() {
		let result: Result<i32, &str> = Err("error");

		let with_fallback: Result<i32, &str> = result.or(Ok(100)).run();
		assert_eq!(with_fallback, Ok(100));
	}

	#[test]
	fn test_join_pipelines() {
		let pipe1: Result<i32, &str> = Ok(10);
		let pipe2: Result<i32, &str> = Ok(20);

		let (a, b) = join(pipe1, pipe2).run().unwrap();
		assert_eq!(a, 10);
		assert_eq!(b, 20);
	}

	#[test]
	fn test_join_with_error() {
		let pipe1: Result<i32, &str> = Ok(10);
		let pipe2: Result<i32, &str> = Err("failed");

		let result = join(pipe1, pipe2).run();
		assert_eq!(result, Err("failed"));
	}

	#[test]
	fn test_pipeline_or_else_fallback() {
		let result: Result<i32, &str> = Err("error");

		let with_fallback: Result<i32, &str> = result.or(Ok(100)).run();
		assert_eq!(with_fallback, Ok(100));
	}
}
