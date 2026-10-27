//! A pipeline engine that orchestrates jobs.
//!
//! The `Pipeline` trait covers `Result<T, E>` and the closures that return
//! one, so a `Result` is itself a pipeline. Jobs compose with standard Rust
//! code through the familiar `Result` methods.

#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;

#[cfg(any(test, feature = "testing"))]
use crate::error::TightBeamError;
#[cfg(any(test, feature = "testing"))]
use crate::trace::TraceCollector;
#[cfg(any(test, feature = "testing"))]
use crate::urn::Urn;

/// A chain of jobs, with `Result` as the base pipeline.
///
/// The trait is implemented for `Result<T, E>`, so a standard `Result`
/// composes with jobs. The familiar `Result` methods (`and_then`, `map`,
/// `or_else`) work as they do on `Result`, and `TracedResult` adds tracing.
pub trait Pipeline: Sized {
	type Output;
	type Error;

	/// Chain another computation, as `Result::and_then` does.
	fn and_then<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce(Self::Output) -> Result<U, Self::Error>;

	/// Transform the success value, as `Result::map` does.
	fn map<F, U>(self, f: F) -> impl Pipeline<Output = U, Error = Self::Error>
	where
		F: FnOnce(Self::Output) -> U;

	/// Handle an error, as `Result::or_else` does.
	fn or_else<F>(self, f: F) -> impl Pipeline<Output = Self::Output, Error = Self::Error>
	where
		F: FnOnce(Self::Error) -> Result<Self::Output, Self::Error>;

	/// Execute the pipeline and return its result.
	fn run(self) -> Result<Self::Output, Self::Error>;
}

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
		// This call resolves to the inherent `Result::map`.
		self.map(f)
	}

	fn or_else<F>(self, f: F) -> impl Pipeline<Output = T, Error = E>
	where
		F: FnOnce(E) -> Result<T, E>,
	{
		// This call resolves to the inherent `Result::or_else`.
		self.or_else(f)
	}

	fn run(self) -> Result<T, E> {
		self // The value is already a `Result`.
	}
}

/// A closure that returns a `Result` is also a pipeline.
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

/// The job struct name in `type_name`, in snake_case, for trace events.
///
/// For a `Job::run` path such as `crate::module::CreateTestFrame::run`, the
/// name is the struct name, the second-to-last segment. Any other path falls
/// back to its last segment.
///
/// For example:
/// - `suite::jobs::CreateTestFrame::run` becomes `create_test_frame`.
/// - `my_crate::ValidateConfig::run` becomes `validate_config`.
/// - `CreateHandshakeRequest` becomes `create_handshake_request`, by the fallback.
#[cfg(any(test, feature = "testing"))]
fn to_snake_case(type_name: impl AsRef<str>) -> String {
	let type_name = type_name.as_ref();
	let segments: Vec<&str> = type_name.split("::").collect();
	let name = match segments.as_slice() {
		[.., struct_name, "run"] => *struct_name,
		_ => segments.last().copied().unwrap_or(type_name),
	};

	// At worst every char is uppercase: "ABC" becomes "a_b_c", 2n - 1 chars.
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

/// Create a tightbeam job event URN.
///
/// The URN has the form `urn:tightbeam:event:job/<job-name>-<suffix>`.
#[cfg(any(test, feature = "testing"))]
fn make_event_urn(
	job_name: &(impl AsRef<str> + ?Sized),
	suffix: &(impl AsRef<str> + ?Sized),
) -> Result<Urn<'static>, crate::TightBeamError> {
	let job_name = job_name.as_ref();
	let suffix = suffix.as_ref();
	let nss = format!("event:job/{}-{}", job_name.replace('_', "-"), suffix);
	Ok(Urn::from_parts("tightbeam", nss)?)
}

/// A `Result` with the trace context that job events go to.
///
/// `and_then` emits a start event before each job and a success or error
/// event after it, under the snake_case form of the job's type name.
#[cfg(any(test, feature = "testing"))]
pub struct TracedResult<T, E> {
	result: Result<T, E>,
	trace: Arc<TraceCollector>,
}

#[cfg(any(test, feature = "testing"))]
impl<T, E> TracedResult<T, E> {
	/// Wrap `result` with the trace collector its jobs report to.
	pub fn new(result: Result<T, E>, trace: Arc<TraceCollector>) -> Self {
		Self { result, trace }
	}

	/// The trace collector the jobs report to.
	pub fn trace(&self) -> &Arc<TraceCollector> {
		&self.trace
	}
}

#[cfg(any(test, feature = "testing"))]
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
		// The job name comes from the closure type: for example,
		// "crate::CreateTestFrame::run" gives "create_test_frame".
		let job_name = to_snake_case(core::any::type_name::<F>());
		TracedResult {
			result: self.result.and_then(|val| {
				// The start event is urn:tightbeam:event:job/<job-name>-start.
				let event_urn = match make_event_urn(&job_name, "start") {
					Ok(urn) => urn,
					Err(e) => return Err(E::from(e)),
				};
				if let Err(e) = self.trace.event(event_urn) {
					return Err(E::from(e));
				}

				// The job then runs, and its outcome emits the end event,
				// urn:tightbeam:event:job/<job-name>-success or -error.
				let res = f(val);
				match &res {
					Ok(_) => {
						let event_urn = match make_event_urn(&job_name, "success") {
							Ok(urn) => urn,
							Err(e) => return Err(E::from(e)),
						};
						if let Err(e) = self.trace.event(event_urn) {
							return Err(E::from(e));
						}
					}
					Err(_) => {
						let event_urn = match make_event_urn(&job_name, "error") {
							Ok(urn) => urn,
							Err(e) => return Err(E::from(e)),
						};
						if let Err(e) = self.trace.event(event_urn) {
							return Err(E::from(e));
						}
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

/// A builder for traced pipelines.
///
/// It starts a pipeline with a trace context, so every job the pipeline
/// chains with `and_then` emits trace events.
#[cfg(any(test, feature = "testing"))]
pub struct PipelineBuilder {
	trace: Arc<TraceCollector>,
}

#[cfg(any(test, feature = "testing"))]
impl PipelineBuilder {
	/// Create a pipeline builder that reports to `trace`.
	pub fn new(trace: Arc<TraceCollector>) -> Self {
		Self { trace }
	}

	/// Start a pipeline with `value` as its first output.
	pub fn start<T, E>(self, value: T) -> TracedResult<T, E> {
		TracedResult { result: Ok(value), trace: self.trace }
	}
}

/// The join of two pipelines, which runs them in order and pairs their outputs.
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
		let left_result = self.left.run()?;
		let right_result = self.right.run()?;
		Ok((left_result, right_result))
	}
}

/// Join two pipelines into one whose output pairs theirs.
///
/// Running the join runs `pipe1` and then `pipe2`, and returns a tuple of
/// their outputs. The first error ends the run and propagates.
///
/// # Examples
///
/// ```rust
/// use tightbeam::utils::task::{join, Pipeline};
///
/// let payload = b"telemetry";
/// let length = || -> Result<usize, &'static str> { Ok(payload.len()) };
/// let lead = || payload.first().copied().ok_or("an empty payload");
///
/// let (length, lead) = join(length, lead).run()?;
///
/// assert_eq!((length, lead), (9, b't'));
/// # Ok::<(), &'static str>(())
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
		// A bare type name takes the fallback, its last segment.
		assert_eq!(to_snake_case("CreateHandshakeRequest"), "create_handshake_request");
		assert_eq!(to_snake_case("ValidateConfig"), "validate_config");
		assert_eq!(to_snake_case("HTTPRequest"), "h_t_t_p_request");
		assert_eq!(to_snake_case("simple"), "simple");

		// A `Job::run` path gives the struct name, the second-to-last segment.
		assert_eq!(to_snake_case("suite::jobs::CreateTestFrame::run"), "create_test_frame");
		assert_eq!(to_snake_case("my_crate::ValidateFrame::run"), "validate_frame");
		assert_eq!(to_snake_case("TransformContent::run"), "transform_content");
	}

	#[test]
	fn test_make_event_urn() {
		assert_eq!(
			make_event_urn("create_handshake_request", "start")
				.expect("a literal NID with a job event NSS")
				.to_string(),
			"urn:tightbeam:event:job/create-handshake-request-start"
		);
		assert_eq!(
			make_event_urn("validate_config", "success")
				.expect("a literal NID with a job event NSS")
				.to_string(),
			"urn:tightbeam:event:job/validate-config-success"
		);
		assert_eq!(
			make_event_urn("send_request", "error")
				.expect("a literal NID with a job event NSS")
				.to_string(),
			"urn:tightbeam:event:job/send-request-error"
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
	fn test_join_pipelines() -> Result<(), Box<dyn core::error::Error>> {
		let pipe1: Result<i32, &str> = Ok(10);
		let pipe2: Result<i32, &str> = Ok(20);

		let (a, b) = join(pipe1, pipe2).run()?;
		assert_eq!(a, 10);
		assert_eq!(b, 20);

		Ok(())
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
