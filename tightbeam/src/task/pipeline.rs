//! A pipeline engine that orchestrates jobs.
//!
//! A `Result<T, E>` and a closure that returns one are each a [`Pipeline`],
//! so jobs compose with standard Rust code.

#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;

#[cfg(any(test, feature = "testing"))]
use crate::error::TightBeamError;
#[cfg(any(test, feature = "testing"))]
use crate::task::Job;
#[cfg(any(test, feature = "testing"))]
use crate::trace::TraceCollector;
#[cfg(any(test, feature = "testing"))]
use crate::urn::Urn;

/// A chain of jobs, with `Result` as the base pipeline.
///
/// `Result<T, E>` implements the trait, so the familiar `Result` methods
/// (`and_then`, `map`, `or_else`) chain jobs as they do on `Result`, and
/// `TracedResult` adds tracing.
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

/// The snake_case form of `name`, a job name such as `CreateTestFrame`, for
/// trace events.
///
/// Each uppercase letter after the first starts a new word, so
/// `CreateHandshakeRequest` becomes `create_handshake_request`.
#[cfg(any(test, feature = "testing"))]
fn to_snake_case(name: impl AsRef<str>) -> String {
	let name = name.as_ref();

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
/// [`Self::then_job`] emits a start event before a job and a success or error
/// event after it, under the snake_case form of [`Job::NAME`]. A closure step
/// through [`Pipeline::and_then`] chains its result alone.
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
impl<T, E> TracedResult<T, E>
where
	E: From<TightBeamError>,
{
	/// Runs the job `J` on the output of this step, and records its start and
	/// its outcome under the snake_case form of [`Job::NAME`], with a hyphen
	/// for each underscore: the event `urn:tightbeam:event:job/<name>-start`,
	/// then `-success` or `-error`.
	///
	/// A failed step passes its error on, and the job runs on a success alone.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::task::{Pipeline, PipelineBuilder};
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::urn::Urn;
	/// use tightbeam::{job, TightBeamError};
	///
	/// job! {
	///     name: AddOne,
	///     fn run((value,): (u32,)) -> Result<u32, TightBeamError> {
	///         Ok(value.saturating_add(1))
	///     }
	/// }
	///
	/// const ADD_ONE_START: Urn<'static> = tightbeam::urn!("tightbeam", "event:job/add-one-start");
	///
	/// let trace = Arc::new(TraceCollector::new());
	/// let value = PipelineBuilder::new(Arc::clone(&trace)).start((1u32,)).then_job::<AddOne, _>().run()?;
	///
	/// assert_eq!((value, trace.recorded(ADD_ONE_START)), (2, 1));
	/// # Ok::<(), TightBeamError>(())
	/// ```
	pub fn then_job<J, U>(self) -> TracedResult<U, E>
	where
		J: Job<Input = T, Output = Result<U, E>>,
	{
		let job_name = to_snake_case(J::NAME);
		let trace = self.trace;
		let result = self.result.and_then(|input| {
			Self::record_job_event(&trace, &job_name, "start")?;
			let outcome = J::run(input);
			let suffix = if outcome.is_ok() {
				"success"
			} else {
				"error"
			};
			Self::record_job_event(&trace, &job_name, suffix)?;
			outcome
		});

		TracedResult { result, trace }
	}

	/// Records the `suffix` event of the job named `job_name`, the URN that
	/// [`make_event_urn`] names.
	///
	/// # Errors
	///
	/// - The error of the URN, or the fault that the trace injects at the event.
	fn record_job_event(trace: &TraceCollector, job_name: &str, suffix: &str) -> Result<(), E> {
		let urn = make_event_urn(job_name, suffix)?;
		trace.event(urn)?.emit();
		Ok(())
	}
}

// Each step returns the traced result itself, so a chain keeps its trace
// through a plain step and takes `then_job` after it.
#[cfg(any(test, feature = "testing"))]
#[allow(refining_impl_trait)]
impl<T, E> Pipeline for TracedResult<T, E> {
	type Output = T;
	type Error = E;

	fn and_then<F, U>(self, f: F) -> TracedResult<U, E>
	where
		F: FnOnce(T) -> Result<U, E>,
	{
		TracedResult { result: self.result.and_then(f), trace: self.trace }
	}

	fn map<F, U>(self, f: F) -> TracedResult<U, E>
	where
		F: FnOnce(T) -> U,
	{
		TracedResult { result: self.result.map(f), trace: self.trace }
	}

	fn or_else<F>(self, f: F) -> TracedResult<T, E>
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
/// It starts a pipeline with a trace context, so every job that the pipeline
/// runs through [`TracedResult::then_job`] emits trace events.
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
/// use tightbeam::task::{join, Pipeline};
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
		assert_eq!(to_snake_case("CreateHandshakeRequest"), "create_handshake_request");
		assert_eq!(to_snake_case("ValidateConfig"), "validate_config");
		assert_eq!(to_snake_case("HTTPRequest"), "h_t_t_p_request");
		assert_eq!(to_snake_case("simple"), "simple");
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

	/// A job that doubles its input.
	struct DoubleCount;

	impl Job for DoubleCount {
		type Input = (u32,);
		type Output = Result<u32, TightBeamError>;

		const NAME: &'static str = "DoubleCount";

		fn run((count,): Self::Input) -> Self::Output {
			Ok(count * 2)
		}
	}

	const DOUBLE_COUNT_START: Urn<'static> = crate::urn!("tightbeam", "event:job/double-count-start");
	const DOUBLE_COUNT_SUCCESS: Urn<'static> = crate::urn!("tightbeam", "event:job/double-count-success");

	#[test]
	fn a_job_step_labels_its_events_with_the_job_name() -> Result<(), TightBeamError> {
		let trace = Arc::new(TraceCollector::new());
		let started = PipelineBuilder::new(Arc::clone(&trace)).start((2u32,));

		started.then_job::<DoubleCount, _>().run()?;

		let recorded = [DOUBLE_COUNT_START, DOUBLE_COUNT_SUCCESS].map(|label| trace.recorded(label));
		assert_eq!(recorded, [1, 1]);
		Ok(())
	}

	#[test]
	fn a_closure_step_emits_no_job_event() -> Result<(), TightBeamError> {
		let trace = Arc::new(TraceCollector::new());
		let started = PipelineBuilder::new(Arc::clone(&trace)).start(1u32);

		started.and_then(|count| Ok::<u32, TightBeamError>(count + 1)).run()?;

		assert_eq!(trace.drain_assertions().len(), 0);
		Ok(())
	}
}
