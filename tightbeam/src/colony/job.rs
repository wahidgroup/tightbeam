//! Job macro for creating reusable frame composition functions
//!
//! Jobs are simple functions that compose TightBeam frames with optional parameters.
//! They can be sync or async and return a Result<Frame, TightBeamError>.

#[macro_export]
macro_rules! test_job {
	(
		name: $test_name:ident,
		job: $job:expr,
		assertions: |$frame:ident| $assertions:block
	) => {
		#[test]
		fn $test_name() {
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
		async fn $test_name() {
			let $frame = $job;
			$assertions
		}
	};
}

#[macro_export]
macro_rules! job {
	// Async job with generic return type
	(
        name: $job_name:ident,
        async fn run($($param:ident: $param_ty:ty),* $(,)?) -> $return_ty:ty $body:block
    ) => {
        pub struct $job_name;

        impl $job_name {
            pub async fn run($($param: $param_ty),*) -> $return_ty {
                $body
            }
        }
    };

    // Sync job with generic return type
    (
        name: $job_name:ident,
        fn run($($param:ident: $param_ty:ty),* $(,)?) -> $return_ty:ty $body:block
    ) => {
        pub struct $job_name;

        impl $job_name {
            pub fn run($($param: $param_ty),*) -> $return_ty {
                $body
            }
        }
    };
}

#[cfg(test)]
mod tests {
	use crate::colony::drone::{HiveManagementRequest, ListServletsParams, SpawnServletParams, StopServletParams};
	use crate::error::Result;
	use crate::Frame;

	job! {
		name: SpawnServletJob,
		fn run(servlet_type: &str, config: Option<Vec<u8>>) -> Result<Frame> {
			crate::compose! {
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
			crate::compose! {
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
			crate::compose! {
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
			crate::compose! {
				V0: id: "calc-result",
					message: crate::testing::TestMessage { content: result.to_string() }
			}
		}
	}

	test_job! {
		name: test_spawn_servlet_job,
		job: SpawnServletJob::run("worker_servlet", None),
		assertions: |frame| {
			let frame = frame.unwrap();
			assert_eq!(frame.metadata.id, b"spawn-req");

			let request: HiveManagementRequest = crate::decode(&frame.message).unwrap();
			assert!(request.spawn.is_some());
			assert_eq!(request.spawn.unwrap().servlet_type, b"worker_servlet");
		}
	}

	test_job! {
		name: test_list_servlets_job,
		job: ListServletsJob::run(),
		assertions: |frame| {
			let frame = frame.unwrap();
			assert_eq!(frame.metadata.id, b"list-req");

			let request: HiveManagementRequest = crate::decode(&frame.message).unwrap();
			assert!(request.list.is_some());
		}
	}

	test_job! {
		name: test_stop_servlet_job,
		job: StopServletJob::run("worker_servlet_127.0.0.1:8080"),
		assertions: |frame| {
			let frame = frame.unwrap();
			assert_eq!(frame.metadata.id, b"stop-req");

			let request: HiveManagementRequest = crate::decode(&frame.message).unwrap();
			assert!(request.stop.is_some());
			assert_eq!(request.stop.unwrap().servlet_id, b"worker_servlet_127.0.0.1:8080");
		}
	}

	test_job! {
		name: test_async_job,
		job: AsyncCalculationJob::run(10, 32),
		assertions: |frame| async move {
			let frame = frame.await.unwrap();
			assert_eq!(frame.metadata.id, b"calc-result");

			let result: crate::testing::TestMessage = crate::decode(&frame.message).unwrap();
			assert_eq!(result.content, "42");
		}
	}
}
