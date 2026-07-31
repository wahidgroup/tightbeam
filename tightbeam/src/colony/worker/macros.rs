//! Worker macros: name, config, policies, and handler wiring over [`WorkerRuntime`].

#[macro_export]
macro_rules! worker {
	(@queue $queue:expr) => { $queue };
	(@queue) => { 64usize };

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config, { $($cfg_field: $cfg_ty,)* },
			{ $( $policy_method : $policy_value ),* },
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			no_config, {},
			{ $( $policy_method : $policy_value ),* },
			(|$message_ident, $trace_ident, _config| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		handle: |$message_ident:ident, $trace_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			no_config, {},
			{},
			(|$message_ident, $trace_ident, _config| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config, { $($cfg_field: $cfg_ty,)* },
			{ $( $policy_method : $policy_value ),* },
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config, { $($cfg_field: $cfg_ty,)* },
			{},
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{ $( $policy_method:ident : $policy_value:tt ),* },
		(|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)
	) => {
		$crate::paste::paste! {
			#[derive(Clone)]
			pub struct [<$worker_name Config>] {
				$(pub $cfg_field: $cfg_ty,)*
			}

			pub struct $worker_name {
				runtime: $crate::colony::worker::WorkerRuntime<$input, $output, [<$worker_name Config>]>,
			}

			impl $worker_name {
				pub fn new(config: [<$worker_name Config>]) -> Self {
					Self { runtime: $crate::colony::worker::WorkerRuntime::new(config) }
				}

				pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
					let queue_capacity = $crate::worker!(@queue $($queue)?);
					let policies = $crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* });
					let runtime = self.runtime.start(trace, queue_capacity, policies, |message, trace, config| {
						let $message_ident = message;
						let $trace_ident = trace;
						async move {
							let $config_ident = config.as_ref();
							$handler_block
						}
					});
					Self { runtime }
				}
			}

			$crate::worker!(@impl_worker_trait $worker_name, $input, $output, [<$worker_name Config>]);
		}
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{ $( $policy_method:ident : $policy_value:tt ),* },
		(|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)
	) => {
		pub struct $worker_name {
			runtime: $crate::colony::worker::WorkerRuntime<$input, $output, ()>,
		}

		impl $worker_name {
			pub fn new(_: ()) -> Self {
				Self { runtime: $crate::colony::worker::WorkerRuntime::new(()) }
			}

			pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
				let queue_capacity = $crate::worker!(@queue $($queue)?);
				let policies = $crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* });
				let runtime = self.runtime.start(trace, queue_capacity, policies, |message, trace, _config| {
					let $message_ident = message;
					let $trace_ident = trace;
					let $config_ident = ();
					async move { $handler_block }
				});

				Self { runtime }
			}
		}

		$crate::worker!(@impl_worker_trait $worker_name, $input, $output, ());
	};

	(@impl_worker_trait $worker_name:ident, $input:ty, $output:ty, $config_ty:ty) => {
		impl $crate::colony::worker::Worker for $worker_name {
			type Input = $input;
			type Output = $output;
			type Config = $config_ty;

			fn new(config: Self::Config) -> Self {
				$worker_name::new(config)
			}

			fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> $crate::colony::worker::WorkerStartFuture<Self> {
				Box::pin(async move { Ok($worker_name::start(self, trace)) })
			}

			fn relay(
				&self,
				message: ::std::sync::Arc<Self::Input>,
			) -> $crate::colony::worker::WorkerRelayFuture<Self::Output> {
				self.runtime.relay(message)
			}

			fn kill(self) -> $crate::colony::worker::WorkerKillFuture {
				self.runtime.kill()
			}

			fn queue_capacity(&self) -> usize {
				self.runtime.queue_capacity()
			}
		}

		impl $crate::colony::worker::WorkerMetadata for $worker_name {
			fn name() -> &'static str {
				// module_path! resolves at the macro call site, so workers
				// with the same ident in different modules cannot collide
				// in a servlet's registration map.
				concat!(module_path!(), "::", stringify!($worker_name))
			}
		}
	};

	(@build_policies $input:ty, {}) => {{
		$crate::colony::worker::WorkerPolicyBuilder::<$input>::default().build()
	}};

	(@build_policies $input:ty, { $( with_receptor_gate : [ $( $gate:expr ),* $(,)? ] ),* $(,)? }) => {{
		$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
			$(.with_receptor_gate([ $( $gate ),* ]))*
			.build()
	}};
}
