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
			config,
			{ $($cfg_field: $cfg_ty,)* },
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
			no_config,
			{},
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
			no_config,
			{},
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
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
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
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		$config_kind:ident,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			$config_kind,
			{ $($cfg_field: $cfg_ty,)* },
			{ $( $policy_method : $policy_value ),* },
			$handler
		);
		$crate::worker!(@impl_new $worker_name, $config_kind, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_worker_trait $worker_name, $input, $output, $config_kind, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, {});
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{ $( $policy_method : $policy_value ),* },
			$handler
		);
		$crate::worker!(@impl_from $worker_name, no_config, {});
		$crate::worker!(@impl_default_if_needed $worker_name, no_config);
		$crate::worker!(@impl_worker_trait $worker_name, $input, $output, no_config, {});
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{},
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
			$handler
		);
		$crate::worker!(@impl_from $worker_name, config, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_default_if_needed $worker_name, config);
		$crate::worker!(@impl_worker_trait $worker_name, $input, $output, config, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{},
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, {});
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{},
			$handler
		);
		$crate::worker!(@impl_from $worker_name, no_config, {});
		$crate::worker!(@impl_default_if_needed $worker_name, no_config);
		$crate::worker!(@impl_worker_trait $worker_name, $input, $output, no_config, {});
		$crate::worker!(@drop_impl $worker_name);
	};

	(@impl_struct $worker_name:ident, $input:ty, $output:ty, {}) => {
		pub struct $worker_name {
			sender: Option<$crate::colony::worker::worker_runtime::rt::QueueSender<$crate::colony::worker::WorkerRequest<$input, $output>>>,
			join: Option<$crate::colony::worker::worker_runtime::rt::JoinHandle>,
			queue: usize,
			config: ::std::sync::Arc<()>,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}
	};

	(@impl_struct $worker_name:ident, $input:ty, $output:ty, { $($cfg_field:ident: $cfg_ty:ty,)* }) => {
		$crate::paste::paste! {
			pub struct $worker_name {
				sender: Option<$crate::colony::worker::worker_runtime::rt::QueueSender<$crate::colony::worker::WorkerRequest<$input, $output>>>,
				join: Option<$crate::colony::worker::worker_runtime::rt::JoinHandle>,
				queue: usize,
				config: ::std::sync::Arc<[<$worker_name Conf>]>,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}

			#[derive(Clone)]
			pub struct [<$worker_name Conf>] {
				$(pub $cfg_field: $cfg_ty,)*
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt
	) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
					if self.sender.is_some() {
						return self;
					}

					let queue_capacity = $crate::worker!(@queue $($queue)?);
					let (tx, rx) = $crate::colony::worker::worker_runtime::rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

					let config_arc = ::std::sync::Arc::clone(&self.config);
					let policies = std::sync::Arc::new(
						$crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* })
					);

					let run_loop = {
						let config_arc = ::std::sync::Arc::clone(&config_arc);
						let policies = ::std::sync::Arc::clone(&policies);
						$crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
					};

					let join = $crate::colony::worker::worker_runtime::rt::spawn(run_loop);
					Self { sender: Some(tx), join: Some(join), queue: queue_capacity, config: ::std::sync::Arc::clone(&self.config), trace }
				}
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt
	) => {
		impl $worker_name {
			pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
				if self.sender.is_some() {
					return self;
				}

				let queue_capacity = $crate::worker!(@queue $($queue)?);
				let (tx, rx) = $crate::colony::worker::worker_runtime::rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

				let policies = std::sync::Arc::new(
					$crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* })
				);

				let run_loop = {
					let policies = ::std::sync::Arc::clone(&policies);
					$crate::worker!(@run_loop rx, (config None), policies, $handler)
				};

				let join = $crate::colony::worker::worker_runtime::rt::spawn(run_loop);
				Self { sender: Some(tx), join: Some(join), queue: queue_capacity, config: ::std::sync::Arc::clone(&self.config), trace }
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{},
		$handler:tt
	) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
					if self.sender.is_some() {
						return self;
					}

					let queue_capacity = $crate::worker!(@queue $($queue)?);
					let (tx, rx) = $crate::colony::worker::worker_runtime::rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

					let config_arc = ::std::sync::Arc::clone(&self.config);
					let policies = ::std::sync::Arc::new(
						$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
							.build(),
					);

					let run_loop = {
						let config_arc = ::std::sync::Arc::clone(&config_arc);
						let policies = ::std::sync::Arc::clone(&policies);
						$crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
					};

					let join = $crate::colony::worker::worker_runtime::rt::spawn(run_loop);
					Self { sender: Some(tx), join: Some(join), queue: queue_capacity, config: ::std::sync::Arc::clone(&self.config), trace }
				}
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{},
		$handler:tt
	) => {
		impl $worker_name {
			pub fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> Self {
				if self.sender.is_some() {
					return self;
				}

				let queue_capacity = $crate::worker!(@queue $($queue)?);
				let (tx, rx) = $crate::colony::worker::worker_runtime::rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

				let policies = ::std::sync::Arc::new(
					$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
						.build(),
				);

				let join = $crate::colony::worker::worker_runtime::rt::spawn(async move {
					let policies = ::std::sync::Arc::clone(&policies);
					$crate::worker!(@run_loop rx, (config None), policies, $handler).await;
				});

				Self { sender: Some(tx), join: Some(join), queue: queue_capacity, config: self.config, trace }
			}
		}
	};

	(@impl_new $worker_name:ident, config, { $($cfg_field:ident: $cfg_ty:ty,)* }) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub fn new(config: [<$worker_name Conf>]) -> Self {
					Self {
						sender: None,
						join: None,
						queue: 0,
						config: ::std::sync::Arc::new(config),
						trace: ::std::sync::Arc::new($crate::trace::TraceCollector::new()),
					}
				}
			}
		}
	};

	(@impl_new $worker_name:ident, no_config, {}) => {
		impl $worker_name {
			pub fn new(_: ()) -> Self {
				Self {
					sender: None,
					join: None,
					queue: 0,
					config: ::std::sync::Arc::new(()),
					trace: ::std::sync::Arc::new($crate::trace::TraceCollector::new()),
				}
			}
		}
	};

	(@impl_worker_trait $worker_name:ident, $input:ty, $output:ty, config, { $($cfg_field:ident: $cfg_ty:ty,)* }) => {
		$crate::paste::paste! {
			impl $crate::colony::worker::Worker for $worker_name {
				type Input = $input;
				type Output = $output;
				type Config = [<$worker_name Conf>];

				fn new(config: Self::Config) -> Self {
					$worker_name::new(config)
				}

				fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> $crate::colony::worker::WorkerStartFuture<Self> {
					Box::pin(async move {
						let started = $worker_name::start(self, trace);
						Ok(started)
					})
				}

				fn relay(
					&self,
					message: ::std::sync::Arc<Self::Input>,
				) -> $crate::colony::worker::WorkerRelayFuture<Self::Output> {
					let sender = self.sender.clone();
					let trace = ::std::sync::Arc::clone(&self.trace);
					Box::pin(async move {
						let sender = sender.as_ref().ok_or($crate::colony::worker::WorkerRelayError::QueueClosed)?;
						let (tx, rx) = $crate::colony::worker::worker_runtime::rt::oneshot();
						let result = $crate::colony::worker::worker_runtime::rt::send(
							sender,
							$crate::colony::worker::WorkerRequest { message, respond_to: tx, trace },
						)
						.await;
						result.map_err(|_| $crate::colony::worker::WorkerRelayError::QueueClosed)?;

						let response = $crate::colony::worker::worker_runtime::rt::wait_response(rx).await;
						match response {
							Ok(Ok(output)) => Ok(output),
							Ok(Err(status)) => Err($crate::colony::worker::WorkerRelayError::Rejected(status)),
							Err(_) => Err($crate::colony::worker::WorkerRelayError::ResponseDropped),
						}
					})
				}

				fn kill(mut self) -> ::core::result::Result<(), std::io::Error> {
					#[cfg(feature = "tokio")]
					{
						use std::io::{Error, ErrorKind};
						$crate::colony::worker::block_on_worker_future(async move {
							if let Some(sender) = self.sender.take() {
								drop(sender);
							}

							if let Some(handle) = self.join.take() {
								$crate::colony::worker::worker_runtime::rt::join(handle)
									.await
									.map_err(|err| Error::new(ErrorKind::Other, err))
							} else {
								Ok(())
							}
						})?
					}
					#[cfg(all(not(feature = "tokio"), feature = "std"))]
					{
						if let Some(sender) = self.sender.take() {
							drop(sender);
						}

						if let Some(handle) = self.join.take() {
							$crate::colony::worker::worker_runtime::rt::join(handle)
						} else {
							Ok(())
						}
					}
					#[cfg(not(any(feature = "tokio", feature = "std")))]
					{
						let _ = self;
						Err(std::io::Error::new(
							std::io::ErrorKind::Other,
							"worker kill requires either `tokio` or `std` feature",
						))
					}
				}

				fn queue_capacity(&self) -> usize {
					self.queue
				}
			}

			impl $crate::colony::worker::WorkerMetadata for $worker_name {
				fn name() -> &'static str {
					stringify!($worker_name)
				}
			}
		}
	};

	(@impl_worker_trait $worker_name:ident, $input:ty, $output:ty, no_config, {}) => {
		impl $crate::colony::worker::Worker for $worker_name {
			type Input = $input;
			type Output = $output;
			type Config = ();

			fn new(config: Self::Config) -> Self {
				$worker_name::new(config)
			}

			fn start(self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) -> $crate::colony::worker::WorkerStartFuture<Self> {
				Box::pin(async move {
					let started = $worker_name::start(self, trace);
					Ok(started)
				})
			}

			fn relay(
				&self,
				message: ::std::sync::Arc<Self::Input>,
			) -> $crate::colony::worker::WorkerRelayFuture<Self::Output> {
				let sender = self.sender.clone();
				let trace = ::std::sync::Arc::clone(&self.trace);
				Box::pin(async move {
					let sender = sender.as_ref().ok_or($crate::colony::worker::WorkerRelayError::QueueClosed)?;
					let (tx, rx) = $crate::colony::worker::worker_runtime::rt::oneshot();
					let result = $crate::colony::worker::worker_runtime::rt::send(
						sender,
						$crate::colony::worker::WorkerRequest { message, respond_to: tx, trace },
					)
					.await;
					result.map_err(|_| $crate::colony::worker::WorkerRelayError::QueueClosed)?;

					let response = $crate::colony::worker::worker_runtime::rt::wait_response(rx).await;
					match response {
						Ok(Ok(output)) => Ok(output),
						Ok(Err(status)) => Err($crate::colony::worker::WorkerRelayError::Rejected(status)),
						Err(_) => Err($crate::colony::worker::WorkerRelayError::ResponseDropped),
					}
				})
			}

			fn kill(mut self) -> ::core::result::Result<(), std::io::Error> {
				#[cfg(feature = "tokio")]
				{
					use std::io::{Error, ErrorKind};
					$crate::colony::worker::block_on_worker_future(async move {
						if let Some(sender) = self.sender.take() {
							drop(sender);
						}

						if let Some(handle) = self.join.take() {
							$crate::colony::worker::worker_runtime::rt::join(handle)
								.await
								.map_err(|err| Error::new(ErrorKind::Other, err))
						} else {
							Ok(())
						}
					})?
				}
				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				{
					if let Some(sender) = self.sender.take() {
						drop(sender);
					}

					if let Some(handle) = self.join.take() {
						$crate::colony::worker::worker_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
				#[cfg(not(any(feature = "tokio", feature = "std")))]
				{
					let _ = self;
					Err(std::io::Error::new(
						std::io::ErrorKind::Other,
						"worker kill requires either `tokio` or `std` feature",
					))
				}
			}

			fn queue_capacity(&self) -> usize {
				self.queue
			}
		}

		impl $crate::colony::worker::WorkerMetadata for $worker_name {
			fn name() -> &'static str {
				stringify!($worker_name)
			}
		}
	};

	(@run_loop $rx:ident, (config Some($config_arc:ident)), $policies:ident, (|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)) => {{
		let mut receiver = $rx;
		let config_arc = $config_arc;
		let policies = $policies;
		async move {
			while let Some(request) = $crate::colony::worker::worker_runtime::rt::recv(&mut receiver).await {
				let $crate::colony::worker::WorkerRequest { message, respond_to, trace } = request;
				if let Err(status) = $crate::worker!(@evaluate_policies policies, &message) {
					let _ = respond_to.send(Err(status));
					continue;
				}
				let $message_ident = message;
				let $trace_ident = trace;
				let $config_ident = config_arc.as_ref();
				let output = (async move $handler_block).await;
				let _ = respond_to.send(Ok(output));
			}
		}
	}};

	(@run_loop $rx:ident, (config None), $policies:ident, (|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)) => {{
		let mut receiver = $rx;
		let policies = $policies;
		async move {
			while let Some(request) = $crate::colony::worker::worker_runtime::rt::recv(&mut receiver).await {
				let $crate::colony::worker::WorkerRequest { message, respond_to, trace } = request;
				if let Err(status) = $crate::worker!(@evaluate_policies policies, &message) {
					let _ = respond_to.send(Err(status));
					continue;
				}
				let $message_ident = message;
				let $trace_ident = trace;
				let $config_ident = ();
				let output = (async move $handler_block).await;
				let _ = respond_to.send(Ok(output));
			}
		}
	}};

	(@evaluate_policies $policies:expr, $message:expr) => {{
        let __result: ::core::result::Result<(), $crate::policy::TransitStatus> = (|| {
            for gate in $policies.receptor_gates().iter() {
                let status = gate.evaluate($message.as_ref());
                if status != $crate::policy::TransitStatus::Accepted {
                    return Err(status);
                }
            }
            Ok(())
        })();
        __result
    }};

	(@build_policies $input:ty, {}) => {{
		$crate::colony::worker::WorkerPolicyBuilder::<$input>::default().build()
	}};

	(@build_policies $input:ty, { $( with_receptor_gate : [ $( $gate:expr ),* $(,)? ] ),* $(,)? }) => {{
		$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
			$(.with_receptor_gate([ $( $gate ),* ]))*
			.build()
	}};


	(@drop_impl $worker_name:ident) => {
		impl Drop for $worker_name {
			fn drop(&mut self) {
				if let Some(sender) = self.sender.take() {
					drop(sender);
				}

				if let Some(handle) = self.join.take() {
					$crate::colony::worker::worker_runtime::rt::abort(&handle);
				}
			}
		}
	};
}
