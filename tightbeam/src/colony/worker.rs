/*
///WORKER SPEC

#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
struct RequestMessage {
	content: String,
	lucky_number: u32,
}

#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
struct ResponseMessage {
	result: String,
	is_winner: bool,
}

#[derive(Sequence, Beamable, Copy, Clone, Debug, PartialEq)]
struct PongMessage {
	result: String,
}

/// Checklist for container assertions
#[derive(Sequence, Beamable, Copy, Clone, Debug, PartialEq)]
struct LottoTicket {
	lotto_number: u32,
}

impl From<RequestMessage> for LottoTicket {
	fn from(msg: RequestMessage) -> Self {
		Self { lotto_number: msg.lucky_number }
	}
}

/// Default gate that only takes PING
#[derive(Default)]
pub struct PingGate;

impl GatePolicy for PingGate {
	fn evaluate(&self, maybe_ping: &Frame) -> TransitStatus {
		let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
		if decoded.content == "PING" {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}
}

worker! {
	name: LuckyNumberDeterminer<bool>
	config: {
		lotto_number: u32,
	},
	handle: |message, config| async move {
		let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
		let is_winner = decoded.lucky_number == config.lotto_number;
		is_winner
	}
}

worker! {
	name: PingPongWorker<Option<PongMessage>>,
	policies: {
		with_collector_gate: PingGate
	},
	config: {
		expected_message: String,
	},
	handle: |message, config| async move {
		let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
		if decoded.content == config.expected_message {
			Some(PongMessage {
				result: "PONG".to_string(),
			})
		} else {
			None
		}
	}
}

servlet! {
	name: PingPongWorker,
	protocol: TokioListener,
	policies: {
		with_collector_gate: crate::policy::AcceptAllGate
	},
	config: {
		lotto_number: u32,
		magic_word: String
	},
	workers: |config| {
		ant: LuckyNumberDeterminer::start(LuckyNumberDeterminerConfig { lotto_number: config.lotto_number }),
		bee: PingPongWorker::start(PingPongWorkerConfig { expected_message: config.magic_word })
	},
	handle: |message, config, workers| async move {
		// Get the worker mpsc transmiters
		let (ant_tx, bee_tx) = workers;

		// Send the message to the workers
		let lotto_ticket = LottoTicket::from(message);
		let is_winner_future = ant_tx.send(lotto_ticket);
		let response_future = bee_tx.send(message);

		// Await workers and join results
		let (is_winner, response) = std::thread::join!(is_winner_future, response_future);
		let is_winner = is_winner??;
		let response = response??;

		if let Some(pong) = response {
			Some(crate::compose! {
				V0: id: message.metadata.id.clone(),
					order: 1_700_000_000u64,
					message: ResponseMessage {
						result: pong.result,
						is_winner,
					}
			}.ok()?)
		} else {
			None
		}
	}
}
*/

use std::fmt;
#[cfg(not(feature = "tokio"))]
use std::{sync::mpsc, thread};
#[cfg(feature = "tokio")]
use tokio::sync::oneshot;

#[cfg(feature = "tokio")]
type WorkerChannel<I, O> = tokio::sync::mpsc::Sender<WorkerRequest<I, O>>;
#[cfg(not(feature = "tokio"))]
type WorkerChannel<I, O> = mpsc::SyncSender<WorkerRequest<I, O>>;

#[cfg(feature = "tokio")]
type WorkerResponseSender<O> = oneshot::Sender<O>;
#[cfg(feature = "tokio")]
type WorkerResponseReceiver<O> = oneshot::Receiver<O>;
#[cfg(not(feature = "tokio"))]
type WorkerResponseSender<O> = mpsc::SyncSender<O>;
#[cfg(not(feature = "tokio"))]
type WorkerResponseReceiver<O> = mpsc::Receiver<O>;

#[cfg(feature = "tokio")]
type WorkerJoinHandle = tokio::task::JoinHandle<()>;
#[cfg(not(feature = "tokio"))]
type WorkerJoinHandle = thread::JoinHandle<()>;
#[cfg(feature = "tokio")]
type WorkerJoinResult = Result<(), tokio::task::JoinError>;
#[cfg(not(feature = "tokio"))]
type WorkerJoinResult = thread::Result<()>;

pub(crate) struct WorkerRequest<I, O> {
	pub(crate) input: I,
	pub(crate) respond_to: WorkerResponseSender<O>,
}

#[derive(Debug)]
pub enum WorkerError {
	QueueClosed,
	QueueFull,
	ResponseDropped,
}

impl fmt::Display for WorkerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::QueueClosed => f.write_str("worker channel closed"),
			Self::QueueFull => f.write_str("worker channel full"),
			Self::ResponseDropped => f.write_str("worker response channel dropped"),
		}
	}
}

impl std::error::Error for WorkerError {}

pub struct WorkerSender<I, O> {
	inner: WorkerChannel<I, O>,
	#[cfg(not(feature = "tokio"))]
	capacity: usize,
}

impl<I, O> Clone for WorkerSender<I, O> {
	fn clone(&self) -> Self {
		#[cfg(feature = "tokio")]
		{
			Self { inner: self.inner.clone() }
		}
		#[cfg(not(feature = "tokio"))]
		{
			Self { inner: self.inner.clone(), capacity: self.capacity }
		}
	}
}

impl<I, O> WorkerSender<I, O> {
	pub(crate) fn new(inner: WorkerChannel<I, O>, capacity: usize) -> Self {
		#[cfg(feature = "tokio")]
		{
			let _ = capacity;
			Self { inner }
		}
		#[cfg(not(feature = "tokio"))]
		{
			Self { inner, capacity }
		}
	}

	#[cfg(feature = "tokio")]
	pub async fn send(&self, input: I) -> Result<O, WorkerError>
	where
		I: Send,
		O: Send,
	{
		let (tx, rx): (WorkerResponseSender<O>, WorkerResponseReceiver<O>) = oneshot::channel();
		self.inner
			.send(WorkerRequest { input, respond_to: tx })
			.await
			.map_err(|_| WorkerError::QueueClosed)?;
		rx.await.map_err(|_| WorkerError::ResponseDropped)
	}

	#[cfg(not(feature = "tokio"))]
	pub fn send(&self, input: I) -> Result<O, WorkerError>
	where
		I: Send + 'static,
		O: Send + 'static,
	{
		let (tx, rx): (WorkerResponseSender<O>, WorkerResponseReceiver<O>) = mpsc::sync_channel(1);
		self.inner
			.send(WorkerRequest { input, respond_to: tx })
			.map_err(|_| WorkerError::QueueClosed)?;
		rx.recv().map_err(|_| WorkerError::ResponseDropped)
	}

	#[cfg(feature = "tokio")]
	pub fn capacity(&self) -> usize {
		self.inner.max_capacity()
	}

	#[cfg(not(feature = "tokio"))]
	pub fn capacity(&self) -> usize {
		self.capacity
	}
}

pub struct WorkerHandle<I, O> {
	sender: WorkerSender<I, O>,
	join: Option<WorkerJoinHandle>,
}

impl<I, O> WorkerHandle<I, O> {
	pub(crate) fn new(sender: WorkerSender<I, O>, join: WorkerJoinHandle) -> Self {
		Self { sender, join: Some(join) }
	}

	pub fn sender(&self) -> WorkerSender<I, O> {
		self.sender.clone()
	}

	pub fn into_sender(self) -> WorkerSender<I, O> {
		self.sender.clone()
	}

	#[cfg(feature = "tokio")]
	pub async fn join(mut self) -> WorkerJoinResult {
		if let Some(handle) = self.join.take() {
			handle.await
		} else {
			Ok(())
		}
	}

	#[cfg(not(feature = "tokio"))]
	pub fn join(mut self) -> WorkerJoinResult {
		if let Some(handle) = self.join.take() {
			handle.join()
		} else {
			Ok(())
		}
	}
}

impl<I, O> Drop for WorkerHandle<I, O> {
	fn drop(&mut self) {
		if let Some(handle) = self.join.take() {
			#[cfg(feature = "tokio")]
			handle.abort();

			#[cfg(not(feature = "tokio"))]
			{
				let _ = handle.join();
			}
		}
	}
}

#[macro_export]
macro_rules! worker {
    // Config first, then policies
    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
        policies: { $($policy_key:ident: $policy_val:expr),+ $(,)? },
        handle: |$message:ident, $config:ident| $handler:expr $(,)?
    ) => {
        $crate::worker!(
            @inner_config_policies
            worker = $worker_name,
            input_ty = $input,
            output_ty = $output,
            queue = $crate::worker!(@queue $( $queue )?),
            handler = { message = $message, config = $config, expr = $handler },
            config_fields = { $( $cfg_field : $cfg_ty ),* },
            policies = { $( $policy_key : $policy_val ),+ }
        );
    };

    // Policies first, then config (alternative order)
    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        policies: { $($policy_key:ident: $policy_val:expr),+ $(,)? },
        config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
        handle: |$message:ident, $config:ident| $handler:expr $(,)?
    ) => {
        $crate::worker!(
            @inner_config_policies
            worker = $worker_name,
            input_ty = $input,
            output_ty = $output,
            queue = $crate::worker!(@queue $( $queue )?),
            handler = { message = $message, config = $config, expr = $handler },
            config_fields = { $( $cfg_field : $cfg_ty ),* },
            policies = { $( $policy_key : $policy_val ),+ }
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        policies: { $($policy_key:ident: $policy_val:expr),+ $(,)? },
        handle: |$message:ident| $handler:expr $(,)?
    ) => {
        $crate::worker!(
            @inner_policies
            worker = $worker_name,
            input_ty = $input,
            output_ty = $output,
            queue = $crate::worker!(@queue $( $queue )?),
            handler = { message = $message, expr = $handler },
            policies = { $( $policy_key : $policy_val ),+ }
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
        handle: |$message:ident, $config:ident| $handler:expr $(,)?
    ) => {
        $crate::worker!(
            @inner_config
            worker = $worker_name,
            input_ty = $input,
            output_ty = $output,
            queue = $crate::worker!(@queue $( $queue )?),
            handler = { message = $message, config = $config, expr = $handler },
            config_fields = { $( $cfg_field : $cfg_ty ),* }
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        handle: |$message:ident| $handler:expr $(,)?
    ) => {
        $crate::worker!(
            @inner_basic
            worker = $worker_name,
            input_ty = $input,
            output_ty = $output,
            queue = $crate::worker!(@queue $( $queue )?),
            handler = { message = $message, expr = $handler }
        );
    };

    (@inner_config_policies
        worker = $worker_name:ident,
        input_ty = $input_ty:ty,
        output_ty = $output_ty:ty,
        queue = $queue:expr,
        handler = { message = $message_ident:ident, config = $config_ident:ident, expr = $handler_expr:expr },
        config_fields = { $( $cfg_field:ident : $cfg_ty:ty ),* },
        policies = { $( $policy_key:ident : $policy_val:expr ),+ }
    ) => {
        paste::paste! {
            pub struct $worker_name;

            #[derive(Debug)]
            pub struct [<$worker_name Config>] {
                $(pub $cfg_field: $cfg_ty,)*
            }

            pub type [<$worker_name Sender>] =
                $crate::colony::worker::WorkerSender<$input_ty, crate::Result<$output_ty>>;
            pub type [<$worker_name Handle>] =
                $crate::colony::worker::WorkerHandle<$input_ty, crate::Result<$output_ty>>;

            impl $worker_name {
                pub const fn queue_capacity() -> usize {
                    $queue
                }

                #[cfg(feature = "tokio")]
                pub async fn start(config: [<$worker_name Config>]) -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                    [<$worker_name Config>]: Send + Sync + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<
                        $input_ty,
                        crate::Result<$output_ty>
                    >>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);
                    let config = std::sync::Arc::new(config);

                    $( let $policy_key = std::sync::Arc::new($policy_val); )*

                    let task = tokio::spawn({
                        let config = std::sync::Arc::clone(&config);
                        $( let $policy_key = std::sync::Arc::clone(&$policy_key); )*
                        async move {
                            while let Some(job) = rx.recv().await {
                                let respond_to = job.respond_to;
                                let input = job.input;

                                match $crate::worker!(@policy_check (&input) $(, $policy_key)*) {
                                    Ok(()) => {
                                        let $message_ident = input;
                                        let $config_ident = std::sync::Arc::clone(&config);
                                        let result = ($handler_expr).await;
                                        let _ = respond_to.send(Ok(result));
                                    }
                                    Err(err) => {
                                        let _ = respond_to.send(Err(err));
                                    }
                                }
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }

                #[cfg(not(feature = "tokio"))]
                pub fn start(config: [<$worker_name Config>]) -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                    [<$worker_name Config>]: Send + Sync + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, rx) = std::sync::mpsc::sync_channel::<$crate::colony::worker::WorkerRequest<
                        $input_ty,
                        crate::Result<$output_ty>
                    >>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);
                    let config = std::sync::Arc::new(config);

                    $( let $policy_key = std::sync::Arc::new($policy_val); )*

                    let task = std::thread::spawn({
                        let config = std::sync::Arc::clone(&config);
                        $( let $policy_key = std::sync::Arc::clone(&$policy_key); )*
                        move || {
                            while let Ok(job) = rx.recv() {
                                let respond_to = job.respond_to;
                                let input = job.input;

                                match $crate::worker!(@policy_check (&input) $(, $policy_key)*) {
                                    Ok(()) => {
                                        let $message_ident = input;
                                        let $config_ident = std::sync::Arc::clone(&config);
                                        let result = $handler_expr;
                                        let _ = respond_to.send(Ok(result));
                                    }
                                    Err(err) => {
                                        let _ = respond_to.send(Err(err));
                                    }
                                }
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }
            }
        }
    };

    (@inner_policies
        worker = $worker_name:ident,
        input_ty = $input_ty:ty,
        output_ty = $output_ty:ty,
        queue = $queue:expr,
        handler = { message = $message_ident:ident, expr = $handler_expr:expr },
        policies = { $( $policy_key:ident : $policy_val:expr ),+ }
    ) => {
        paste::paste! {
            pub struct $worker_name;

            pub type [<$worker_name Sender>] =
                $crate::colony::worker::WorkerSender<$input_ty, Result<$output_ty, $crate::policy::TransitStatus>>;
            pub type [<$worker_name Handle>] =
                $crate::colony::worker::WorkerHandle<$input_ty, Result<$output_ty, $crate::policy::TransitStatus>>;

            impl $worker_name {
                pub const fn queue_capacity() -> usize {
                    $queue
                }

                #[cfg(feature = "tokio")]
                pub async fn start() -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<
                        $input_ty,
                        Result<$output_ty, $crate::policy::TransitStatus>
                    >>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);

                    $( let $policy_key = std::sync::Arc::new($policy_val); )*

                    let task = tokio::spawn({
                        $( let $policy_key = std::sync::Arc::clone(&$policy_key); )*
                        async move {
                            while let Some(job) = rx.recv().await {
                                let respond_to = job.respond_to;
                                let input = job.input;

                                match $crate::worker!(@policy_check (&input) $(, $policy_key)*) {
                                    Ok(()) => {
                                        let $message_ident = input;
                                        let result = ($handler_expr).await;
                                        let _ = respond_to.send(Ok(result));
                                    }
                                    Err(status) => {
                                        let _ = respond_to.send(Err(status));
                                        continue;
                                    }
                                }
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }

                #[cfg(not(feature = "tokio"))]
                pub fn start() -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, rx) = std::sync::mpsc::sync_channel::<$crate::colony::worker::WorkerRequest<
                        $input_ty,
                        Result<$output_ty, $crate::policy::TransitStatus>
                    >>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);

                    $( let $policy_key = std::sync::Arc::new($policy_val); )*

                    let task = std::thread::spawn({
                        $( let $policy_key = std::sync::Arc::clone(&$policy_key); )*
                        move || {
                            while let Ok(job) = rx.recv() {
                                let respond_to = job.respond_to;
                                let input = job.input;

                                match $crate::worker!(@policy_check (&input) $(, $policy_key)*) {
                                    Ok(()) => {
                                        let $message_ident = input;
                                        let result = $handler_expr;
                                        let _ = respond_to.send(Ok(result));
                                    }
                                    Err(status) => {
                                        let _ = respond_to.send(Err(status));
                                        continue;
                                    }
                                }
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }
            }
        }
    };

    (@inner_config
        worker = $worker_name:ident,
        input_ty = $input_ty:ty,
        output_ty = $output_ty:ty,
        queue = $queue:expr,
        handler = { message = $message_ident:ident, config = $config_ident:ident, expr = $handler_expr:expr },
        config_fields = { $($cfg_field:ident : $cfg_ty:ty ),* }
    ) => {
        paste::paste! {
            pub struct $worker_name;

            #[derive(Debug)]
            pub struct [<$worker_name Config>] {
                $(pub $cfg_field: $cfg_ty,)*
            }

            pub type [<$worker_name Sender>] = $crate::colony::worker::WorkerSender<$input_ty, $output_ty>;
            pub type [<$worker_name Handle>] = $crate::colony::worker::WorkerHandle<$input_ty, $output_ty>;

            impl $worker_name {
                pub const fn queue_capacity() -> usize {
                    $queue
                }

                #[cfg(feature = "tokio")]
                pub async fn start(config: [<$worker_name Config>]) -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                    [<$worker_name Config>]: Send + Sync + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input_ty, $output_ty>>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);
                    let config = std::sync::Arc::new(config);

                    let task = tokio::spawn({
                        let config = std::sync::Arc::clone(&config);
                        async move {
                            while let Some(job) = rx.recv().await {
                                let respond_to = job.respond_to;
                                let $message_ident = job.input;
                                let $config_ident = std::sync::Arc::clone(&config);
                                let result = ($handler_expr).await;
                                let _ = respond_to.send(result);
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }

                #[cfg(not(feature = "tokio"))]
                pub fn start(config: [<$worker_name Config>]) -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                    [<$worker_name Config>]: Send + Sync + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, rx) = std::sync::mpsc::sync_channel::<$crate::colony::worker::WorkerRequest<$input_ty, $output_ty>>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);
                    let config = std::sync::Arc::new(config);

                    let task = std::thread::spawn({
                        let config = std::sync::Arc::clone(&config);
                        move || {
                            while let Ok(job) = rx.recv() {
                                let respond_to = job.respond_to;
                                let $message_ident = job.input;
                                let $config_ident = std::sync::Arc::clone(&config);
                                let result = $handler_expr;
                                let _ = respond_to.send(result);
                            }
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }
            }
        }
    };

    (@inner_basic
        worker = $worker_name:ident,
        input_ty = $input_ty:ty,
        output_ty = $output_ty:ty,
        queue = $queue:expr,
        handler = { message = $message_ident:ident, expr = $handler_expr:expr }
    ) => {
        paste::paste! {
            pub struct $worker_name;

            pub type [<$worker_name Sender>] = $crate::colony::worker::WorkerSender<$input_ty, $output_ty>;
            pub type [<$worker_name Handle>] = $crate::colony::worker::WorkerHandle<$input_ty, $output_ty>;

            impl $worker_name {
                pub const fn queue_capacity() -> usize {
                    $queue
                }

                #[cfg(feature = "tokio")]
                pub async fn start() -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input_ty, $output_ty>>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);

                    let task = tokio::spawn(async move {
                        while let Some(job) = rx.recv().await {
                            let respond_to = job.respond_to;
                            let $message_ident = job.input;
                            let result = ($handler_expr).await;
                            let _ = respond_to.send(result);
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }

                #[cfg(not(feature = "tokio"))]
                pub fn start() -> $crate::Result<[<$worker_name Handle>]>
                where
                    $input_ty: Send + 'static,
                    $output_ty: Send + 'static,
                {
                    let capacity = Self::queue_capacity();
                    let (tx, rx) = std::sync::mpsc::sync_channel::<$crate::colony::worker::WorkerRequest<$input_ty, $output_ty>>(capacity);
                    let sender = $crate::colony::worker::WorkerSender::new(tx, capacity);

                    let task = std::thread::spawn(move || {
                        while let Ok(job) = rx.recv() {
                            let respond_to = job.respond_to;
                            let $message_ident = job.input;
                            let result = $handler_expr;
                            let _ = respond_to.send(result);
                        }
                    });

                    Ok($crate::colony::worker::WorkerHandle::new(sender, task))
                }
            }
        }
    };

    (@policy_check $input:expr $(, $policy_key:ident )* ) => {
        $crate::worker!(@policy_check_impl $input $(, $policy_key )* )
    };

    (@policy_check_impl $input:expr) => { Ok(()) };
    (@policy_check_impl $input:expr, with_receptor $(, $rest:ident )* ) => {{
        use $crate::policy::{ReceptorPolicy, TransitStatus};
        match with_receptor.evaluate($input) {
            TransitStatus::Accepted => $crate::worker!(@policy_check_impl $input $(, $rest )* ),
            status => Err(status),
        }
    }};
    (@policy_check_impl $input:expr, $other:ident $(, $rest:ident )* ) => {
        $crate::worker!(@policy_check_impl $input $(, $rest )* )
    };

    (@queue) => { 64usize };
    (@queue $queue:expr) => { $queue };
}

#[cfg(test)]
mod tests {
	use crate::der::Sequence;
	use crate::policy::{ReceptorPolicy, TransitStatus};
	use crate::{Beamable, Result};

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct RequestMessage {
		content: String,
		lucky_number: u32,
	}

	#[derive(Sequence, Beamable, Clone, Debug, PartialEq)]
	struct PongMessage {
		result: String,
	}

	/// Default gate that only takes PING
	#[derive(Default)]
	pub struct PingGate;

	impl ReceptorPolicy<RequestMessage> for PingGate {
		fn evaluate(&self, maybe_ping: &RequestMessage) -> TransitStatus {
			if maybe_ping.content == "PING" {
				TransitStatus::Accepted
			} else {
				TransitStatus::Forbidden
			}
		}
	}

	worker! {
		name: LuckyNumberDeterminer<RequestMessage, Result<bool>>,
		config: {
			lotto_number: u32,
		},
		handle: |message, config| async move {
			let is_winner = message.lucky_number == config.lotto_number;
			Ok(is_winner)
		}
	}

	worker! {
		name: PingPongWorker<RequestMessage, Option<PongMessage>>,
		config: {
			expected_message: String,
		},
		policies: {
			with_receptor: PingGate
		},
		handle: |message, config| async move {
			if message.content == config.expected_message {
				Some(PongMessage {
					result: "PONG".to_string(),
				})
			} else {
				None
			}
		}
	}

	#[test]
	fn simple() {}
}
