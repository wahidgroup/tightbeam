use std::sync::Arc;

#[cfg(feature = "derive")]
use crate::Errorizable;

use crate::policy::{ReceptorPolicy, TransitStatus};
use crate::Message;

pub struct WorkerRequest<I: Send, O> {
    pub message: I,
    pub respond_to: tokio::sync::oneshot::Sender<Result<O, TransitStatus>>,
}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum WorkerRelayError {
    #[cfg_attr(feature = "derive", error("Worker queue closed"))]
    QueueClosed,
    #[cfg_attr(feature = "derive", error("Worker response channel dropped"))]
    ResponseDropped,
    #[cfg_attr(feature = "derive", error("Message rejected with status {:?}"))]
    #[cfg_attr(feature = "derive", from)]
    Rejected(TransitStatus),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for WorkerRelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QueueClosed => f.write_str("worker queue closed"),
            Self::ResponseDropped => f.write_str("worker response channel dropped"),
            Self::Rejected(status) => write!(f, "message rejected with status {:?}", status),
        }
    }
}

#[cfg(not(feature = "derive"))]
impl std::error::Error for WorkerRelayError {}

pub struct WorkerPolicies<I: Send> {
    pub(crate) receptor_gate: Option<Arc<dyn ReceptorPolicy<I> + Send + Sync>>,
}

impl<I: Send> Default for WorkerPolicies<I> {
    fn default() -> Self {
        Self {
            receptor_gate: None,
        }
    }
}

pub struct WorkerPolicyBuilder<I: Send> {
    receptor_gate: Option<Arc<dyn ReceptorPolicy<I> + Send + Sync>>,
}

impl<I: Send> Default for WorkerPolicyBuilder<I> {
    fn default() -> Self {
        Self {
            receptor_gate: None,
        }
    }
}

impl<I: Message + Send> WorkerPolicyBuilder<I> {
    pub fn build(self) -> WorkerPolicies<I> {
        WorkerPolicies {
            receptor_gate: self.receptor_gate,
        }
    }

    pub fn with_receptor_gate<R>(mut self, gate: R) -> Self
    where
        R: ReceptorPolicy<I> + Send + Sync + 'static,
    {
        self.receptor_gate = Some(Arc::new(gate));
        self
    }
}

#[macro_export]
macro_rules! worker {
    (@queue $queue:expr) => { $queue };
    (@queue) => { 64usize };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
        policies: { $( $policy_method:ident : $policy_expr:expr ),* $(,)? },
        handle: |$message_ident:ident, $config_ident:ident| async move $handler_block:block
    ) => {
        $crate::worker!(@generate
            $worker_name, $input, $output, [$($queue)?],
            config,
            { $($cfg_field: $cfg_ty,)* },
            { $( $policy_method : $policy_expr ),* },
            (|$message_ident, $config_ident| async move $handler_block)
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        policies: { $( $policy_method:ident : $policy_expr:expr ),* $(,)? },
        handle: |$message_ident:ident| async move $handler_block:block
    ) => {
        $crate::worker!(@generate
            $worker_name, $input, $output, [$($queue)?],
            no_config,
            {},
            { $( $policy_method : $policy_expr ),* },
            (|$message_ident| async move $handler_block)
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
        handle: |$message_ident:ident, $config_ident:ident| async move $handler_block:block
    ) => {
        $crate::worker!(@generate
            $worker_name, $input, $output, [$($queue)?],
            config,
            { $($cfg_field: $cfg_ty,)* },
            {},
            (|$message_ident, $config_ident| async move $handler_block)
        );
    };

    (
        name: $worker_name:ident < $input:ty, $output:ty >,
        $(queue: $queue:expr,)?
        handle: |$message_ident:ident| async move $handler_block:block
    ) => {
        $crate::worker!(@generate
            $worker_name, $input, $output, [$($queue)?],
            no_config,
            {},
            {},
            (|$message_ident| async move $handler_block)
        );
    };

    (@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
        $config_kind:ident,
        { $($cfg_field:ident: $cfg_ty:ty,)* },
        { $( $policy_method:ident : $policy_expr:expr ),* },
        $handler:tt) => {
        $crate::worker!(@impl_struct $worker_name, $input, $output, { $($cfg_field: $cfg_ty,)* });
        $crate::worker!(@impl_methods
            $worker_name, $input, $output, [$($queue)?],
            $config_kind,
            { $($cfg_field: $cfg_ty,)* },
            { $( $policy_method : $policy_expr ),* },
            $handler
        );
        $crate::worker!(@drop_impl $worker_name);
    };

    (@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
        no_config,
        {},
        { $( $policy_method:ident : $policy_expr:expr ),* },
        $handler:tt) => {
        $crate::worker!(@impl_struct $worker_name, $input, $output, {});
        $crate::worker!(@impl_methods
            $worker_name, $input, $output, [$($queue)?],
            no_config,
            {},
            { $( $policy_method : $policy_expr ),* },
            $handler
        );
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
        $crate::worker!(@drop_impl $worker_name);
    };

    (@impl_struct $worker_name:ident, $input:ty, $output:ty, {}) => {
        pub struct $worker_name {
            sender: Option<tokio::sync::mpsc::Sender<$crate::colony::worker::WorkerRequest<$input, $output>>>,
            join: Option<tokio::task::JoinHandle<()>>,
            queue: usize,
        }
    };

    (@impl_struct $worker_name:ident, $input:ty, $output:ty, { $($cfg_field:ident: $cfg_ty:ty,)* }) => {
        paste::paste! {
            pub struct $worker_name {
                sender: Option<tokio::sync::mpsc::Sender<$crate::colony::worker::WorkerRequest<$input, $output>>>,
                join: Option<tokio::task::JoinHandle<()>>,
                queue: usize,
            }

            #[derive(Clone)]
            pub struct [<$worker_name Config>] {
                $(pub $cfg_field: $cfg_ty,)*
            }
        }
    };

    (@impl_methods
        $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
        config,
        { $($cfg_field:ident: $cfg_ty:ty,)* },
        { $( $policy_method:ident : $policy_expr:expr ),* },
        $handler:tt
    ) => {
        paste::paste! {
            impl $worker_name {
                pub fn start(config: [<$worker_name Config>]) -> crate::Result<Self> {
                    let queue_capacity = $crate::worker!(@queue $($queue)?);
                    let (tx, rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

                    let config_arc = std::sync::Arc::new(config);
                    let policies = std::sync::Arc::new(
                        $crate::worker!(@build_policies $input, { $( $policy_method : $policy_expr ),* })
                    );

                    let join = tokio::spawn({
                        let config_arc = config_arc.clone();
                        let policies = policies.clone();
                        async move {
                            $crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
                        }
                    });

                    Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
                }

                $crate::worker!(@common_methods $input, $output);
            }
        }
    };

    (@impl_methods
        $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
        no_config,
        {},
        { $( $policy_method:ident : $policy_expr:expr ),* },
        $handler:tt
    ) => {
        impl $worker_name {
            pub fn start() -> Result<Self, $crate::TightBeamError> {
                let queue_capacity = $crate::worker!(@queue $($queue)?);
                let (tx, rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

                let policies = Arc::new(
                    $crate::worker!(@build_policies $input, { $( $policy_method : $policy_expr ),* })
                );

                let join = tokio::spawn({
                    let policies = policies.clone();
                    async move {
                        $crate::worker!(@run_loop rx, (config None), policies, $handler)
                    }
                });

                Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
            }

            $crate::worker!(@common_methods $input, $output);
        }
    };

    (@impl_methods
        $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
        config,
        { $($cfg_field:ident: $cfg_ty:ty,)* },
        {},
        $handler:tt
    ) => {
        paste::paste! {
            impl $worker_name {
                pub fn start(config: [<$worker_name Config>]) -> crate::Result<Self> {
                    let queue_capacity = $crate::worker!(@queue $($queue)?);
                    let (tx, rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

                    let config_arc = Arc::new(config);
                    let policies = Arc::new(
                        $crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
                            .build(),
                    );

                    let join = tokio::spawn({
                        let config_arc = config_arc.clone();
                        let policies = policies.clone();
                        async move {
                            $crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
                        }
                    });

                    Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
                }

                $crate::worker!(@common_methods $input, $output);
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
            pub fn start() -> crate::Result<Self> {
                let queue_capacity = $crate::worker!(@queue $($queue)?);
                let (tx, rx) = tokio::sync::mpsc::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

                let policies = Arc::new(
                    $crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
                        .build(),
                );

                let join = tokio::spawn(async move {
                    let policies = policies.clone();
                    $crate::worker!(@run_loop rx, (config None), policies, $handler)
                });

                Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
            }

            $crate::worker!(@common_methods $input, $output);
        }
    };

	(@run_loop $rx:ident, (config Some($config_arc:ident)), $policies:ident, (|$message_ident:ident, $config_ident:ident| async move $handler_block:block)) => {{
        let mut $rx = $rx;
        while let Some(request) = $rx.recv().await {
            let $crate::colony::worker::WorkerRequest { message, respond_to } = request;
            if let Err(status) = $crate::worker!(@evaluate_policies $policies, &message) {
                let _ = respond_to.send(Err(status));
                continue;
            }
            let future = {
                let $message_ident = message;
                let $config_ident = $config_arc.clone();
                async move $handler_block
            };
            let output = future.await;
            let _ = respond_to.send(Ok(output));
        }
    }};

    (@run_loop $rx:ident, (config None), $policies:ident, (|$message_ident:ident| async move $handler_block:block)) => {{
        let mut $rx = $rx;
        while let Some(request) = $rx.recv().await {
            let $crate::colony::worker::WorkerRequest { message, respond_to } = request;
            if let Err(status) = $crate::worker!(@evaluate_policies $policies, &message) {
                let _ = respond_to.send(Err(status));
                continue;
            }
            let future = {
                let $message_ident = message;
                async move $handler_block
            };
            let output = future.await;
            let _ = respond_to.send(Ok(output));
        }
    }};

    (@evaluate_policies $policies:expr, $message:expr) => {{
        if let Some(gate) = $policies.receptor_gate.as_ref() {
            let status = gate.evaluate($message);
            if status == $crate::policy::TransitStatus::Accepted {
                Ok(())
            } else {
                Err(status)
            }
        } else {
            Ok(())
        }
    }};
    
    (@build_policies $input:ty, { $( $policy_method:ident : $policy_expr:expr ),* $(,)? }) => {{
        let builder = $crate::colony::worker::WorkerPolicyBuilder::<$input>::default();
        $(
            let builder = builder.$policy_method($policy_expr);
        )*
        builder.build()
    }};

    (@common_methods $input:ty, $output:ty) => {
        #[allow(dead_code)]
        pub fn queue_capacity(&self) -> usize {
            self.queue
        }

        pub async fn relay(
            &self,
            message: $input,
        ) -> core::result::Result<$output, $crate::colony::worker::WorkerRelayError> {
            let sender = self.sender.as_ref().ok_or($crate::colony::worker::WorkerRelayError::QueueClosed)?;
            let (tx, rx) = tokio::sync::oneshot::channel();

            sender
                .send($crate::colony::worker::WorkerRequest { message, respond_to: tx })
                .await
                .map_err(|_| $crate::colony::worker::WorkerRelayError::QueueClosed)?;

            match rx.await {
                Ok(Ok(output)) => Ok(output),
                Ok(Err(status)) => Err($crate::colony::worker::WorkerRelayError::Rejected(status)),
                Err(_) => Err($crate::colony::worker::WorkerRelayError::ResponseDropped),
            }
        }

        pub async fn shutdown(mut self) -> core::result::Result<(), tokio::task::JoinError> {
            if let Some(sender) = self.sender.take() {
                drop(sender);
            }

            if let Some(handle) = self.join.take() {
                handle.await
            } else {
                Ok(())
            }
        }
    };

    (@drop_impl $worker_name:ident) => {
        impl Drop for $worker_name {
            fn drop(&mut self) {
                if let Some(sender) = self.sender.take() {
                    drop(sender);
                }

                if let Some(handle) = self.join.take() {
                    handle.abort();
                }
            }
        }
    };
}


#[cfg(test)]
mod tests {
    use crate::der::Sequence;
    use crate::policy::{ReceptorPolicy, TransitStatus};
    use crate::{Beamable};
    use crate::colony::worker::WorkerRelayError;

    #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
    pub struct RequestMessage {
        content: String,
        lucky_number: u32,
    }

    #[derive(Sequence, Beamable, Clone, Debug, PartialEq)]
    pub struct PongMessage {
        result: String,
    }

    #[derive(Default)]
    struct PingGate;

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
        name: LuckyNumberDeterminer<RequestMessage, bool>,
        config: {
            lotto_number: u32,
        },
        handle: |message, config| async move {
            let is_winner = message.lucky_number == config.lotto_number;
            is_winner
        }
    }

    worker! {
        name: PingPongWorker<RequestMessage, Option<PongMessage>>,
        config: {
            expected_message: String,
        },
        policies: {
            with_receptor_gate: PingGate::default()
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

	crate::test_worker! {
        name: lucky_number_worker_checks_winner,
        features: ["std"],
        setup: || {
            LuckyNumberDeterminer::start(LuckyNumberDeterminerConfig { lotto_number: 42 })
        },
        assertions: |worker| async move {
            assert_eq!(worker.queue_capacity(), 64);

            let winner = worker.relay(RequestMessage {
                content: "PING".to_string(),
                lucky_number: 42,
            }).await?;
            assert!(winner);

            let loser = worker.relay(RequestMessage {
                content: "PING".to_string(),
                lucky_number: 7,
            }).await?;
            assert!(!loser);

            Ok(())
        }
    }

    crate::test_worker! {
        name: test_ping_pong_worker,
        features: ["std"],
        setup: || {
            PingPongWorker::start(PingPongWorkerConfig {
                expected_message: "PING".to_string(),
            })
        },
        assertions: |worker| async move {
            // Test accepted message
            let ping_msg = RequestMessage {
                content: "PING".to_string(),
                lucky_number: 42,
            };
            let response = worker.relay(ping_msg).await?;
            assert_eq!(response, Some(PongMessage { result: "PONG".to_string() }));

            // Test rejected message
            let pong_msg = RequestMessage {
                content: "PONG".to_string(),
                lucky_number: 42,
            };

            let result = worker.relay(pong_msg).await;
            assert!(matches!(result, Err(WorkerRelayError::Rejected(_))));

            Ok(())
        }
    }
}