//! The four nodes of the DTN path, and the Creation Methods that start each
//! one over a chain of its own.
//!
//! [`DtnRole`] names the identity of a node: its certificate, its keys, its
//! signer, and its pinning policy. [`DtnPath`] holds the parts that every node
//! of one path shares and starts each servlet with its workers.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tightbeam::colony::servlet::{ServletConfig, ServletConfigBuilder, WithCertificate};
use tightbeam::crypto::key::SigningKeySpec;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1, Secp256k1SigningKey};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, CertificateSpec};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, ConnectionPool, GenericClient, PoolConfig};
use tightbeam::TightBeamError;

use crate::dtn::certs::{
	earth_relay_pinning, earth_relay_signer, mars_relay_pinning, mars_relay_signer, mission_control_pinning,
	mission_control_signer, rover_pinning, rover_signer, FrameSigner, SharedCipher, EARTH_RELAY_CERT, EARTH_RELAY_KEY,
	MARS_RELAY_CERT, MARS_RELAY_KEY, MISSION_CONTROL_CERT, MISSION_CONTROL_KEY, ROVER_CERT, ROVER_KEY,
};
use crate::dtn::chain_processor::ChainProcessor;
use crate::dtn::fault_manager::FaultManager;
use crate::dtn::frame_builder::FrameBuilderHelper;
use crate::dtn::messages::{MessageChainState, RelayMessage};
use crate::dtn::ordering::OutOfOrderBuffer;
use crate::dtn::servlets::{
	EarthRelaySatelliteServlet, EarthRelaySatelliteServletConfig, LateAddr, MarsRelaySatelliteServlet,
	MarsRelaySatelliteServletConfig, MissionControlServlet, MissionControlServletConfig, MissionState, RoverServlet,
	RoverServletConfig,
};
use crate::dtn::storage::{FrameStore, StorageRoot};
use crate::dtn::workers::{
	CommandAckHandlerWorker, CommandExecutionWorker, FrameRequestHandlerWorker, FrameRequestHandlerWorkerConfig,
	FrameResponseHandlerWorker, FrameResponseHandlerWorkerConfig, MissionControlTelemetryHandlerWorker,
	MissionControlTelemetryHandlerWorkerConfig, RoverCommandHandlerWorker, RoverCommandHandlerWorkerConfig,
	TelemetryBuilderWorker, TelemetryBuilderWorkerConfig,
};

/// The servlet configuration builder of a node that presents its certificate,
/// with `Env` as its environment.
type NodeConfigBuilder<Env> = ServletConfigBuilder<
	TokioListener,
	RelayMessage,
	DefaultCryptoProvider,
	Env,
	WithCertificate<DefaultCryptoProvider>,
>;

/// One node of the DTN path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtnRole {
	/// The command center on Earth.
	MissionControl,
	/// The relay satellite in orbit around Earth.
	EarthRelay,
	/// The relay satellite in orbit around Mars.
	MarsRelay,
	/// The rover on the surface of Mars.
	Rover,
}

impl DtnRole {
	/// The certificate that the node presents in a TLS handshake.
	pub fn certificate(self) -> CertificateSpec {
		match self {
			Self::MissionControl => MISSION_CONTROL_CERT,
			Self::EarthRelay => EARTH_RELAY_CERT,
			Self::MarsRelay => MARS_RELAY_CERT,
			Self::Rover => ROVER_CERT,
		}
	}

	/// The key of the node, which signs its handshakes and its frames.
	pub fn key(self) -> SigningKeySpec {
		match self {
			Self::MissionControl => MISSION_CONTROL_KEY,
			Self::EarthRelay => EARTH_RELAY_KEY,
			Self::MarsRelay => MARS_RELAY_KEY,
			Self::Rover => ROVER_KEY,
		}
	}

	/// The key of the node as the key that signs its frames.
	pub fn signing_key(self) -> Secp256k1SigningKey {
		let SigningKeySpec::Bytes(bytes) = self.key() else {
			panic!("each DTN key is a SigningKeySpec::Bytes");
		};

		Secp256k1SigningKey::from_slice(bytes).expect("each DTN key is a valid secp256k1 scalar")
	}

	/// The certificate that verifies the frames this node signs.
	pub fn signer(self) -> FrameSigner {
		match self {
			Self::MissionControl => mission_control_signer(),
			Self::EarthRelay => earth_relay_signer(),
			Self::MarsRelay => mars_relay_signer(),
			Self::Rover => rover_signer(),
		}
	}

	/// The name of the node's directory under a storage root.
	pub fn node_name(self) -> &'static str {
		match self {
			Self::MissionControl => "mission_control",
			Self::EarthRelay => "earth_relay",
			Self::MarsRelay => "mars_relay",
			Self::Rover => "rover",
		}
	}

	/// The policy that admits the TLS clients of the node, each a peer on the
	/// path.
	fn pinning(self) -> PublicKeyPinning {
		match self {
			Self::MissionControl => mission_control_pinning(),
			Self::EarthRelay => earth_relay_pinning(),
			Self::MarsRelay => mars_relay_pinning(),
			Self::Rover => rover_pinning(),
		}
	}

	/// A trust store that admits the certificate of this node alone.
	pub fn trust_store(self) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
		let certificate = Certificate::try_from(self.certificate())?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		Ok(Arc::new(builder.with_certificate(certificate)?.build()))
	}

	/// The TLS identity of the node as a client.
	pub fn client_identity(self) -> Result<SigningIdentity, TightBeamError> {
		let key = self.key().to_provider::<Secp256k1>()?;
		SigningIdentity::from_spec(self.certificate(), key)
	}

	/// A pool that dials `peer` as this node over mutual TLS, with at most
	/// 3 connections to each destination.
	pub fn dial_pool(self, peer: Self) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
		let config = PoolConfig { max_connections: 3, ..PoolConfig::default() };
		let pool = ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(peer.trust_store()?)
			.with_client_identity(self.client_identity()?)
			.build();

		Ok(Arc::new(pool))
	}

	/// A client that connects as this node to `peer` at `addr`.
	pub async fn connect(
		self,
		peer: Self,
		addr: TightBeamSocketAddr,
	) -> Result<GenericClient<TokioListener>, TightBeamError> {
		let client = ClientBuilder::<TokioListener>::builder()
			.with_trust_store(peer.trust_store()?)
			.with_client_identity(self.client_identity()?)
			.with_timeout(Duration::from_millis(5000))
			.build()
			.connect(addr)
			.await?;

		Ok(client)
	}

	/// The servlet configuration of the node: its certificate, its key, and
	/// the pinning of its peers, with `config` as its environment.
	fn servlet_config<Env>(self, config: Env) -> Result<NodeConfigBuilder<Env>, TightBeamError> {
		let key = self.key().to_provider::<Secp256k1>()?;
		let validators = vec![Arc::new(self.pinning()) as Arc<dyn CertificateValidation>];
		let builder = ServletConfig::<TokioListener, RelayMessage>::builder()
			.with_certificate(self.certificate(), key, validators)?
			.with_config(Arc::new(config));

		Ok(builder)
	}
}

/// The chain of one node: its chain processor over a frame store of its own,
/// and the frame builder that extends it.
#[derive(Clone)]
pub struct NodeChain {
	/// The chain processor that persists, orders, and validates the frames of
	/// the node.
	pub processor: Arc<ChainProcessor>,
	/// The frame builder that links each outgoing frame into the chain.
	pub frame_builder: Arc<FrameBuilderHelper>,
}

impl NodeChain {
	/// Opens an empty chain in the directory `node` under `storage`.
	pub fn open(storage: &StorageRoot, node: &str) -> Result<Self, TightBeamError> {
		let store = FrameStore::new(storage.node(node))?;
		let processor = ChainProcessor::new(
			Arc::new(RwLock::new(store)),
			Arc::new(RwLock::new(MessageChainState::new(node))),
			Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
		);

		Ok(Self::over(Arc::new(processor)))
	}

	/// The chain over `processor`, with a frame builder that extends it.
	pub fn over(processor: Arc<ChainProcessor>) -> Self {
		let frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&processor)));
		Self { processor, frame_builder }
	}
}

/// The parts that every node of one DTN path shares.
pub struct DtnPath {
	/// The trace that every servlet and worker of the path records into.
	pub trace: Arc<TraceCollector>,
	/// The cipher that Mission Control and the Rover seal each message under,
	/// which every relay holds.
	pub cipher: SharedCipher,
	/// The mission progress that the Rover and Mission Control share.
	pub mission_state: Arc<RwLock<MissionState>>,
	/// The number of command round trips of the mission.
	pub rounds: usize,
}

impl DtnPath {
	/// Starts Mission Control over `chain`, which sends its commands to the
	/// Earth Relay at `earth_relay`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a key or a certificate fails to load, or the servlet fails to bind.
	pub async fn start_mission_control(
		&self,
		chain: &NodeChain,
		earth_relay: TightBeamSocketAddr,
	) -> Result<MissionControlServlet, TightBeamError> {
		let role = DtnRole::MissionControl;
		let config = MissionControlServletConfig {
			mission_control_signing_key: role.signing_key(),
			rover_signer: DtnRole::Rover.signer(),
			earth_relay_signer: DtnRole::EarthRelay.signer(),
			shared_cipher: self.cipher.to_owned(),
			chain_processor: Arc::clone(&chain.processor),
			frame_builder: Arc::clone(&chain.frame_builder),
			earth_relay_addr: earth_relay,
			earth_relay_pool: role.dial_pool(DtnRole::EarthRelay)?,
		};

		let telemetry = MissionControlTelemetryHandlerWorker::new(MissionControlTelemetryHandlerWorkerConfig {
			mission_state: Arc::clone(&self.mission_state),
			max_commands: self.rounds as u64,
		});
		let frame_requests = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
			can_cascade: false, // Mission Control is an origin of the path.
		});
		let frame_responses = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
		});
		let servlet_config = role
			.servlet_config(config)?
			.with_worker(telemetry)
			.with_worker(frame_requests)
			.with_worker(frame_responses)
			.with_worker(CommandAckHandlerWorker::new(()))
			.build();

		MissionControlServlet::start(Arc::clone(&self.trace), servlet_config).await
	}

	/// Starts the Earth Relay over `chain`, between Mission Control at the
	/// address that `mission_control` publishes and the Mars Relay at
	/// `mars_relay`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a key or a certificate fails to load, or the servlet fails to bind.
	pub async fn start_earth_relay(
		&self,
		chain: &NodeChain,
		mars_relay: TightBeamSocketAddr,
		mission_control: &LateAddr,
	) -> Result<EarthRelaySatelliteServlet, TightBeamError> {
		let role = DtnRole::EarthRelay;
		let config = EarthRelaySatelliteServletConfig {
			earth_relay_signing_key: role.signing_key(),
			mission_control_signer: DtnRole::MissionControl.signer(),
			mars_relay_signer: DtnRole::MarsRelay.signer(),
			rover_signer: DtnRole::Rover.signer(),
			shared_cipher: self.cipher.to_owned(),
			mars_relay_addr: mars_relay,
			mission_control_addr: Arc::clone(mission_control),
			mission_control_pool: role.dial_pool(DtnRole::MissionControl)?,
			mars_relay_pool: role.dial_pool(DtnRole::MarsRelay)?,
			chain_processor: Arc::clone(&chain.processor),
			frame_builder: Arc::clone(&chain.frame_builder),
		};

		let servlet_config = role.servlet_config(config)?.with_relay_workers(chain).build();
		EarthRelaySatelliteServlet::start(Arc::clone(&self.trace), servlet_config).await
	}

	/// Starts the Mars Relay over `chain`, between the Earth Relay at the
	/// address that `earth_relay` publishes and the Rover at `rover`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a key or a certificate fails to load, or the servlet fails to bind.
	pub async fn start_mars_relay(
		&self,
		chain: &NodeChain,
		rover: TightBeamSocketAddr,
		earth_relay: &LateAddr,
	) -> Result<MarsRelaySatelliteServlet, TightBeamError> {
		let role = DtnRole::MarsRelay;
		let config = MarsRelaySatelliteServletConfig {
			mars_relay_signing_key: role.signing_key(),
			mission_control_signer: DtnRole::MissionControl.signer(),
			earth_relay_signer: DtnRole::EarthRelay.signer(),
			rover_signer: DtnRole::Rover.signer(),
			shared_cipher: self.cipher.to_owned(),
			rover_addr: rover,
			earth_relay_addr: Arc::clone(earth_relay),
			earth_relay_pool: role.dial_pool(DtnRole::EarthRelay)?,
			rover_pool: role.dial_pool(DtnRole::Rover)?,
			chain_processor: Arc::clone(&chain.processor),
			frame_builder: Arc::clone(&chain.frame_builder),
		};

		let servlet_config = role.servlet_config(config)?.with_relay_workers(chain).build();
		MarsRelaySatelliteServlet::start(Arc::clone(&self.trace), servlet_config).await
	}

	/// Starts the Rover over `chain`, which answers the Mars Relay at the
	/// address that `mars_relay` publishes.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a key or a certificate fails to load, or the servlet fails to bind.
	pub async fn start_rover(
		&self,
		chain: &NodeChain,
		mars_relay: &LateAddr,
		fault_manager: Arc<FaultManager>,
	) -> Result<RoverServlet, TightBeamError> {
		let role = DtnRole::Rover;
		let config = RoverServletConfig {
			mars_relay_addr: Arc::clone(mars_relay),
			mars_relay_pool: role.dial_pool(DtnRole::MarsRelay)?,
			rover_signing_key: role.signing_key(),
			mission_control_signer: DtnRole::MissionControl.signer(),
			mars_relay_signer: DtnRole::MarsRelay.signer(),
			shared_cipher: self.cipher.to_owned(),
			chain_processor: Arc::clone(&chain.processor),
			_fault_manager: fault_manager,
			frame_builder: Arc::clone(&chain.frame_builder),
			max_rounds: self.rounds,
		};

		let commands = RoverCommandHandlerWorker::new(RoverCommandHandlerWorkerConfig {
			mission_state: Arc::clone(&self.mission_state),
		});
		let telemetry =
			TelemetryBuilderWorker::new(TelemetryBuilderWorkerConfig { default_battery: 85, default_temp: -63 });
		let frame_requests = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
			can_cascade: false, // The Rover is an origin of the path.
		});
		let frame_responses = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
		});
		let servlet_config = role
			.servlet_config(config)?
			.with_worker(commands)
			.with_worker(CommandExecutionWorker::new(()))
			.with_worker(telemetry)
			.with_worker(frame_requests)
			.with_worker(frame_responses)
			.build();

		RoverServlet::start(Arc::clone(&self.trace), servlet_config).await
	}
}

/// The workers of a relay satellite, which answers and cascades frame
/// requests in both directions.
trait RelayWorkers: Sized {
	/// The builder with the frame request and frame response workers over
	/// `chain`.
	fn with_relay_workers(self, chain: &NodeChain) -> Self;
}

impl<Env> RelayWorkers for NodeConfigBuilder<Env> {
	fn with_relay_workers(self, chain: &NodeChain) -> Self {
		let frame_requests = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
			can_cascade: true, // A relay cascades both ways.
		});
		let frame_responses = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
			chain_processor: Arc::clone(&chain.processor),
		});

		self.with_worker(frame_requests).with_worker(frame_responses)
	}
}
