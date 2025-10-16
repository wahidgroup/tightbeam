/*
//  The Drone (192.168.1.101:889)
fn main() -> Result<(), Box<dyn std::error::Error>> {
	Ok(drone! {
		name: RegularDrone,
		protocol: Listener,
		id: b"regular-drone",
		servlets: {
			simple_servlet: SimpleServlet,
			configurable_servlet: ConfurableServlet,
			worker_servlet: WorkerServlet
		}
	}.start().await?)
}

// Cluster (192.168.1.101:888)
fn main() -> Result<(), Box<dyn std::error::Error>> {
	cluster! {
		// How the cluster receives messages
		name: UserCluster,
		// The protocol the cluster operates on
		protocol TokioListener: listener,
		// The cluster's configuration
		config: {
			arbitrary: u32,
		},
		servlets: {
			simple_servlet: SimpleServlet,
			configurable_servlet: ConfurableServlet,
			worker_servlet: WorkerServlet
		}
		router: {
			PingMessage: simple_servlet,
			OtherMessage: worker_servlet,
		},
		// Optionally define cluster-wide commands
		commands: {
			emergency_stop: |self| async move {

			}
		}
	};

	let user_cluster = UserCluster::new(UserClusterConf { arbitrary: 42 });
	let drones = vec![
		TightBeamSocketAddr("192.168.1.101:889".parse()?),
	];

	// Connect to drones
	drones.iter().for_each(|addr| user_cluster.colonize(addr.clone()));

	Ok(user_cluster.run().await?)
}

*/
