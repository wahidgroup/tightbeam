/*
//  The Drone (192.168.1.101:889)
fn main() -> Result<(), Box<dyn std::error::Error>> {
	let drone_handle = drone! {
		name: RegularDrone,
		protocol: Listener,
		id: b"regular-drone",
		servlets: {
			simple_servlet: SimpleServlet,
			configurable_servlet: ConfurableServlet,
			worker_servlet: WorkerServlet
		}
	}.start();

	// Graceful shutdown
	drone_handle.join().await?;

	Ok(())
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
		// Optionally define cluster-wide commands
		commands: {
			emergency_stop: |self| async move {

			}
		}
	};

	let user_cluster = UserCluster::new(UserClusterConf { arbitrary: 42 });
	let user_cluster.colonize()

	// Graceful shutdown
	user_cluster.stop().await?;

	Ok(())
}

*/
