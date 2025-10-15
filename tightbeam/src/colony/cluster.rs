/*
// Central/Decentral Authority (192.168.1.100)

let user_cluster = cluster! {
	// How the cluster receives messages
	protocol TokioListener: listener,
	config: {
	},
	// Optionally define cluster-wide commands
	commands: {
		EmergencyStop: |config, members| async move {

		}
	}
	members: |config| {
		User: UserManagerServlet::start()
		Items: ItemManagerServlet::start()
	}
};

fn main() -> Result<(), Box<dyn std::error::Error>> {

	user_cluster::colonize

	let (ant_a_tx, ant_b_tx, ant_c_tx)?;
}

// Any node running your application (192.168.1.101:888)

fn main() -> Result<(), Box<dyn std::error::Error>> {
	entrypoint! {
		protocol TokioListener: listener,
	}.await?;
}
*/
