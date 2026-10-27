use tightbeam::tb_process_spec;
use tightbeam::urn::Urn;

const PING: Urn<'static> = tightbeam::urn!("test", "event:compile/ping");

// A state takes one definition, so its transitions sit in one place, and a
// spec that defines a state twice must fail to compile.
tb_process_spec! {
	pub Pings,
	events {
		observable { PING }
		hidden { }
	}
	states {
		Idle => { PING => Done },
		Idle => { PING => Idle }
	}
	terminal { Done }
}

fn main() {
	let _ = Pings::process();
}
