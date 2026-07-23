use tightbeam::{exactly, tb_assert_spec};

// Version blocks out of ascending order: the key constants would generate
// from V(1,0,0) (last in source) while `latest()` runs V(2,0,0). This must
// fail to compile.
tb_assert_spec! {
	pub OutOfOrderSpec,
	V(2,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(newer_key, exactly!(1))
		]
	},
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(older_key, exactly!(1))
		]
	}
}

fn main() {}
