use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec};

pub(crate) const NEWER_KEY: Urn<'static> = Urn::new("test", "event:assert-spec-version-order/newer-key");
pub(crate) const OLDER_KEY: Urn<'static> = Urn::new("test", "event:assert-spec-version-order/older-key");

// Version blocks out of ascending order: the key constants would generate
// from V(1,0,0) (last in source) while `latest()` runs V(2,0,0). This must
// fail to compile.
tb_assert_spec! {
	pub OutOfOrderSpec,
	V(2,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(NEWER_KEY, exactly!(1))
		]
	},
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(OLDER_KEY, exactly!(1))
		]
	}
}

fn main() {}
