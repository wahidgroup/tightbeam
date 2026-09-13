use tightbeam::utils::urn::Urn;
use tightbeam::{at_least, tb_assert_spec};

pub(crate) const SOME_KEY: Urn<'static> = tightbeam::urn!("test", "event:at-least-zero/some-key");

// A lower bound of zero is satisfied by every trace, so the label it names
// grades nothing. The bound is a `NonZeroU32` built in a `const` block, so
// this must fail to compile rather than build a spec that cannot reject.
tb_assert_spec! {
	pub ZeroBoundSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SOME_KEY, at_least!(0))
		]
	}
}

fn main() {}
