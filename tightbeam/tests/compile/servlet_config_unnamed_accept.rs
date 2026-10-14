use tightbeam::colony::servlet::ServletConfig;
use tightbeam::der::Sequence;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Beamable;

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct Ping {
	content: String,
}

fn main() {
	// ERROR: the builder holds no certificate and has not named cleartext.
	let _config = ServletConfig::<TokioListener, Ping>::builder().build();

	// ERROR: a default configuration would serve in the clear, so none exists.
	let _unnamed: ServletConfig<TokioListener, Ping> = ServletConfig::default();
}
