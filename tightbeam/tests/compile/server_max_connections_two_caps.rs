use tightbeam::server;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Frame;

// A `max_connections` list names one cap, so a list of two must fail to
// compile rather than serve under the default cap.
fn serve(listener: TokioListener) {
	let _server = server! {
		protocol TokioListener: listener,
		policies: { max_connections: [ 1, 2 ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};
}

fn main() {
	let _ = serve;
}
