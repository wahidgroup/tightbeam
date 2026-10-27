use tightbeam::server;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Frame;

// A connection cap is one or more, so a literal cap of zero must fail to
// compile rather than serve no connection.
fn serve(listener: TokioListener) {
	let _server = server! {
		protocol TokioListener: listener,
		policies: { max_connections: [ 0 ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};
}

fn main() {
	let _ = serve;
}
