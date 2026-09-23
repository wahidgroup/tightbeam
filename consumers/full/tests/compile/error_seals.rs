use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::error::TightBeamError;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::TransportError;

fn classify_root(err: TightBeamError) {
	match err {
		TightBeamError::LockPoisoned => {}
	}
}

fn classify_transport(err: TransportError) {
	match err {
		TransportError::ConnectionClosed => {}
	}
}

fn classify_handshake(err: HandshakeError) {
	match err {
		HandshakeError::SignatureVerificationFailed => {}
	}
}

fn classify_certificate(err: CertificateValidationError) {
	match err {
		CertificateValidationError::Expired => {}
	}
}

fn main() {}
