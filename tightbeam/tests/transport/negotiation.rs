//! An integration test of security profile negotiation.
//!
//! The test shows how a server configured with two security profiles
//! (AES-256-GCM with SHA3-512 and AES-128-GCM with SHA3-256) negotiates
//! with a client that offers profiles in preference order.

#![cfg(all(feature = "transport-hpke", feature = "tokio", feature = "testing"))]

use tightbeam::crypto::profiles::SecurityProfileDesc;
use tightbeam::testing::{Aes256Sha3_512Profile, Aes256Sha3_512Provider};

use crate::common::result::TestResult;
use crate::common::security::{weak_security_profile, ServerMaterials};

/// The server lists the weaker profile, AES-128-GCM with SHA3-256, first. The
/// client offer and the server list both include it, and the test provider
/// runs the stronger profile alone, so both ends select the client's
/// preferred profile.
#[tokio::test]
async fn both_ends_select_the_profile_the_provider_runs() -> TestResult {
	let preferred = SecurityProfileDesc::from(&Aes256Sha3_512Profile);
	let fallback = weak_security_profile();
	let client_offer = [preferred, fallback];
	let server_list = [fallback, preferred];
	let materials = ServerMaterials::fixed();
	let (mut client, mut server) = materials.hpke_pair::<Aes256Sha3_512Provider>(client_offer, server_list);

	let opening = client.start()?;
	let reply = server.reply(opening).await?;
	let closing = client.respond(reply).await?;

	server.finish(closing).await?;

	let selected = (server.selected_profile(), client.selected_profile());
	assert_eq!(selected, (Some(preferred), Some(preferred)));
	Ok(())
}
