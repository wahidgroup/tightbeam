//! Registry and context coherence for servlet instances.

use std::sync::Arc;

use crate::colony::common::{canonical_bytes, servlet_instance, ServletInfo};
use crate::colony::hive::runtime::HiveContextImpl;
use crate::colony::hive::{ServletRegistration, ServletRegistry};
use crate::transport::Protocol;
use crate::utils::urn::{Urn, UrnValidationError};
use crate::TightBeamError;

/// Type URN with the instance locator as the resource-id tail.
pub fn instance_urn(type_urn: &Urn<'_>, addr_bytes: impl AsRef<[u8]>) -> Result<Urn<'static>, TightBeamError> {
	let addr = core::str::from_utf8(addr_bytes.as_ref()).map_err(|_| {
		TightBeamError::UrnValidationError(UrnValidationError::InvalidFormat { field: "resource-id", pattern: None })
	})?;

	let instance = servlet_instance(type_urn, addr);
	Ok(instance)
}

/// Current servlet slate for list and cluster registration.
pub fn servlet_slate(servlets: &impl ServletRegistry) -> Vec<ServletInfo> {
	let mut list = Vec::new();
	servlets.for_each(|_key, reg| {
		let address = reg.servlet.addr_bytes();
		let Ok(servlet_id) = instance_urn(&reg.servlet_type, address.as_ref()) else {
			return;
		};

		list.push(ServletInfo { servlet_id, address: address.as_ref().to_vec() });
	});

	list
}

/// Insert a registration into the registry and routing context.
///
/// Returns the instance URN and shared address bytes for callers that notify
/// the cluster after insert.
pub fn insert_instance<P: Protocol>(
	servlets: &impl ServletRegistry,
	ctx: &HiveContextImpl<P>,
	registration: ServletRegistration,
) -> Result<(Urn<'static>, Arc<[u8]>), TightBeamError> {
	let addr_bytes = registration.servlet.addr_bytes();
	let instance = match instance_urn(&registration.servlet_type, addr_bytes.as_ref()) {
		Ok(instance) => instance,
		Err(err) => {
			let ServletRegistration { servlet, .. } = registration;
			servlet.stop_boxed();
			return Err(err);
		}
	};
	let key_bytes = canonical_bytes(&instance);
	let type_key = canonical_bytes(&registration.servlet_type);

	// Vec clone: route map and registry each must own a key.
	let route_key = key_bytes.clone();

	ctx.add_route(route_key, Arc::clone(&addr_bytes), &type_key);

	let _ = servlets.insert(key_bytes, registration);

	Ok((instance, addr_bytes))
}

/// Remove, stop, and drop routes for one instance.
///
/// Returns the removed type URN and address when present (for notify).
pub fn remove_instance<P: Protocol>(
	servlets: &impl ServletRegistry,
	ctx: &HiveContextImpl<P>,
	key: &[u8],
) -> Option<(Urn<'static>, Arc<[u8]>)> {
	let ServletRegistration { servlet, servlet_type, .. } = servlets.remove(key)?;
	let removed_type = canonical_bytes(&servlet_type);
	let removed_addr = servlet.addr_bytes();

	servlet.stop_boxed();
	ctx.remove_route(key, &servlet_type, &removed_type, &removed_addr);

	Some((servlet_type, removed_addr))
}
