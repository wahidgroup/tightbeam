//! The module whose item pairs with the item of `alpha`.

use crate::alpha::Alpha;

/// The item of `beta`.
pub struct Beta;

/// The item of `beta` beside the item of `alpha`.
pub fn paired() -> (Beta, Alpha) {
	(Beta, Alpha)
}
