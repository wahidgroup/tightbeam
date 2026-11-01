//! The module whose item pairs with the item of `beta`.

use crate::beta::Beta;

/// The item of `alpha`.
pub struct Alpha;

/// The item of `alpha` beside the item of `beta`.
pub fn paired() -> (Alpha, Beta) {
	(Alpha, Beta)
}
