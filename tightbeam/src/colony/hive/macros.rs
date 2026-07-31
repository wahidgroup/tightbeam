//! Hive macros: name a runtime type as an alias of [`HiveRuntime`].
//!
//! Lifecycle, control, scaling, and cluster client helpers live in
//! [`crate::colony::hive::runtime`].

/// Macro for creating hives that orchestrate dynamically registered servlets.
///
/// Hives coordinate multiple servlets, enabling intra-hive communication,
/// lifecycle management, auto-scaling, and cluster integration.
///
/// # Syntax
///
/// ```ignore
/// hive! {
///     pub MyHive,
///     protocol: TokioListener
/// }
/// ```
#[macro_export]
macro_rules! hive {
	(
		$(#[$meta:meta])*
		pub $hive_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		pub type $hive_name = $crate::colony::hive::HiveRuntime<$protocol>;
	};

	(
		$(#[$meta:meta])*
		$hive_name:ident,
		protocol: $protocol:path
	) => {
		$(#[$meta])*
		type $hive_name = $crate::colony::hive::HiveRuntime<$protocol>;
	};
}
