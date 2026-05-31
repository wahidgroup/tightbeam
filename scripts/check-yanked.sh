#!/usr/bin/env bash
set -euo pipefail

# Fail if the current crate version has been yanked. Pass --derive to check
# the tightbeam-derive crate instead of the workspace crate.

CRATE_TOML="Cargo.toml"
VERSION_SECTION="workspace.package"
YANKED_PREFIX="yanked/v"

for arg in "$@"; do
	if [ "$arg" = "--derive" ]; then
		CRATE_TOML="tightbeam-derive/Cargo.toml"
		VERSION_SECTION="package"
		YANKED_PREFIX="yanked/derive/v"
	fi
done

if [ "$VERSION_SECTION" = "package" ]; then
	VERSION=$(awk -F'"' '/^\[package\]/{f=1;next} f&&/^\[/{f=0} f&&/^version/{print $2;exit}' "$CRATE_TOML" 2>/dev/null || echo "")
else
	VERSION=$(awk -F'"' '/^\[workspace\.package\]/{f=1;next} f&&/^\[/{f=0} f&&/^version/{print $2;exit}' "$CRATE_TOML" 2>/dev/null || echo "")
fi

if [ -n "$VERSION" ] && \
   git ls-remote --tags origin "${YANKED_PREFIX}${VERSION}" 2>/dev/null | grep -q .; then
	printf '  \033[0;31m[error]\033[0m Version %s has been yanked. Cannot proceed.\n' "$VERSION" >&2
	exit 1
fi
