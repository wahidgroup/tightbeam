#!/usr/bin/env bash
set -euo pipefail

VERSION=$(awk -F'"' '/^\[workspace\.package\]/,/^\[/{if(/^version/) print $2}' Cargo.toml 2>/dev/null || echo "")

if [ -n "$VERSION" ] && \
   git ls-remote --tags origin "yanked/v${VERSION}" 2>/dev/null | grep -q .; then
	printf '  \033[0;31m[error]\033[0m Version %s has been yanked. Cannot proceed.\n' "$VERSION" >&2
	exit 1
fi
