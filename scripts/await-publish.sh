#!/usr/bin/env bash
set -euo pipefail

# Block until crates.io serves a published version, or fail:
#   await-publish.sh <package> <version> [timeout-seconds]
#
# Publishing is asynchronous, so a dependent publish that starts too early
# fails to resolve. Polling the registry replaces a fixed sleep, which is both
# slower than the common case and shorter than the slow one.

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $(basename "$0") <package> <version> [timeout-seconds]" >&2
	exit 2
fi

PACKAGE="$1"
VERSION="$2"
TIMEOUT="${3:-300}"
INTERVAL=5

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WAITED=0

while true; do
	STATE="$("$ROOT/scripts/crates-io.sh" "$PACKAGE" "$VERSION")"
	case "$STATE" in
		published)
			echo "crates.io is serving ${PACKAGE} ${VERSION} after ${WAITED}s."
			exit 0
			;;
		yanked)
			echo "ERROR: ${PACKAGE} ${VERSION} appeared yanked." >&2
			exit 1
			;;
	esac

	if [ "$WAITED" -ge "$TIMEOUT" ]; then
		echo "ERROR: ${PACKAGE} ${VERSION} did not appear on crates.io within ${TIMEOUT}s." >&2
		exit 1
	fi

	sleep "$INTERVAL"
	WAITED=$((WAITED + INTERVAL))
done
