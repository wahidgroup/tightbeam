#!/usr/bin/env bash
set -euo pipefail

# Report what crates.io holds for one package version:
#   crates-io.sh <package> <version>
#
# Prints exactly one word on success and exits 0:
#   absent     the version was never published
#   published  the version is live and not yanked
#   yanked     the version is live but yanked
#
# Any outcome the registry cannot answer definitively is an error exit, so a
# caller that treats a non-zero status as "stop" fails closed on its own.

if [ "$#" -ne 2 ]; then
	echo "usage: $(basename "$0") <package> <version>" >&2
	exit 2
fi

PACKAGE="$1"
VERSION="$2"
REGISTRY="${CRATES_IO_API:-https://crates.io/api/v1}"

fail() {
	echo "ERROR: $1" >&2
	exit 1
}

BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

# A transport failure is curl's exit status, not a status code: `--write-out`
# emits one code per retry, so the body of a failed fetch is never a number.
# crates.io also rejects requests without a descriptive User-Agent.
if ! STATUS="$(
	curl --silent --show-error --location \
		--max-time 30 --retry 3 --retry-connrefused \
		--user-agent "tightbeam-release-check (https://github.com/wahidgroup/tightbeam)" \
		--output "$BODY_FILE" --write-out '%{http_code}' \
		"${REGISTRY}/crates/${PACKAGE}/${VERSION}"
)"; then
	fail "could not reach crates.io for ${PACKAGE} ${VERSION}."
fi

case "$STATUS" in
	200) ;;
	404)
		echo "absent"
		exit 0
		;;
	*) fail "crates.io returned HTTP ${STATUS} for ${PACKAGE} ${VERSION}." ;;
esac

case "$(jq -r '.version.yanked' < "$BODY_FILE" 2>/dev/null || echo "")" in
	false) echo "published" ;;
	true) echo "yanked" ;;
	*) fail "crates.io returned no yank state for ${PACKAGE} ${VERSION}." ;;
esac
