#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# release-derive.sh - derive-only release helper for tightbeam-derive
#
# The workspace release (scripts/release.sh) publishes tightbeam-derive
# automatically whenever its version is ahead of crates.io, so this script
# is only needed to publish (or yank) the derive crate WITHOUT cutting a
# workspace release.
#
# Release: verifies tightbeam-derive/Cargo.toml [package].version matches
#          the requested version (bump it in a normal PR first), then pushes
#          a signed releases/derive/v* tag. CI (release.yml) verifies the
#          tag, refuses yanked versions, and publishes to crates.io.
#
# Yank:    deletes the GitHub release (if any) and pushes a signed
#          yanked/derive/v* marker tag. The release tag is preserved.
#          Run `cargo yank` separately to yank on crates.io.
#
# Usage:
#	./scripts/release-derive.sh [--dry-run] [--yank] [vX.Y.Z]
#
# Flags may also be set via environment (used by `make release-derive`):
#	DRY_RUN=1   Preview without changes
#	YANK=1      Yank instead of release
#
# The version defaults to the manifest version when omitted.
# ---------------------------------------------------------------------------

DEFAULT_BRANCH="master"
DERIVE_TOML="tightbeam-derive/Cargo.toml"

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()    { printf "  ${GREEN}[ok]${RESET} %s\n" "$1"; }
fail()  { printf "  ${RED}[error]${RESET} %s\n" "$1" >&2; exit 1; }
info()  { printf "  ${CYAN}[info]${RESET} %s\n" "$1"; }
header(){ printf "\n${BOLD}${CYAN}%s${RESET}\n" "$1"; }

# Exact remote ref check, fail closed: a network/auth error must abort the
# run instead of reading as "tag absent".
remote_tag_exists() {
	local status=0
	git ls-remote --exit-code --tags origin "refs/tags/${1}" \
		>/dev/null 2>&1 || status=$?
	if (( status == 0 )); then
		return 0
	fi
	if (( status == 2 )); then
		return 1
	fi
	fail "Could not query origin for ${1} (network or auth error)"
}

manifest_version() {
	awk -F'"' '
		/^\[package\]/ { f = 1; next }
		f && /^\[/ { f = 0 }
		f && /^version/ { print $2; exit }
	' "$DERIVE_TOML" 2>/dev/null || true
}

require_signing_key() {
	if [[ -z "$(git config user.signingkey 2>/dev/null || true)" ]]; then
		fail "Signing key is required (git config user.signingkey)"
	fi
	ok "Signing configured (format: $(git config gpg.format 2>/dev/null || echo openpgp))"
}

require_gh() {
	if ! command -v gh &>/dev/null; then
		fail "gh CLI is required (https://cli.github.com)"
	fi
	if ! gh auth status &>/dev/null; then
		fail "gh CLI is not authenticated (run 'gh auth login')"
	fi
	ok "gh CLI available and authenticated"
}

parse_args() {
	DRY_RUN="${DRY_RUN:+true}"
	DRY_RUN="${DRY_RUN:-false}"
	YANK="${YANK:+true}"
	YANK="${YANK:-false}"
	VERSION=""

	local arg
	for arg in "$@"; do
		# Makefile passes an empty version argument when version= is unset.
		if [[ -z "$arg" ]]; then
			continue
		elif [[ "$arg" == "--dry-run" ]]; then
			DRY_RUN=true
		elif [[ "$arg" == "--yank" ]]; then
			YANK=true
		elif [[ "$arg" == --* ]]; then
			fail "Unknown flag: ${arg}"
		elif [[ -n "$VERSION" ]]; then
			fail "Unexpected argument: '${arg}' (version already set to '${VERSION}')"
		else
			VERSION="$arg"
		fi
	done

	VERSION="${VERSION#v}"
	if [[ -z "$VERSION" ]]; then
		VERSION="$(manifest_version)"
	fi
	if [[ -z "$VERSION" ]]; then
		fail "Could not read version from ${DERIVE_TOML} and none was given"
	fi
	if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		fail "Invalid semver format: '${VERSION}'. Expected X.Y.Z (e.g. 0.1.8)"
	fi

	TAG="releases/derive/v${VERSION}"
	YANKED_TAG="yanked/derive/v${VERSION}"
}

run_yank() {
	header "Yank - tightbeam-derive v${VERSION}"

	if remote_tag_exists "$YANKED_TAG"; then
		ok "Version v${VERSION} is already yanked (${YANKED_TAG} exists)"
		exit 0
	fi
	if ! remote_tag_exists "$TAG"; then
		fail "Release tag ${TAG} does not exist on remote - nothing to yank"
	fi

	if [[ "$DRY_RUN" == true ]]; then
		info "Would delete GitHub release for ${TAG}"
		info "Would push signed marker tag ${YANKED_TAG}"
		info "Dry run complete. No changes were made."
		exit 0
	fi

	require_gh
	require_signing_key

	if gh release view "$TAG" &>/dev/null; then
		gh release delete "$TAG" --yes
		ok "GitHub release deleted for ${TAG}"
	else
		info "No GitHub release found for ${TAG} (tag-only release)"
	fi

	# Signed like release tags: unsigned markers could be forged.
	git tag -s "$YANKED_TAG" \
		-m "Yanked by $(git config user.name) on $(date +%Y-%m-%d)"
	git push origin "$YANKED_TAG"
	ok "Marker tag ${YANKED_TAG} pushed (signed)"
	info "Run 'cargo yank --package tightbeam-derive --version ${VERSION}' to yank on crates.io"
}

run_release() {
	header "Release - tightbeam-derive v${VERSION}"

	local manifest
	manifest="$(manifest_version)"
	if [[ "$manifest" != "$VERSION" ]]; then
		fail "${DERIVE_TOML} is at ${manifest:-unknown}, not ${VERSION}. Bump it in a normal PR first."
	fi
	ok "Manifest version matches: ${VERSION}"

	if remote_tag_exists "$YANKED_TAG"; then
		fail "Version v${VERSION} has been yanked (${YANKED_TAG} exists)"
	fi
	if remote_tag_exists "$TAG"; then
		ok "tightbeam-derive v${VERSION} already released (${TAG} exists)"
		exit 0
	fi

	local current_branch
	current_branch="$(git branch --show-current)"
	if [[ "$current_branch" != "$DEFAULT_BRANCH" ]]; then
		fail "Must be on branch ${DEFAULT_BRANCH} (currently on ${current_branch})"
	fi
	if ! git diff --quiet || ! git diff --cached --quiet; then
		fail "Working tree is not clean"
	fi
	git fetch origin "$DEFAULT_BRANCH" --quiet
	if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "origin/${DEFAULT_BRANCH}")" ]]; then
		fail "${DEFAULT_BRANCH} is not up to date with origin/${DEFAULT_BRANCH} (pull or push first)"
	fi
	ok "On ${DEFAULT_BRANCH}, clean, and up to date with origin"

	if [[ "$DRY_RUN" == true ]]; then
		info "Would push signed tag ${TAG} (CI publishes to crates.io)"
		info "Dry run complete. No changes were made."
		exit 0
	fi

	require_signing_key

	git tag -s "$TAG" -m "tightbeam-derive v${VERSION}"
	git push origin "$TAG"
	ok "Tag ${TAG} pushed (signed) - CI will verify and publish"
}

main() {
	parse_args "$@"

	if [[ "$YANK" == true ]]; then
		run_yank
	else
		run_release
	fi
}

main "$@"
