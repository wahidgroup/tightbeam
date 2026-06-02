#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Project detection
# ---------------------------------------------------------------------------
PROJECT_NAME="$(git remote get-url origin 2>/dev/null \
	| sed -e 's|.*/||' -e 's/\.git$//' || echo 'unknown')"

DEFAULT_BRANCH="${DEFAULT_BRANCH:-$(git remote show origin 2>/dev/null \
	| sed -n 's/.*HEAD branch: //p' || echo 'main')}"

# ---------------------------------------------------------------------------
# Colors and formatting
# ---------------------------------------------------------------------------
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

ok()    { printf "  ${GREEN}[ok]${RESET} %s\n" "$1"; }
fail()  { printf "  ${RED}[error]${RESET} %s\n" "$1" >&2; exit 1; }
info()  { printf "  ${CYAN}[info]${RESET} %s\n" "$1"; }
step()  { printf "\n${BOLD}==> Step %s: %s${RESET}\n" "$1" "$2"; }
header(){ printf "\n${BOLD}${CYAN}%s${RESET}\n" "$1"; }

# ---------------------------------------------------------------------------
# Crate definitions
# ---------------------------------------------------------------------------
CRATES=("tightbeam" "tightbeam-derive")
CRATE_TOML_PATHS=("Cargo.toml" "tightbeam-derive/Cargo.toml")
CRATE_VERSION_SECTIONS=("workspace.package" "package")

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

detect_version() {
	local toml_path="$1"
	local section="$2"
	local section_re='^\['"${section//./\\.}"'\]'
	local next_section_re='^\['
	local version_re='^version[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)"'

	local in_section=false
	while IFS= read -r line; do
		if [[ "$line" =~ $section_re ]]; then
			in_section=true
			continue
		fi
		if [[ "$in_section" == true && "$line" =~ $next_section_re ]]; then
			break
		fi
		if [[ "$in_section" == true && "$line" =~ $version_re ]]; then
			printf '%s' "${BASH_REMATCH[1]}"
			return
		fi
	done < "$toml_path"
}

bump_version() {
	local version="$1"
	local toml_path="$2"
	local section="$3"
	local section_re='^\['"${section//./\\.}"'\]'
	local next_section_re='^\['
	local bump_re='^(version[[:space:]]*=[[:space:]]*")[0-9]+\.[0-9]+\.[0-9]+(".*)'

	local in_section=false
	local replaced=false
	local tmpfile
	tmpfile=$(mktemp)

	while IFS= read -r line; do
		if [[ "$line" =~ $section_re ]]; then
			in_section=true
		elif [[ "$in_section" == true && "$line" =~ $next_section_re ]]; then
			in_section=false
		fi

		if [[ "$in_section" == true && "$replaced" == false && "$line" =~ $bump_re ]]; then
			printf '%s%s%s\n' "${BASH_REMATCH[1]}" "$version" "${BASH_REMATCH[2]}" >> "$tmpfile"
			replaced=true
		else
			printf '%s\n' "$line" >> "$tmpfile"
		fi
	done < "$toml_path"

	mv "$tmpfile" "$toml_path"
	git add "$toml_path"
	if [[ -f Cargo.lock ]]; then
		cargo generate-lockfile --quiet 2>/dev/null || true
		git add Cargo.lock
	fi

	if [[ "$replaced" == true ]]; then
		ok "Version updated to ${version} in ${toml_path}"
	else
		fail "Could not find version field in [${section}] of ${toml_path}"
	fi
}

# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

compile_changelog() {
	if [[ -n "${CHANGELOG:-}" ]]; then
		return 0
	fi

	local last_tag
	last_tag=$(git describe --tags --match "${TAG_PREFIX}*" --abbrev=0 2>/dev/null) \
		|| last_tag=$(git rev-list --max-parents=0 HEAD)

	local date_str
	date_str=$(date +%Y-%m-%d)

	local changelog_title="## v${VERSION} (${date_str})"

	local body=""
	local merge_subjects
	merge_subjects=$(git log "${last_tag}..HEAD" --merges --format="%s")

	local labels_file
	labels_file=$(mktemp)

	if [[ -n "$merge_subjects" ]]; then
		while IFS= read -r subject; do
			[[ -z "$subject" ]] && continue
			local pr_num
			pr_num=$(echo "$subject" | grep -oE '#[0-9]+' | head -1 | tr -d '#') || true
			[[ -z "$pr_num" ]] && continue

			local pr_json
			pr_json=$(gh pr view "$pr_num" \
				--json number,title,url,author,headRefName,labels \
				2>/dev/null || true)
			[[ -z "$pr_json" ]] && continue

			local is_release_pr
			is_release_pr=$(echo "$pr_json" \
				| jq -r '.headRefName | startswith("process/")')
			[[ "$is_release_pr" == "true" ]] && continue

			local pr_line
			pr_line=$(echo "$pr_json" \
				| jq -r '"- [#\(.number)](\(.url)) \(.title) (@\(.author.login))"')
			[[ -z "$pr_line" ]] && continue

			body+="${pr_line}"$'\n'

			echo "$pr_json" | jq -r '.labels[].name' >> "$labels_file"
		done <<< "$merge_subjects"
	fi

	RELEASE_LABELS=$(sort -u "$labels_file" 2>/dev/null || true)
	rm -f "$labels_file"

	CHANGELOG="${changelog_title}

${body}"
}

print_release_notes() {
	compile_changelog
	printf "\n"
	printf "  ${BOLD}Release Notes (v${VERSION})${RESET}\n"
	printf "  ──────────────────────────────────\n"
	printf '%s\n' "$CHANGELOG" | while IFS= read -r line; do
		printf "  %s\n" "$line"
	done
	printf "  ──────────────────────────────────\n"
}

print_summary() {
	printf "\n"
	printf "  ${BOLD}Project:${RESET}   %s\n" "$PROJECT_NAME"
	printf "  ${BOLD}Crate:${RESET}     %s\n" "$TARGET_CRATE"
	printf "  ${BOLD}Version:${RESET}   %s\n" "$VERSION"
	printf "  ${BOLD}Tag:${RESET}       %s\n" "$TAG"
	printf "  ${BOLD}Branch:${RESET}    %s\n" "$BRANCH"
	if [[ "$RELEASE_MODE" == "backport" ]]; then
		printf "  ${BOLD}Base:${RESET}      %s\n" "$PR_BASE"
	fi
	printf "\n"
}

poll_pr() {
	local pr_number="$1"
	local start_time
	start_time=$(date +%s)

	info "Polling PR #${pr_number} for merge (every 10s)..."
	while true; do
		local state
		state=$(gh pr view "$pr_number" --json state --jq .state)

		local now elapsed
		now=$(date +%s)
		elapsed=$(( now - start_time ))

		if [[ "$state" == "MERGED" ]]; then
			ok "PR #${pr_number} merged (${elapsed}s elapsed)"
			return 0
		fi

		if [[ "$state" == "CLOSED" ]]; then
			fail "PR #${pr_number} was closed without merging. Release aborted."
		fi

		printf "  ${YELLOW}[wait]${RESET} PR #%s is %s (%ds elapsed)\n" \
			"$pr_number" "$state" "$elapsed"
		sleep 10
	done
}

ensure_label() {
	local label="$1"
	if ! gh label create "$label" \
		--color "0e8a16" \
		--description "Release PR (auto-managed by scripts/release.sh)" \
		--force >/dev/null 2>&1; then
		fail "Failed to ensure label '${label}' exists. Check repo write permissions."
	fi
}

semver_compare() {
	local IFS=.
	local -a a=($1) b=($2)
	for i in 0 1 2; do
		if (( a[i] > b[i] )); then
			printf "gt"; return
		elif (( a[i] < b[i] )); then
			printf "lt"; return
		fi
	done
	printf "eq"
}

# Abort unless a commit-signing key is configured.
require_signing_key() {
	local signing_key
	signing_key=$(git config user.signingkey 2>/dev/null || true)
	if [[ -n "$signing_key" ]]; then
		local sign_format
		sign_format=$(git config gpg.format 2>/dev/null || echo "openpgp")
		ok "Signing configured (format: ${sign_format})"
		return 0
	fi

	cat >&2 <<-SIGNING
	
	  ${RED}No signing key configured.${RESET}
	
	  Configure GPG signing:
	    git config --global user.signingkey <GPG-KEY-ID>
	
	  Or configure SSH signing:
	    git config --global gpg.format ssh
	    git config --global user.signingkey ~/.ssh/id_ed25519.pub
	
	SIGNING
	fail "Signing key is required for releases"
}

# Abort unless on the default branch and in sync with origin.
require_default_branch_synced() {
	local current_branch
	current_branch=$(git branch --show-current)
	[[ "$current_branch" == "$DEFAULT_BRANCH" ]] \
		|| fail "Must be on branch ${DEFAULT_BRANCH} (currently on ${current_branch})"

	git fetch origin "$DEFAULT_BRANCH" --quiet
	[[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/${DEFAULT_BRANCH}")" ]] \
		|| fail "${DEFAULT_BRANCH} is not up to date with origin/${DEFAULT_BRANCH} (pull or push first)"
	ok "On ${DEFAULT_BRANCH}, up to date with origin"
}

# Commit the staged release changes, falling back to an empty marker commit.
commit_release() {
	local message="$1"
	if git diff --cached --quiet; then
		info "Nothing staged - creating empty release marker commit"
		git commit --allow-empty -m "$message"
	else
		git commit -m "$message"
	fi
	ok "Committed ${message}"
}

# Inspect a release branch, setting PR_NUMBER, PR_STATE, and RESUME_STATE to one
# of: tag (PR merged), poll (PR open), pr (remote branch only), fresh (none).
detect_pr_resume_state() {
	local branch="$1"

	PR_NUMBER=""
	PR_STATE=""
	RESUME_STATE="fresh"

	local pr_line
	pr_line=$(gh pr list --head "$branch" --state all --json number,state \
		--jq '.[0] | [.number, .state] | @tsv' 2>/dev/null || true)
	[[ -n "$pr_line" ]] && IFS=$'\t' read -r PR_NUMBER PR_STATE <<< "$pr_line"

	if [[ -n "$PR_NUMBER" && "$PR_STATE" == "MERGED" ]]; then
		RESUME_STATE="tag"
		info "[resume] PR #${PR_NUMBER} already merged, continuing to tag..."
	elif [[ -n "$PR_NUMBER" && "$PR_STATE" == "OPEN" ]]; then
		RESUME_STATE="poll"
		info "[resume] PR #${PR_NUMBER} is open, waiting for merge..."
	elif git ls-remote --heads origin "$branch" 2>/dev/null | grep -q "$branch"; then
		RESUME_STATE="pr"
		info "[resume] Branch ${branch} exists on remote, creating PR..."
	fi
}

# Open the release PR, attaching the changelog-derived labels. Sets PR_NUMBER.
create_release_pr() {
	local title="$1"
	local base="$2"
	local head="$3"

	compile_changelog
	ensure_label "release"

	local pr_args=(
		--title "$title"
		--body "$CHANGELOG"
		--base "$base"
		--head "$head"
		--assignee "@me"
	)
	local labels
	labels=$(printf 'release\n%s\n' "${RELEASE_LABELS:-}" | sort -u)
	local label
	while IFS= read -r label; do
		[[ -n "$label" ]] && pr_args+=(--label "$label")
	done <<< "$labels"

	local pr_url
	pr_url=$(gh pr create "${pr_args[@]}")
	PR_NUMBER="${pr_url##*/}"
	ok "PR #${PR_NUMBER} created: ${pr_url}"
}

# ---------------------------------------------------------------------------
# Backport helpers
# ---------------------------------------------------------------------------

ensure_release_branch() {
	local branch="$1"
	local major="$2"
	local minor="$3"
	local patch="$4"

	git fetch origin --quiet --tags

	if git ls-remote --heads origin "$branch" 2>/dev/null | grep -q "$branch"; then
		git checkout "$branch" --quiet
		git pull origin "$branch" --quiet
		ok "Release branch ${branch} is up to date"
		return
	fi

	local base_tag=""
	if (( patch > 0 )); then
		base_tag="${TAG_PREFIX}v${major}.${minor}.0"
		if ! git rev-parse --verify "${base_tag}^{commit}" &>/dev/null; then
			fail "Base tag ${base_tag} not found - release v${major}.${minor}.0 first"
		fi
	else
		local latest_branch
		latest_branch=$(git branch -r --list "origin/release/${BRANCH_PREFIX}${major}.*" \
			--sort=-v:refname 2>/dev/null | head -1 | tr -d ' ')
		if [[ -n "$latest_branch" ]]; then
			base_tag="${latest_branch#origin/}"
			git checkout "$base_tag" --quiet
			git checkout -b "$branch"
			git push -u origin "$branch" --quiet
			ok "Created release branch ${branch} from ${latest_branch}"
			return
		fi

		base_tag=$(git tag --list "${TAG_PREFIX}v${major}.*" --sort=-v:refname | head -1)
		if [[ -z "$base_tag" ]]; then
			fail "No release found for major version ${major}"
		fi
	fi

	git checkout -b "$branch" "$base_tag"
	git push -u origin "$branch" --quiet
	ok "Created release branch ${branch} from ${base_tag}"
}

interactive_cherry_pick() {
	local release_branch="$1"

	git fetch origin "$DEFAULT_BRANCH" --quiet
	local commits
	commits=$(git log --oneline --cherry-pick --right-only \
		"${release_branch}...origin/${DEFAULT_BRANCH}" --no-merges 2>/dev/null || true)

	if [[ -z "$commits" ]]; then
		info "No commits available to cherry-pick since ${release_branch}"
		return 0
	fi

	local count
	count=$(echo "$commits" | wc -l | tr -d ' ')
	if (( count > 50 )); then
		info "${count} commits available - consider narrowing your selection"
	fi

	local selected=""
	if command -v fzf &>/dev/null; then
		selected=$(echo "$commits" \
			| fzf --multi --reverse \
				--header "Select commits to cherry-pick (TAB to select, ENTER to confirm)" \
			|| true)
	else
		local -a lines=()
		while IFS= read -r line; do
			lines+=("$line")
		done <<< "$commits"

		printf "\n  Commits on %s since %s:\n\n" "$DEFAULT_BRANCH" "$release_branch"
		for i in "${!lines[@]}"; do
			printf "    %d) %s\n" "$((i + 1))" "${lines[$i]}"
		done

		printf "\n  Enter commits to include (e.g. 1,3,5): "
		read -r selection

		if [[ -z "$selection" ]]; then
			info "No commits selected"
			return 0
		fi

		IFS=',' read -ra indices <<< "$selection"
		for idx in "${indices[@]}"; do
			idx=$(( ${idx// /} - 1 ))
			if (( idx >= 0 && idx < ${#lines[@]} )); then
				selected+="${lines[$idx]}"$'\n'
			fi
		done
	fi

	if [[ -z "$selected" ]]; then
		info "No commits selected"
		return 0
	fi

	while IFS= read -r line; do
		[[ -z "$line" ]] && continue
		local sha="${line%% *}"
		if ! git cherry-pick "$sha"; then
			printf "\n"
			fail "Cherry-pick conflict on ${line}
        Resolve the conflict, then resume:
          git cherry-pick --continue
          make release v${VERSION}"
		fi
		ok "Cherry-picked ${line}"
	done <<< "$selected"
}

# ---------------------------------------------------------------------------
# Combined (workspace + derive) release helpers
# ---------------------------------------------------------------------------

# Prompt for a version, echoing the current value when the user enters nothing.
prompt_version() {
	local label="$1"
	local current="$2"
	local input

	printf "\n  Enter %s version (current: %s, enter to keep): " \
		"$label" "${current:-unknown}" >&2
	read -r input
	input="${input#v}"
	[[ -z "$input" ]] && input="$current"

	printf '%s' "$input"
}

# Echo the version of a crate currently published on crates.io (empty if none).
crates_io_version() {
	local crate="$1"
	cargo search "$crate" --limit 1 2>/dev/null \
		| sed -n "s/^${crate} = \"\([^\"]*\)\".*/\1/p" | head -1
}

# Block until a crate version is queryable on crates.io, so dependents publish
# against an indexed release instead of racing it.
wait_for_crate() {
	local crate="$1"
	local want="$2"
	local waited=0
	local timeout=300

	info "Waiting for ${crate} ${want} on crates.io..."
	while (( waited < timeout )); do
		local current
		current=$(crates_io_version "$crate")
		if [[ "$current" == "$want" ]]; then
			ok "${crate} ${want} is live on crates.io"
			return 0
		fi
		printf "  ${YELLOW}[wait]${RESET} %s on crates.io is %s (%ds elapsed)\n" \
			"$crate" "${current:-none}" "$waited"
		sleep 15
		waited=$(( waited + 15 ))
	done

	fail "Timed out waiting for ${crate} ${want} on crates.io"
}

# Create (signed) and push a tag for one crate, computing its changelog against
# the crate's own tag namespace.
push_crate_tag() {
	local tag="$1"
	local crate_version="$2"
	local tag_prefix="$3"

	if [[ -n "$(git tag --list "$tag")" ]]; then
		ok "Tag ${tag} already exists locally - skipping creation"
	else
		VERSION="$crate_version"
		TAG_PREFIX="$tag_prefix"
		CHANGELOG=""
		compile_changelog
		git tag -s -a "$tag" -m "$CHANGELOG"
		ok "Tag ${tag} created (signed)"
	fi

	git push origin "$tag"
	ok "Tag ${tag} pushed"
}

# Release tightbeam-derive and tightbeam together: one PR bumping both crates,
# then derive is tagged/published first and tightbeam follows once derive is
# live on crates.io.
run_combined_release() {
	command -v gh &>/dev/null || fail "gh CLI is required (https://cli.github.com)"
	ok "gh CLI available"

	local tb_toml="Cargo.toml"
	local tb_section="workspace.package"
	local dv_toml="tightbeam-derive/Cargo.toml"
	local dv_section="package"

	local tb_current dv_current
	tb_current=$(detect_version "$tb_toml" "$tb_section")
	dv_current=$(detect_version "$dv_toml" "$dv_section")

	local tb_ver="$VERSION"
	local dv_ver="$DERIVE_VERSION"
	[[ -z "$tb_ver" ]] && tb_ver=$(prompt_version "tightbeam" "$tb_current")
	[[ -z "$dv_ver" ]] && dv_ver=$(prompt_version "tightbeam-derive" "$dv_current")
	tb_ver="${tb_ver#v}"
	dv_ver="${dv_ver#v}"

	local v
	for v in "$tb_ver" "$dv_ver"; do
		[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
			|| fail "Invalid semver format: '${v}'. Expected X.Y.Z (e.g. 0.2.0)"
	done

	if [[ "$DRY_RUN" == true ]]; then
		header "Combined release (dry run)"
	else
		header "Combined release"
	fi
	ok "tightbeam:        ${tb_current:-unknown} -> ${tb_ver}"
	ok "tightbeam-derive: ${dv_current:-unknown} -> ${dv_ver}"

	local branch="process/v${tb_ver}"
	local tb_tag="releases/v${tb_ver}"
	local dv_tag="releases/derive/v${dv_ver}"

	local tb_done=false
	local dv_done=false
	git ls-remote --tags origin "$tb_tag" 2>/dev/null | grep -q "$tb_tag" && tb_done=true
	git ls-remote --tags origin "$dv_tag" 2>/dev/null | grep -q "$dv_tag" && dv_done=true
	if [[ "$tb_done" == true && "$dv_done" == true ]]; then
		ok "Both tags already exist on remote - nothing to do"
		return 0
	fi

	detect_pr_resume_state "$branch"
	local resume="$RESUME_STATE"
	ok "Release state: ${resume}"

	if [[ "$resume" == "fresh" ]]; then
		if [[ -n "$tb_current" && "$tb_done" == false \
			&& "$(semver_compare "$tb_ver" "$tb_current")" == "lt" ]]; then
			fail "tightbeam ${tb_ver} is older than current ${tb_current}"
		fi
		if [[ -n "$dv_current" && "$dv_done" == false \
			&& "$(semver_compare "$dv_ver" "$dv_current")" == "lt" ]]; then
			fail "tightbeam-derive ${dv_ver} is older than current ${dv_current}"
		fi

		header "Validating preconditions..."
		require_signing_key

		git diff --quiet || fail "Working tree has unstaged changes"
		if ! git diff --cached --quiet; then
			[[ "$ALLOW_STAGED" == true ]] || fail "Working tree has staged changes (use --allow-staged to include them)"
			info "Staged changes will be included in the release commit"
		fi

		require_default_branch_synced
	fi

	VERSION="$tb_ver"
	TAG_PREFIX="releases/"

	if [[ "$DRY_RUN" == true ]]; then
		header "Release notes preview"
		print_release_notes
		printf "\n"
		info "Dry run complete. No changes were made."
		return 0
	fi

	local commit_msg="chore(release): tightbeam v${tb_ver} + tightbeam-derive v${dv_ver}"
	local n=0

	if [[ "$resume" == "fresh" ]]; then
		n=$((n + 1))
		step $n "Create branch ${branch}"
		git checkout -b "$branch"
		ok "Branch created"

		bump_version "$dv_ver" "$dv_toml" "$dv_section"
		bump_version "$tb_ver" "$tb_toml" "$tb_section"

		n=$((n + 1))
		step $n "Preview release notes"
		print_release_notes

		n=$((n + 1))
		step $n "Commit release"
		commit_release "$commit_msg"
	fi

	if [[ "$resume" == "fresh" || "$resume" == "pr" ]]; then
		n=$((n + 1))
		step $n "Push branch and create PR"
		if [[ "$resume" == "fresh" ]]; then
			git push -u origin "$branch"
			ok "Branch pushed to origin"
		fi
		create_release_pr "$commit_msg" "$DEFAULT_BRANCH" "$branch"
	fi

	if [[ "$resume" == "fresh" || "$resume" == "pr" || "$resume" == "poll" ]]; then
		n=$((n + 1))
		step $n "Wait for PR merge"
		poll_pr "$PR_NUMBER"
	fi

	if [[ "$resume" != "tag" ]]; then
		n=$((n + 1))
		step $n "Return to ${DEFAULT_BRANCH}"
		git checkout "$DEFAULT_BRANCH"
		git pull origin "$DEFAULT_BRANCH" --quiet
		ok "On ${DEFAULT_BRANCH} at $(git rev-parse --short HEAD)"
	fi

	if [[ "$dv_done" == false ]]; then
		n=$((n + 1))
		step $n "Tag tightbeam-derive (${dv_tag})"
		push_crate_tag "$dv_tag" "$dv_ver" "releases/derive/"
		wait_for_crate "tightbeam-derive" "$dv_ver"
	else
		info "tightbeam-derive ${dv_ver} already released - skipping derive tag"
	fi

	if [[ "$tb_done" == false ]]; then
		n=$((n + 1))
		step $n "Tag tightbeam (${tb_tag})"
		push_crate_tag "$tb_tag" "$tb_ver" "releases/"
	else
		info "tightbeam ${tb_ver} already released - skipping workspace tag"
	fi

	header "Combined release complete!"
	printf "\n"
	printf "  ${BOLD}tightbeam:${RESET}        v%s (%s)\n" "$tb_ver" "$tb_tag"
	printf "  ${BOLD}tightbeam-derive:${RESET} v%s (%s)\n" "$dv_ver" "$dv_tag"
	printf "\n"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
DRY_RUN=false
ALLOW_STAGED=false
YANK=false
COMBINED=true
VERSION=""
DERIVE_VERSION=""
TARGET_CRATE=""
CRATE_INDEX=0

for arg in "$@"; do
	if [[ "$arg" == "--dry-run" ]]; then
		DRY_RUN=true
	elif [[ "$arg" == "--allow-staged" ]]; then
		ALLOW_STAGED=true
	elif [[ "$arg" == "--yank" ]]; then
		YANK=true
		COMBINED=false
	elif [[ "$arg" == "--both" ]]; then
		COMBINED=true
	elif [[ "$arg" == "--single" ]]; then
		COMBINED=false
	elif [[ "$arg" == --derive=* ]]; then
		COMBINED=true
		DERIVE_VERSION="${arg#--derive=}"
	elif [[ "$arg" == "--derive" ]]; then
		COMBINED=false
		CRATE_INDEX=1
	elif [[ -z "$VERSION" ]]; then
		VERSION="$arg"
	fi
done

VERSION="${VERSION#v}"

if [[ "$COMBINED" == true ]]; then
	run_combined_release
	exit 0
fi

TARGET_CRATE="${CRATES[$CRATE_INDEX]}"
CARGO_TOML_PATH="${CRATE_TOML_PATHS[$CRATE_INDEX]}"
VERSION_SECTION="${CRATE_VERSION_SECTIONS[$CRATE_INDEX]}"

if [[ "$CRATE_INDEX" -eq 0 ]]; then
	TAG_PREFIX="releases/"
	BRANCH_PREFIX=""
else
	TAG_PREFIX="releases/derive/"
	BRANCH_PREFIX="derive/"
fi

ok "Targeting crate: ${TARGET_CRATE} (${CARGO_TOML_PATH})"

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
CURRENT_VERSION=""
CURRENT_VERSION=$(detect_version "$CARGO_TOML_PATH" "$VERSION_SECTION")

if [[ "$YANK" == true ]]; then
	if [[ "$DRY_RUN" == true ]]; then
		header "Yank (dry run) - ${TARGET_CRATE}"
	else
		header "Yank - ${TARGET_CRATE}"
	fi
else
	if [[ "$DRY_RUN" == true ]]; then
		header "Release (dry run) - ${TARGET_CRATE}"
	else
		header "Release - ${TARGET_CRATE}"
	fi
fi

if [[ -z "$VERSION" ]]; then
	if [[ "$YANK" == true ]]; then
		all_tags=$(git ls-remote --tags origin 2>/dev/null \
			| sed -n 's|.*refs/tags/\(.*\)$|\1|p' | grep -v '\^{}')
		release_vers=$(echo "$all_tags" | grep "^${TAG_PREFIX}v" | sed "s|${TAG_PREFIX}v||" || true)
		yanked_tag_prefix="yanked/"
		if [[ "$CRATE_INDEX" -eq 1 ]]; then
			yanked_tag_prefix="yanked/derive/"
		fi
		yanked_vers=$(echo "$all_tags" | grep "^${yanked_tag_prefix}v" | sed "s|${yanked_tag_prefix}v||" || true)

		yankable=""
		while IFS= read -r ver; do
			[[ -z "$ver" ]] && continue
			if ! echo "$yanked_vers" | grep -qx "$ver"; then
				yankable+="$ver"$'\n'
			fi
		done <<< "$release_vers"

		if [[ -n "$yankable" ]]; then
			printf "\n  Yankable versions:\n"
			while IFS= read -r ver; do
				[[ -z "$ver" ]] && continue
				printf "    - v%s\n" "$ver"
			done <<< "$yankable"
		else
			fail "No yankable versions found"
		fi
		printf "\n  Enter version to yank: "
	else
		printf "\n  Enter version to release (current: %s): " "${CURRENT_VERSION:-unknown}"
	fi
	read -r VERSION
	VERSION="${VERSION#v}"
fi

# ---------------------------------------------------------------------------
# Semver format validation
# ---------------------------------------------------------------------------
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	fail "Invalid semver format: '${VERSION}'. Expected X.Y.Z (e.g. 0.2.0)"
fi
ok "Semver format valid: ${VERSION}"

# ---------------------------------------------------------------------------
# Release mode detection (forward vs backport)
# ---------------------------------------------------------------------------
IFS='.' read -r SV_MAJOR SV_MINOR SV_PATCH <<< "$VERSION"
RELEASE_MODE="forward"
PR_BASE="$DEFAULT_BRANCH"
RELEASE_BRANCH=""

LATEST_TAG=$(git tag --list "${TAG_PREFIX}v*" --sort=-v:refname | head -1)
if [[ -n "$LATEST_TAG" ]]; then
	LATEST_VER="${LATEST_TAG#${TAG_PREFIX}v}"
	IFS='.' read -r LATEST_MAJOR LATEST_MINOR _ <<< "$LATEST_VER"
	if (( SV_MAJOR < LATEST_MAJOR )) || \
	   (( SV_MAJOR == LATEST_MAJOR && SV_MINOR < LATEST_MINOR )); then
		RELEASE_MODE="backport"
	fi
fi

if [[ "$RELEASE_MODE" == "backport" ]]; then
	RELEASE_BRANCH="release/${BRANCH_PREFIX}${SV_MAJOR}.${SV_MINOR}"
	PR_BASE="$RELEASE_BRANCH"
fi

ok "Release mode: ${RELEASE_MODE} (base: ${PR_BASE})"

BRANCH="process/${BRANCH_PREFIX}v${VERSION}"
TAG="${TAG_PREFIX}v${VERSION}"

YANKED_TAG_PREFIX="yanked/"
if [[ "$CRATE_INDEX" -eq 1 ]]; then
	YANKED_TAG_PREFIX="yanked/derive/"
fi
YANKED_TAG="${YANKED_TAG_PREFIX}v${VERSION}"

# ---------------------------------------------------------------------------
# gh CLI check
# ---------------------------------------------------------------------------
if command -v gh &>/dev/null; then
	ok "gh CLI available"
else
	fail "gh CLI is required (https://cli.github.com)"
fi

# ---------------------------------------------------------------------------
# Yank workflow (early exit)
# ---------------------------------------------------------------------------
if [[ "$YANK" == true ]]; then
	if git ls-remote --tags origin "$YANKED_TAG" 2>/dev/null | grep -q "$YANKED_TAG"; then
		ok "Version v${VERSION} is already yanked (${YANKED_TAG} exists)"
		exit 0
	fi

	if ! git ls-remote --tags origin "$TAG" 2>/dev/null | grep -q "$TAG"; then
		fail "Release tag ${TAG} does not exist on remote - nothing to yank"
	fi

	if [[ "$DRY_RUN" == true ]]; then
		info "Would delete GitHub release for ${TAG}"
		info "Would push marker tag ${YANKED_TAG}"
		info "Dry run complete. No changes were made."
		exit 0
	fi

	step 1 "Delete GitHub release"
	if gh release view "$TAG" &>/dev/null; then
		gh release delete "$TAG" --yes
		ok "GitHub release deleted for ${TAG}"
	else
		info "No GitHub release found for ${TAG} (tag-only release)"
	fi

	step 2 "Push yanked marker tag"
	git tag -a "$YANKED_TAG" \
		-m "Yanked by $(git config user.name) on $(date +%Y-%m-%d)"
	git push origin "$YANKED_TAG"
	ok "Marker tag ${YANKED_TAG} pushed"

	header "Yank complete!"
	printf "\n"
	printf "  ${BOLD}Version:${RESET}  v%s\n" "$VERSION"
	printf "  ${BOLD}Release:${RESET}  deleted\n"
	printf "  ${BOLD}Tag:${RESET}      %s (preserved)\n" "$TAG"
	printf "  ${BOLD}Marker:${RESET}   %s\n" "$YANKED_TAG"
	printf "\n"
	exit 0
fi

# ---------------------------------------------------------------------------
# State detection and resumability
# ---------------------------------------------------------------------------
header "Detecting release state..."

if git ls-remote --tags origin "$TAG" 2>/dev/null | grep -q "$TAG"; then
	ok "Release v${VERSION} already complete (tag ${TAG} exists on remote)"
	exit 0
fi

detect_pr_resume_state "$BRANCH"

if [[ "$RESUME_STATE" == "fresh" ]] && git branch --list "$BRANCH" | grep -q "$BRANCH"; then
	if [[ "$RELEASE_MODE" == "backport" ]]; then
		RESUME_STATE="local"
		git checkout "$BRANCH" --quiet
		info "[resume] Local branch ${BRANCH} found, resuming after cherry-pick..."
	else
		info "[cleanup] Removed stale local branch, starting fresh..."
		git checkout "$DEFAULT_BRANCH" 2>/dev/null || true
		git branch -D "$BRANCH" 2>/dev/null || true
	fi
fi

ok "Release state: ${RESUME_STATE}"

# ---------------------------------------------------------------------------
# Semver comparison (fresh forward releases only)
# ---------------------------------------------------------------------------
if [[ "$RESUME_STATE" == "fresh" && "$RELEASE_MODE" == "forward" && -n "$CURRENT_VERSION" ]]; then
	cmp=$(semver_compare "$VERSION" "$CURRENT_VERSION")
	if [[ "$cmp" == "eq" ]]; then
		if git ls-remote --tags origin "$TAG" 2>/dev/null | grep -q "$TAG"; then
			fail "Already released v${VERSION}"
		fi
		info "Version already at ${VERSION} - resuming incomplete release"
	elif [[ "$cmp" == "lt" ]]; then
		fail "Requested version ${VERSION} is older than current ${CURRENT_VERSION}"
	fi
	ok "Version bump: ${CURRENT_VERSION} -> ${VERSION}"
fi

# ---------------------------------------------------------------------------
# Full validation (fresh releases only)
# ---------------------------------------------------------------------------
if [[ "$RESUME_STATE" == "fresh" ]]; then
	header "Validating preconditions..."

	if [[ -z "$(git tag --list "$TAG")" ]]; then
		ok "Tag ${TAG} does not exist"
	else
		fail "Tag ${TAG} already exists"
	fi

	require_signing_key

	if ! git diff --quiet; then
		fail "Working tree has unstaged changes"
	fi

	if ! git diff --cached --quiet; then
		STAGED_VERSION_ONLY=true
		while IFS= read -r f; do
			case "$f" in
				Cargo.toml|tightbeam-derive/Cargo.toml|Cargo.lock) ;;
				*) STAGED_VERSION_ONLY=false; break ;;
			esac
		done < <(git diff --cached --name-only)

		if [[ "$STAGED_VERSION_ONLY" == true ]] \
			&& [[ "$(detect_version "$CARGO_TOML_PATH" "$VERSION_SECTION")" == "$VERSION" ]]; then
			info "Staged version bump to ${VERSION} from previous attempt"
		elif [[ "$ALLOW_STAGED" == true ]]; then
			info "Staged files will be included in the release commit:"
			git diff --cached --name-only | while IFS= read -r f; do
				printf "    %s\n" "$f"
			done
		else
			fail "Working tree has staged changes (use --allow-staged to include them)"
		fi
	else
		ok "Working tree is clean"
	fi

	if [[ "$RELEASE_MODE" == "forward" ]]; then
		require_default_branch_synced
	fi
fi

# ---------------------------------------------------------------------------
# Dry run: preview only, no mutations
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" == true ]]; then
	header "Release notes preview"
	print_release_notes
	printf "\n"
	info "Dry run complete. No changes were made."
	print_summary
	exit 0
fi

# ---------------------------------------------------------------------------
# Fresh Release
# ---------------------------------------------------------------------------
STEP=0

if [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ]]; then
	if [[ "$RESUME_STATE" == "fresh" ]]; then
		if [[ "$RELEASE_MODE" == "backport" ]]; then
			STEP=$((STEP + 1))
			step $STEP "Prepare release branch ${RELEASE_BRANCH}"
			ensure_release_branch "$RELEASE_BRANCH" "$SV_MAJOR" "$SV_MINOR" "$SV_PATCH"

			STEP=$((STEP + 1))
			step $STEP "Create branch ${BRANCH}"
			git checkout -b "$BRANCH"
			ok "Branch created from ${RELEASE_BRANCH}"

			STEP=$((STEP + 1))
			step $STEP "Cherry-pick commits"
			interactive_cherry_pick "$RELEASE_BRANCH"
		else
			STEP=$((STEP + 1))
			step $STEP "Create branch ${BRANCH}"
			git checkout -b "$BRANCH"
			ok "Branch created"
		fi
	fi

	bump_version "$VERSION" "$CARGO_TOML_PATH" "$VERSION_SECTION"

	STEP=$((STEP + 1))
	step $STEP "Preview release notes"
	print_release_notes

	STEP=$((STEP + 1))
	step $STEP "Commit release"
	commit_release "chore(release): ${TARGET_CRATE} v${VERSION}"
fi

# ---------------------------------------------------------------------------
# Push + PR (fresh or resume from "pr")
# ---------------------------------------------------------------------------
if [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" || "$RESUME_STATE" == "pr" ]]; then
	STEP=$((STEP + 1))
	step $STEP "Push branch and create PR"

	if [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ]]; then
		git push -u origin "$BRANCH"
		ok "Branch pushed to origin"
	fi

	create_release_pr "chore(release): ${TARGET_CRATE} v${VERSION}" "$PR_BASE" "$BRANCH"
fi

# ---------------------------------------------------------------------------
# Poll for merge
# ---------------------------------------------------------------------------
if [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" || "$RESUME_STATE" == "pr" || "$RESUME_STATE" == "poll" ]]; then
	STEP=$((STEP + 1))
	step $STEP "Wait for PR merge"
	poll_pr "$PR_NUMBER"
fi

# ---------------------------------------------------------------------------
# Tag and push
# ---------------------------------------------------------------------------
if [[ "$RESUME_STATE" != "tag" ]]; then
	STEP=$((STEP + 1))
	step $STEP "Return to ${PR_BASE}"
	git checkout "$PR_BASE"
	git pull origin "$PR_BASE" --quiet
	ok "On ${PR_BASE} at $(git rev-parse --short HEAD)"
fi

STEP=$((STEP + 1))
step $STEP "Tag and push (${TAG})"
push_crate_tag "$TAG" "$VERSION" "$TAG_PREFIX"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Release complete!"
print_summary
