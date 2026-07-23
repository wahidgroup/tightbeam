#!/usr/bin/env bash
set -euo pipefail
# Propagate errexit into command substitutions (see BashFAQ/105).
# Bash 4.4+ only. Older shells (macOS default 3.2) keep default behavior.
if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
	shopt -s inherit_errexit
fi

# ---------------------------------------------------------------------------
# release.sh - guided, resumable release automation for GitHub repositories
#
# SYNOPSIS
#	scripts/release.sh [version] [--dry-run] [--allow-staged] [--yank]
#	                   [--<submodule>]
#	make release [version=vX.Y.Z] [dry-run=1] [allow-staged=1] [yank=1]
#
# DESCRIPTION
#	Drives a release from version bump to signed tag as a finite state
#	machine. Each run detects how far a previous run progressed and
#	continues from that point, so an interrupted release is re-run with
#	the same command:
#
#	  entry states:  fresh | local | pr | poll | tag
#	  phases:        prepare -> push_pr -> wait_merge -> tag_push -> done
#
#	Forward releases cut process/v<version> from main. Versions older
#	than the latest tag become backports and cut from the matching
#	release/vX.Y branch (created on demand, commits cherry-picked).
#	Release notes are compiled from merged PR titles and labels. Release
#	and yank marker tags are signed (GPG or SSH).
#
# OPTIONS
#	version         Release version, X.Y.Z or vX.Y.Z. Prompted if absent.
#	--dry-run       Preview every action. No workspace mutation.
#	--allow-staged  Include already-staged changes in the release commit.
#	--yank          Yank a published release: delete the GitHub release,
#	                push signed yanked/v* marker. Release tag preserved.
#	--<submodule>   Run against the named submodule from .gitmodules.
#
# ENVIRONMENT
#	DRY_RUN         Non-empty enables --dry-run (set by make dry-run=1).
#	ALLOW_STAGED    Non-empty enables --allow-staged (allow-staged=1).
#	YANK            Non-empty enables --yank (yank=1).
#
# EXIT STATUS
#	0  Release complete (or already complete), yank complete, or dry run.
#	1  Precondition, validation, network, or tooling failure.
#
# DEPENDENCIES
#	bash 3.2+ (extra hardening on 4.4+), git, gh (authenticated), jq,
#	cargo (when version source is Cargo.toml), node (when version source
#	is package.json), fzf (optional picker).
#
# ATTRIBUTION
#	Tanveer Wahid <tan@wahid.email> - canonical version of this script:
#	https://gist.github.com/sephynox/be7d7f742bea7738b74a3ad723eac165
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BRANCH="master"

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

next_step() {
	STEP=$((STEP + 1))
	step "$STEP" "$1"
}

# HTTPS (.../repo.git) and SCP (git@host:org/repo.git or git@host:repo.git).
project_name_from_remote() {
	local url=""
	if [[ -n "${1:-}" ]]; then
		url="$(git -C "$1" remote get-url origin 2>/dev/null || true)"
	else
		url="$(git remote get-url origin 2>/dev/null || true)"
	fi
	if [[ -z "$url" ]]; then
		printf "unknown"
		return 0
	fi
	printf '%s\n' "$url" | sed -e 's/\.git$//' -e 's|.*/||' -e 's|.*:||'
}

# Exact remote ref checks, fail closed: a network/auth error must abort the
# run instead of reading as "ref absent".
# Usage: remote_ref_exists <tags|heads> <full-ref> [repo-dir]
remote_ref_exists() {
	local kind="$1"
	local ref="$2"
	local dir="${3:-.}"
	local status=0

	git -C "$dir" ls-remote --exit-code "--${kind}" origin "$ref" \
		>/dev/null 2>&1 || status=$?
	if (( status == 0 )); then
		return 0
	fi
	if (( status == 2 )); then
		return 1
	fi
	fail "Could not query origin for ${ref} (network or auth error)"
}

remote_tag_exists() {
	remote_ref_exists tags "refs/tags/${1}" "${2:-.}"
}

remote_head_exists() {
	remote_ref_exists heads "refs/heads/${1}" "${2:-.}"
}

require_tty() {
	if [[ ! -t 0 ]]; then
		fail "$1 requires an interactive terminal (stdin is not a TTY)"
	fi
}

fail_diverged() {
	fail "Local ${BRANCH} and origin/${BRANCH} have diverged. Update or delete the local branch, then retry."
}

# ---------------------------------------------------------------------------
# Release FSM
#
# Resume states (entry): fresh | local | pr | poll | tag
# Phases (pipeline):     prepare -> push_pr -> wait_merge -> tag_push -> done
#
# Entry maps to first phase.
# Each phase advances via fsm_next_phase.
# ---------------------------------------------------------------------------

fsm_assert_resume_state() {
	case "$RESUME_STATE" in
		fresh|local|pr|poll|tag) ;;
		*) fail "Invalid resume state: '${RESUME_STATE}'" ;;
	esac
}

fsm_entry_phase() {
	case "$RESUME_STATE" in
		fresh|local) printf "prepare" ;;
		pr)          printf "push_pr" ;;
		poll)        printf "wait_merge" ;;
		tag)         printf "tag_push" ;;
		*)           fail "Invalid resume state: '${RESUME_STATE}'" ;;
	esac
}

fsm_assert_phase() {
	case "$1" in
		prepare|push_pr|wait_merge|tag_push|done) ;;
		*) fail "Invalid release phase: '${1}'" ;;
	esac
}

fsm_next_phase() {
	case "$1" in
		prepare)    printf "push_pr" ;;
		push_pr)    printf "wait_merge" ;;
		wait_merge) printf "tag_push" ;;
		tag_push)   printf "done" ;;
		*)          fail "Invalid release phase: '${1}'" ;;
	esac
}

fsm_run_phase() {
	local phase="$1"
	fsm_assert_phase "$phase"
	case "$phase" in
		prepare)    prepare_release_work ;;
		push_pr)    push_and_open_pr ;;
		wait_merge) wait_for_merge ;;
		tag_push)   return_and_tag ;;
		done)       ;;
	esac
}

run_release_fsm() {
	fsm_assert_resume_state
	local phase
	phase="$(fsm_entry_phase)"
	info "FSM entry: state=${RESUME_STATE} phase=${phase}"
	while [[ "$phase" != "done" ]]; do
		fsm_run_phase "$phase"
		phase="$(fsm_next_phase "$phase")"
	done
}

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

# Cargo workspaces version from [workspace.package] in the root Cargo.toml.
CARGO_VERSION_SECTION="workspace.package"

cargo_read_version() {
	awk -v section="$CARGO_VERSION_SECTION" -F'"' '
		$0 ~ "^\\[" section "\\]" { in_section = 1; next }
		in_section && /^\[/ { in_section = 0 }
		in_section && /^version[[:space:]]*=/ { print $2; exit }
	' Cargo.toml 2>/dev/null || true
}

cargo_write_version() {
	local version="$1"
	local tmpfile
	tmpfile=$(mktemp)
	awk -v section="$CARGO_VERSION_SECTION" -v version="$version" '
		$0 ~ "^\\[" section "\\]" { in_section = 1; print; next }
		in_section && /^\[/ { in_section = 0 }
		in_section && !replaced \
			&& /^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"/ {
			sub(/"[0-9]+\.[0-9]+\.[0-9]+"/, "\"" version "\"")
			replaced = 1
		}
		{ print }
		END { exit replaced ? 0 : 1 }
	' Cargo.toml > "$tmpfile" \
		|| fail "Could not find version field in [${CARGO_VERSION_SECTION}] of Cargo.toml"
	mv "$tmpfile" Cargo.toml
}

detect_version_source() {
	if [[ -f Cargo.toml ]]; then
		printf "cargo"
	elif [[ -f package.json ]]; then
		printf "npm"
	elif [[ -f VERSION ]]; then
		printf "file"
	fi
}

detect_version() {
	case "$(detect_version_source)" in
		cargo) cargo_read_version ;;
		npm)   node -p "require('./package.json').version" 2>/dev/null || true ;;
		file)  cat VERSION ;;
	esac
}

bump_version() {
	local version="$1"
	local source
	source="$(detect_version_source)"
	case "$source" in
		cargo)
			cargo_write_version "$version"
			git add Cargo.toml
			if [[ -f Cargo.lock ]]; then
				cargo generate-lockfile --offline --quiet 2>/dev/null \
					|| cargo generate-lockfile --quiet 2>/dev/null \
					|| true
				git add Cargo.lock
			fi
			# Repo adaptation: cargo and npm share one workspace version;
			# the release workflow verifies both against the tag.
			if [[ -f ws/client/package.json ]]; then
				(cd ws/client && npm version "$version" \
					--no-git-tag-version --allow-same-version >/dev/null) \
					|| fail "Could not bump ws/client/package.json to ${version}"
				git add ws/client/package.json
				if [[ -f ws/package-lock.json ]]; then
					(cd ws && npm install --package-lock-only \
						--ignore-scripts >/dev/null 2>&1) \
						|| fail "Could not refresh ws/package-lock.json for ${version}"
					git add ws/package-lock.json
				fi
			fi
			;;
		npm)
			npm version "$version" --no-git-tag-version --allow-same-version
			git add package.json
			[[ -f npm-shrinkwrap.json ]] && git add npm-shrinkwrap.json
			[[ -f package-lock.json ]] && git add package-lock.json
			;;
		file)
			printf '%s\n' "$version" > VERSION
			git add VERSION
			;;
		*)
			fail "No version source found (need Cargo.toml, package.json, or VERSION)"
			;;
	esac
	ok "Version updated to ${version}"
}

# Plain X.Y.Z only; prerelease/build metadata (SemVer 2.0.0 items 9-10) is
# rejected so arithmetic comparison below cannot silently misread it.
assert_plain_semver() {
	if [[ ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		fail "Invalid semver format: '${1}'. Expected X.Y.Z (e.g. 0.2.0)"
	fi
}

semver_compare() {
	local -a a b
	local i
	assert_plain_semver "$1"
	assert_plain_semver "$2"
	IFS=. read -ra a <<< "$1"
	IFS=. read -ra b <<< "$2"
	for i in 0 1 2; do
		if (( a[i] > b[i] )); then
			printf "gt"
			return 0
		fi
		if (( a[i] < b[i] )); then
			printf "lt"
			return 0
		fi
	done
	printf "eq"
}

working_tree_clean() {
	git diff --quiet --ignore-submodules \
		&& git diff --cached --quiet --ignore-submodules
}

# Version recorded at <ref> (Cargo.toml, package.json, or VERSION); empty if none.
version_at_ref() {
	local ref="$1"
	if git cat-file -e "${ref}:Cargo.toml" 2>/dev/null; then
		git show "${ref}:Cargo.toml" | awk -v section="$CARGO_VERSION_SECTION" -F'"' '
			$0 ~ "^\\[" section "\\]" { in_section = 1; next }
			in_section && /^\[/ { in_section = 0 }
			in_section && /^version[[:space:]]*=/ { print $2; exit }
		' 2>/dev/null || true
	elif git cat-file -e "${ref}:package.json" 2>/dev/null; then
		git show "${ref}:package.json" \
			| node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).version" 2>/dev/null || true
	elif git cat-file -e "${ref}:VERSION" 2>/dev/null; then
		git show "${ref}:VERSION" | tr -d '\n' || true
	fi
}

# ---------------------------------------------------------------------------
# Changelog / summary / gh helpers
# ---------------------------------------------------------------------------

# Usage: compile_changelog [ref]
compile_changelog() {
	local ref="${1:-HEAD}"

	if [[ -n "${CHANGELOG:-}" ]]; then
		return 0
	fi

	local last_tag
	last_tag=$(git describe --tags --match "releases/v*" --abbrev=0 "$ref" 2>/dev/null) \
		|| last_tag=$(git rev-list --max-parents=0 "$ref")

	local date_str
	date_str=$(date +%Y-%m-%d)

	local changelog_title="## v${VERSION} (${date_str})"

	local components="" i
	if [[ -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
		components=$'\n### Components\n'
		for i in "${!SUBMODULES[@]}"; do
			local submod="${SUBMODULES[$i]}"
			local sub_version
			sub_version=$(cd "$submod" && detect_version)
			local sub_sha
			sub_sha=$(git -C "$submod" rev-parse --short HEAD)

			local line="- **${submod}**"
			if [[ -n "$sub_version" ]]; then
				line+=" v${sub_version}"
			fi
			line+=" (\`${sub_sha}\`)"
			if [[ -n "${SUBMODULE_REFS[$i]:-}" ]]; then
				line+=" @ ${SUBMODULE_REFS[$i]}"
			fi
			components+="${line}"$'\n'
		done
	fi

	local body=""
	local merge_subjects
	merge_subjects=$(git log "${last_tag}..${ref}" --merges --format="%s")

	local labels=""

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
				| jq -r '.headRefName | startswith("process/v")')
			[[ "$is_release_pr" == "true" ]] && continue

			local pr_line
			pr_line=$(echo "$pr_json" \
				| jq -r '"- [#\(.number)](\(.url)) \(.title) (@\(.author.login))"')
			[[ -z "$pr_line" ]] && continue

			body+="${pr_line}"$'\n'

			labels+="$(echo "$pr_json" | jq -r '.labels[].name')"$'\n'
		done <<< "$merge_subjects"
	fi

	RELEASE_LABELS=$(printf '%s' "$labels" | sort -u)

	if [[ -n "$body" && -n "$components" ]]; then
		CHANGELOG="${changelog_title}
${components}
### Changes

${body}"
	elif [[ -n "$components" ]]; then
		CHANGELOG="${changelog_title}
${components}"
	elif [[ -n "$body" ]]; then
		CHANGELOG="${changelog_title}

${body}"
	else
		CHANGELOG="$changelog_title"
	fi
}

# Usage: print_release_notes [ref]
print_release_notes() {
	compile_changelog "${1:-HEAD}"
	printf "\n"
	printf "  ${BOLD}Release Notes (v%s)${RESET}\n" "$VERSION"
	printf "  ──────────────────────────────────\n"
	printf '%s\n' "$CHANGELOG" | while IFS= read -r line; do
		printf "  %s\n" "$line"
	done
	printf "  ──────────────────────────────────\n"
}

print_summary() {
	printf "\n"
	printf "  ${BOLD}Project:${RESET}   %s\n" "$PROJECT_NAME"
	printf "  ${BOLD}Version:${RESET}   %s\n" "$VERSION"
	printf "  ${BOLD}Tag:${RESET}       %s\n" "$TAG"
	printf "  ${BOLD}Branch:${RESET}    %s\n" "$BRANCH"
	if [[ "$RELEASE_MODE" == "backport" ]]; then
		printf "  ${BOLD}Base:${RESET}      %s\n" "$PR_BASE"
	fi
	if [[ -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
		local i pad
		for i in "${!SUBMODULES[@]}"; do
			local submod="${SUBMODULES[$i]}"
			local label
			label="$(echo "${submod:0:1}" | tr '[:lower:]' '[:upper:]')${submod:1}"
			pad=$((10 - ${#label}))
			if (( pad < 1 )); then
				pad=1
			fi
			printf "  ${BOLD}%s:${RESET}%s%s\n" "$label" \
				"$(printf '%*s' "$pad" '')" \
				"${SUBMODULE_REFS[$i]:-current}"
		done
	fi
	printf "\n"
}

poll_pr() {
	local pr_number="$1"
	local start_time
	start_time=$(date +%s)
	local failures=0

	info "Polling PR #${pr_number} for merge (every 10s)..."
	while true; do
		# Tolerate transient gh/network failures instead of dying mid-wait.
		local state
		if state=$(gh pr view "$pr_number" --json state --jq .state 2>/dev/null); then
			failures=0
		else
			failures=$((failures + 1))
			if (( failures >= 6 )); then
				fail "Could not read PR #${pr_number} state after ${failures} consecutive attempts (gh or network error)"
			fi
			info "Could not read PR #${pr_number} state (attempt ${failures}/6) - retrying in 10s"
			sleep 10
			continue
		fi

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

# ---------------------------------------------------------------------------
# Submodule helpers
# ---------------------------------------------------------------------------

detect_submodules() {
	SUBMODULES=()
	local name
	if [[ -f .gitmodules ]]; then
		while IFS= read -r name; do
			SUBMODULES+=("$name")
		done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' \
			| awk '{print $2}')
	fi
}

resolve_submodule_ref() {
	local name="$1"
	local ref="$2"

	git submodule update --init -- "$name"

	if ! git -C "$name" diff --quiet || ! git -C "$name" diff --cached --quiet; then
		fail "${name}: has uncommitted changes"
	fi

	git -C "$name" fetch origin --quiet --tags
	if ! git -C "$name" rev-parse --verify "${ref}^{commit}" &>/dev/null; then
		fail "${name}: ref '${ref}' not found (fetch returned no match)"
	fi

	if [[ "$ref" == releases/v* ]]; then
		local yanked_tag="yanked/${ref#releases/}"
		if remote_tag_exists "$yanked_tag" "$name"; then
			fail "${name}: version ${ref#releases/} has been yanked"
		fi
	fi

	local resolved
	resolved=$(git -C "$name" rev-parse --short "${ref}^{commit}")
	git -C "$name" checkout "$ref" --quiet
	ok "${name}: pinned to ${ref} (${resolved})"
}

resolve_or_keep() {
	local name="$1"
	local ref="$2"

	if [[ -n "$ref" ]]; then
		resolve_submodule_ref "$name" "$ref"
	else
		git submodule update --init "$name"
		ok "${name}: keeping committed pointer"
	fi
}

resolve_submodules() {
	local i
	for i in "${!SUBMODULES[@]}"; do
		resolve_or_keep "${SUBMODULES[$i]}" "${SUBMODULE_REFS[$i]:-}"
	done
}

stage_submodules() {
	local staged=false
	local i

	for i in "${!SUBMODULES[@]}"; do
		if [[ -n "${SUBMODULE_REFS[$i]:-}" ]]; then
			git add "${SUBMODULES[$i]}"
			staged=true
		fi
	done

	if [[ "$staged" == true ]]; then
		ok "Submodule pointers updated"
	else
		ok "No submodule changes"
	fi
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

	if remote_head_exists "$branch"; then
		git checkout "$branch" --quiet
		git pull origin "$branch" --quiet
		ok "Release branch ${branch} is up to date"
		return
	fi

	local base_tag=""
	if (( patch > 0 )); then
		base_tag="releases/v${major}.${minor}.0"
		if ! git rev-parse --verify "${base_tag}^{commit}" &>/dev/null; then
			fail "Base tag ${base_tag} not found - release v${major}.${minor}.0 first"
		fi
	else
		local latest_branch=""
		local candidate candidate_minor
		while IFS= read -r candidate; do
			candidate="${candidate//[[:space:]]/}"
			[[ -z "$candidate" ]] && continue
			candidate_minor="${candidate##*.}"
			[[ "$candidate_minor" =~ ^[0-9]+$ ]] || continue
			# Never fork a new minor line from a higher minor's tip
			if (( candidate_minor < minor )); then
				latest_branch="$candidate"
				break
			fi
		done < <(git branch -r --list "origin/release/v${major}.*" --sort=-v:refname 2>/dev/null)
		if [[ -n "$latest_branch" ]]; then
			git checkout -b "$branch" "$latest_branch"
			git push -u origin "$branch" --quiet
			ok "Created release branch ${branch} from ${latest_branch}"
			return
		fi

		base_tag=""
		local tag_candidate tag_minor
		while IFS= read -r tag_candidate; do
			[[ -z "$tag_candidate" ]] && continue
			tag_minor="${tag_candidate#"releases/v${major}."}"
			tag_minor="${tag_minor%%.*}"
			[[ "$tag_minor" =~ ^[0-9]+$ ]] || continue
			# Never base a new minor line on a higher minor's tag
			if (( tag_minor < minor )); then
				base_tag="$tag_candidate"
				break
			fi
		done < <(git tag --list "releases/v${major}.*" --sort=-v:refname)
		if [[ -z "$base_tag" ]]; then
			# No lower minor line exists (always true for a new .0 line):
			# cut from DEFAULT_BRANCH, per the standard release-lines model
			git fetch origin "$DEFAULT_BRANCH" --quiet
			base_tag="origin/${DEFAULT_BRANCH}"
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

	local selected="" line i selection idx
	local -a indices
	if command -v fzf &>/dev/null; then
		selected=$(echo "$commits" \
			| fzf --multi --reverse \
				--header "Select commits to cherry-pick (TAB to select, ENTER to confirm)" \
			|| true)
	else
		require_tty "Cherry-pick selection"

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
			idx="${idx//[[:space:]]/}"
			if [[ ! "$idx" =~ ^[0-9]+$ ]]; then
				fail "Invalid selection: '${idx}' (expected numbers like 1,3,5)"
			fi
			if (( idx < 1 || idx > ${#lines[@]} )); then
				fail "Selection out of range: ${idx} (valid: 1-${#lines[@]})"
			fi
			selected+="${lines[idx - 1]}"$'\n'
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
          make release version=v${VERSION}"
		fi
		ok "Cherry-picked ${line}"
	done <<< "$selected"
}

# ---------------------------------------------------------------------------
# Phase functions
# ---------------------------------------------------------------------------

parse_args() {
	local dry_run_env="${DRY_RUN:-}"
	local allow_staged_env="${ALLOW_STAGED:-}"
	local yank_env="${YANK:-}"

	DRY_RUN=false
	ALLOW_STAGED=false
	YANK=false
	VERSION=""
	REPO_DIR=""

	if [[ -n "$dry_run_env" ]]; then
		DRY_RUN=true
	fi
	if [[ -n "$allow_staged_env" ]]; then
		ALLOW_STAGED=true
	fi
	if [[ -n "$yank_env" ]]; then
		YANK=true
	fi

	local arg matched submod
	for arg in "$@"; do
		# Makefile passes an empty version argument when version= is unset.
		if [[ -z "$arg" ]]; then
			continue
		fi
		if [[ "$arg" == "--dry-run" ]]; then
			DRY_RUN=true
		elif [[ "$arg" == "--allow-staged" ]]; then
			ALLOW_STAGED=true
		elif [[ "$arg" == "--yank" ]]; then
			YANK=true
		else
			matched=false
			if (( ${#SUBMODULES[@]} > 0 )); then
				for submod in "${SUBMODULES[@]}"; do
					if [[ "$arg" == "--${submod}" ]]; then
						if [[ -n "$REPO_DIR" ]]; then
							fail "Only one --<submodule> flag allowed at a time"
						fi
						REPO_DIR="$submod"
						matched=true
						break
					fi
				done
			fi
			if [[ "$matched" == false ]]; then
				if [[ "$arg" == --* ]]; then
					fail "Unknown flag: ${arg}"
				fi
				if [[ -n "$VERSION" ]]; then
					fail "Unexpected argument: '${arg}' (version already set to '${VERSION}')"
				fi
				VERSION="$arg"
			fi
		fi
	done

	VERSION="${VERSION#v}"
}

enter_submodule_mode() {
	if [[ -z "$REPO_DIR" ]]; then
		return 0
	fi
	if [[ ! -d "$REPO_DIR/.git" && ! -f "$REPO_DIR/.git" ]]; then
		fail "${REPO_DIR} is not a git repository (run 'make setup' first)"
	fi

	PROJECT_NAME="$(project_name_from_remote "$REPO_DIR")"
	cd "$REPO_DIR"
	ok "Targeting submodule: ${PROJECT_NAME} ($(pwd))"
}

print_run_header() {
	local kind="Release"
	if [[ "$YANK" == true ]]; then
		kind="Yank"
	fi
	if [[ "$DRY_RUN" == true ]]; then
		header "${kind} (dry run) - ${PROJECT_NAME}"
	else
		header "${kind} - ${PROJECT_NAME}"
	fi
}

resolve_version_interactive() {
	if [[ -n "$VERSION" ]]; then
		return 0
	fi

	require_tty "Version prompt"

	if [[ "$YANK" == true ]]; then
		local all_tags release_vers yanked_vers yankable ver
		if ! all_tags=$(git ls-remote --tags origin 2>/dev/null); then
			fail "Could not list tags on origin (network or auth error)"
		fi
		all_tags=$(printf '%s\n' "$all_tags" \
			| sed -n 's|.*refs/tags/\(.*\)$|\1|p' | grep -v '\^{}' || true)
		release_vers=$(echo "$all_tags" | grep '^releases/v' | sed 's|releases/v||' || true)
		yanked_vers=$(echo "$all_tags" | grep '^yanked/v' | sed 's|yanked/v||' || true)

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
}

validate_semver() {
	assert_plain_semver "$VERSION"
	ok "Semver format valid: ${VERSION}"
}

detect_release_mode() {
	IFS='.' read -r SV_MAJOR SV_MINOR SV_PATCH <<< "$VERSION"
	RELEASE_MODE="forward"
	PR_BASE="$DEFAULT_BRANCH"
	RELEASE_BRANCH=""

	local latest_tag latest_ver latest_major latest_minor
	git fetch origin --tags --quiet 2>/dev/null || true
	latest_tag=$(git tag --list "releases/v*" --sort=-v:refname | head -1)
	if [[ -n "$latest_tag" ]]; then
		latest_ver="${latest_tag#releases/v}"
		IFS='.' read -r latest_major latest_minor _ <<< "$latest_ver"
		if (( SV_MAJOR < latest_major )) || \
		   (( SV_MAJOR == latest_major && SV_MINOR < latest_minor )); then
			RELEASE_MODE="backport"
		fi
	fi

	if [[ "$RELEASE_MODE" == "backport" ]]; then
		RELEASE_BRANCH="release/v${SV_MAJOR}.${SV_MINOR}"
		PR_BASE="$RELEASE_BRANCH"
	fi

	ok "Release mode: ${RELEASE_MODE} (base: ${PR_BASE})"

	BRANCH="process/v${VERSION}"
	TAG="releases/v${VERSION}"
	YANKED_TAG="yanked/v${VERSION}"
}

require_gh() {
	if ! command -v gh &>/dev/null; then
		fail "gh CLI is required (https://cli.github.com)"
	fi
	# Unauthenticated gh reads as "no PR" in state detection; fail closed here.
	if ! gh auth status &>/dev/null; then
		fail "gh CLI is not authenticated (run 'gh auth login')"
	fi
	ok "gh CLI available and authenticated"
}

require_signing_key() {
	local signing_key sign_format
	signing_key=$(git config user.signingkey 2>/dev/null || true)
	if [[ -n "$signing_key" ]]; then
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

require_jq() {
	if command -v jq &>/dev/null; then
		ok "jq available"
	else
		fail "jq is required for release notes (https://jqlang.github.io/jq/)"
	fi
}

run_yank() {
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

	require_signing_key

	step 1 "Delete GitHub release"
	if gh release view "$TAG" &>/dev/null; then
		gh release delete "$TAG" --yes
		ok "GitHub release deleted for ${TAG}"
	else
		info "No GitHub release found for ${TAG} (tag-only release)"
	fi

	step 2 "Push yanked marker tag"
	# Signed like release tags: unsigned markers could be forged.
	git tag -s "$YANKED_TAG" \
		-m "Yanked by $(git config user.name) on $(date +%Y-%m-%d)"
	git push origin "$YANKED_TAG"
	ok "Marker tag ${YANKED_TAG} pushed (signed)"

	header "Yank complete!"
	printf "\n"
	printf "  ${BOLD}Version:${RESET}  v%s\n" "$VERSION"
	printf "  ${BOLD}Release:${RESET}  %s\n" "deleted"
	printf "  ${BOLD}Tag:${RESET}      %s (preserved)\n" "$TAG"
	printf "  ${BOLD}Marker:${RESET}   %s\n" "$YANKED_TAG"
	printf "\n"
	exit 0
}

# Pure detection: sets RESUME_STATE / RESUME_NEEDS_CHECKOUT. No checkout.
detect_resume_state() {
	PR_NUMBER=""
	PR_STATE=""
	RESUME_STATE="fresh"
	RESUME_NEEDS_CHECKOUT=false

	header "Detecting release state..."

	if remote_tag_exists "$TAG"; then
		ok "Release v${VERSION} already complete (tag ${TAG} exists on remote)"
		exit 0
	fi

	local pr_line tip_subject tip_version
	if ! pr_line=$(gh pr list --head "$BRANCH" --state all --json number,state \
		--jq '.[0] | select(. != null) | "\(.number) \(.state)"' 2>/dev/null); then
		fail "Could not list PRs for ${BRANCH} (gh or network error)"
	fi
	if [[ -n "$pr_line" ]]; then
		read -r PR_NUMBER PR_STATE <<< "$pr_line"
	fi

	if [[ -n "$PR_NUMBER" && "$PR_STATE" == "MERGED" ]]; then
		RESUME_STATE="tag"
		info "[resume] PR #${PR_NUMBER} already merged, continuing to tag..."
	elif [[ -n "$PR_NUMBER" && "$PR_STATE" == "OPEN" ]]; then
		RESUME_STATE="poll"
		info "[resume] PR #${PR_NUMBER} is open, waiting for merge..."
	elif [[ -n "$PR_NUMBER" && "$PR_STATE" == "CLOSED" ]]; then
		fail "Previous release PR #${PR_NUMBER} for ${BRANCH} was closed without merging. Delete the branch (git push origin --delete ${BRANCH}) or reopen PR #${PR_NUMBER}, then retry."
	elif remote_head_exists "$BRANCH"; then
		RESUME_STATE="pr"
		# Need local checkout of process/v* so changelog/PR body use release history.
		RESUME_NEEDS_CHECKOUT=true
		info "[resume] Branch ${BRANCH} exists on remote, creating PR..."
	elif git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
		if [[ "$RELEASE_MODE" == "backport" ]]; then
			RESUME_STATE="local"
			RESUME_NEEDS_CHECKOUT=true
			info "[resume] Local branch ${BRANCH} found, resuming after cherry-pick..."
		else
			# Forward: inspect tip without checkout.
			tip_subject=$(git log -1 --pretty=%s "$BRANCH" 2>/dev/null || true)
			tip_version=$(version_at_ref "$BRANCH")

			if [[ "$tip_subject" == "chore(release):"* && "$tip_version" == "$VERSION" ]]; then
				# Finished release tip: clean tree required to resume.
				if ! working_tree_clean; then
					fail "Working tree has uncommitted changes; clean tree required to resume ${BRANCH}"
				fi
				RESUME_STATE="local"
				RESUME_NEEDS_CHECKOUT=true
				info "[resume] Local branch ${BRANCH} found, resuming forward release..."
			elif [[ "$tip_subject" == "chore(release):"* ]]; then
				# Wrong-version release tip: fail closed (do not auto-delete).
				fail "Local branch ${BRANCH} tip is chore(release) for v${tip_version:-unknown}, not v${VERSION}. Delete it (git branch -D ${BRANCH}) or finish that release, then retry."
			else
				# No release commit yet: only resume if tip still equals origin/DEFAULT_BRANCH.
				local tip_sha base_sha
				git fetch origin "$DEFAULT_BRANCH" --quiet
				tip_sha=$(git rev-parse "$BRANCH")
				base_sha=$(git rev-parse "origin/${DEFAULT_BRANCH}")
				if [[ "$tip_sha" == "$base_sha" ]]; then
					RESUME_STATE="local"
					RESUME_NEEDS_CHECKOUT=true
					info "[resume] Local branch ${BRANCH} found at origin/${DEFAULT_BRANCH}, resuming forward release..."
				else
					fail "Local branch ${BRANCH} tip is not on origin/${DEFAULT_BRANCH} (abandoned or dirty process branch). Delete it (git branch -D ${BRANCH}) and retry from ${DEFAULT_BRANCH}."
				fi
			fi
		fi
	fi

	fsm_assert_resume_state
	ok "Release state: ${RESUME_STATE}"
}

# Prints eq|ahead|behind|diverged for local BRANCH vs origin/BRANCH.
# Both refs must already exist (fetch first).
branch_sync_state() {
	local local_sha remote_sha
	local_sha=$(git rev-parse "refs/heads/${BRANCH}")
	remote_sha=$(git rev-parse "refs/remotes/origin/${BRANCH}")
	if [[ "$local_sha" == "$remote_sha" ]]; then
		printf "eq"
	elif git merge-base --is-ancestor "$local_sha" "$remote_sha"; then
		printf "behind"
	elif git merge-base --is-ancestor "$remote_sha" "$local_sha"; then
		printf "ahead"
	else
		printf "diverged"
	fi
}

# For pr resume: local HEAD must match origin tip for changelog (ff if behind).
align_pr_branch_to_origin() {
	case "$(branch_sync_state)" in
		eq)
			;;
		ahead)
			# Strictly ahead: push_and_open_pr will push.
			;;
		behind)
			git reset --quiet --hard "origin/${BRANCH}"
			ok "Local ${BRANCH} aligned to origin/${BRANCH}"
			;;
		diverged)
			fail_diverged
			;;
	esac
}

# Dry run must not checkout or reset anything.
resolve_dry_run_notes_ref() {
	local ref=""
	case "$RESUME_STATE" in
		fresh)
			return 0
			;;
		local)
			git fetch origin "$BRANCH" --quiet 2>/dev/null || true
			if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
				ref="refs/heads/${BRANCH}"
			elif git rev-parse --verify "refs/remotes/origin/${BRANCH}" >/dev/null 2>&1; then
				ref="refs/remotes/origin/${BRANCH}"
			fi
			;;
		pr|poll)
			git fetch origin "$BRANCH" --quiet 2>/dev/null || true
			if git rev-parse --verify "refs/remotes/origin/${BRANCH}" >/dev/null 2>&1; then
				ref="refs/remotes/origin/${BRANCH}"
			elif git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
				ref="refs/heads/${BRANCH}"
			fi
			;;
		tag)
			git fetch origin "$PR_BASE" --quiet 2>/dev/null || true
			if git rev-parse --verify "refs/remotes/origin/${PR_BASE}" >/dev/null 2>&1; then
				ref="refs/remotes/origin/${PR_BASE}"
			fi
			;;
	esac
	if [[ -z "$ref" ]]; then
		fail "Could not resolve a ref for dry run notes preview (state: ${RESUME_STATE})"
	fi
	NOTES_REF="$ref"
	info "Dry run: no checkout (notes preview uses ${NOTES_REF})"
}

# Apply workspace mutation required by detected resume state.
# Sets NOTES_REF: the ref release-note previews read history from.
enter_resume_workspace() {
	NOTES_REF="HEAD"

	if [[ "$DRY_RUN" == true ]]; then
		resolve_dry_run_notes_ref
		return 0
	fi

	if [[ "${RESUME_NEEDS_CHECKOUT}" != true ]]; then
		return 0
	fi

	# pr resume needs origin tip; local resume may work offline from local ref.
	if [[ "$RESUME_STATE" == "pr" ]]; then
		if ! git fetch origin "$BRANCH" --quiet; then
			fail "Could not fetch origin/${BRANCH}"
		fi
	else
		git fetch origin "$BRANCH" --quiet 2>/dev/null || true
	fi

	if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
		if ! git checkout "$BRANCH" --quiet; then
			fail "Could not checkout ${BRANCH} to resume release"
		fi
		if [[ "$RESUME_STATE" == "pr" ]]; then
			align_pr_branch_to_origin
		fi
		return 0
	fi

	if git rev-parse --verify "refs/remotes/origin/${BRANCH}" >/dev/null 2>&1; then
		if ! git checkout -b "$BRANCH" --track "origin/${BRANCH}" --quiet; then
			fail "Could not create local ${BRANCH} from origin/${BRANCH}"
		fi
		return 0
	fi

	fail "Could not checkout ${BRANCH}: no local or origin/${BRANCH} ref"
}

# Reads NOTES_REF so dry-run resume reflects the branch tip, not current HEAD.
mark_release_commit_exists() {
	RELEASE_COMMIT_EXISTS=false
	if [[ "$RESUME_STATE" == "local" ]] \
		&& [[ "$(git log -1 --pretty=%s "$NOTES_REF" 2>/dev/null)" == "chore(release):"* ]] \
		&& [[ "$(version_at_ref "$NOTES_REF")" == "$VERSION" ]] \
		&& working_tree_clean; then
		RELEASE_COMMIT_EXISTS=true
	fi
}

assert_version_bump_ok() {
	local cmp line_tag line_ver

	if [[ ( "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ) && "$RELEASE_MODE" == "forward" && -n "$CURRENT_VERSION" ]]; then
		cmp=$(semver_compare "$VERSION" "$CURRENT_VERSION")
		if [[ "$cmp" == "eq" ]]; then
			if remote_tag_exists "$TAG"; then
				fail "Already released v${VERSION}"
			fi
			info "Version already at ${VERSION} - resuming incomplete release"
		elif [[ "$cmp" == "lt" ]]; then
			fail "Requested version ${VERSION} is older than current ${CURRENT_VERSION}"
		else
			ok "Version bump: ${CURRENT_VERSION} -> ${VERSION}"
		fi
	fi

	if [[ ( "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ) && "$RELEASE_MODE" == "backport" ]]; then
		line_tag=$(git tag --list "releases/v${SV_MAJOR}.${SV_MINOR}.*" --sort=-v:refname | head -1)
		if [[ -n "$line_tag" ]]; then
			line_ver="${line_tag#releases/v}"
			cmp=$(semver_compare "$VERSION" "$line_ver")
			if [[ "$cmp" == "eq" ]]; then
				if remote_tag_exists "$TAG"; then
					fail "Already released v${VERSION} on ${RELEASE_BRANCH}"
				fi
				info "Version already at ${VERSION} on ${RELEASE_BRANCH} - resuming incomplete release"
			elif [[ "$cmp" == "lt" ]]; then
				fail "Requested version ${VERSION} is older than latest ${line_ver} on ${RELEASE_BRANCH}"
			else
				ok "Backport bump: ${line_ver} -> ${VERSION}"
			fi
		fi
	fi
}

prompt_submodule_refs() {
	SUBMODULE_REFS=()

	if [[ "$RELEASE_COMMIT_EXISTS" == false ]] \
		&& [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ]] \
		&& [[ -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
		require_tty "Submodule ref prompt"

		local prompt_suffix="" ref i
		if [[ "$RELEASE_MODE" == "backport" ]]; then
			prompt_suffix=" for backport"
		fi
		for i in "${!SUBMODULES[@]}"; do
			printf "\n  Enter %s tag or commit hash%s (Enter to keep current): " \
				"${SUBMODULES[$i]}" "$prompt_suffix"
			read -r ref
			SUBMODULE_REFS[i]="$ref"
		done
	fi
}

validate_preconditions() {
	if [[ "$RESUME_STATE" != "fresh" && "$RESUME_STATE" != "local" ]]; then
		return 0
	fi

	header "Validating preconditions..."

	if [[ -z "$(git tag --list "$TAG")" ]]; then
		ok "Tag ${TAG} does not exist"
	else
		fail "Tag ${TAG} already exists"
	fi

	require_signing_key

	if ! git diff --quiet --ignore-submodules; then
		fail "Working tree has unstaged changes (excluding submodules)"
	fi

	if ! git diff --cached --quiet --ignore-submodules; then
		local staged_version_only=true f
		while IFS= read -r f; do
			case "$f" in
				Cargo.toml|Cargo.lock|package.json|package-lock.json|npm-shrinkwrap.json|VERSION) ;;
				*) staged_version_only=false; break ;;
			esac
		done < <(git diff --cached --name-only --ignore-submodules)

		if [[ "$staged_version_only" == true ]] \
			&& [[ "$(detect_version)" == "$VERSION" ]]; then
			info "Staged version bump to ${VERSION} from previous attempt"
		elif [[ "$ALLOW_STAGED" == true ]]; then
			info "Staged files will be included in the release commit:"
			git diff --cached --name-only --ignore-submodules | while IFS= read -r f; do
				printf "    %s\n" "$f"
			done
		else
			fail "Working tree has staged changes (use --allow-staged to include them)"
		fi
	else
		ok "Working tree is clean (excluding submodules)"
	fi

	# Fresh forward only: must start from up-to-date DEFAULT_BRANCH.
	# Local resume is already on process/v* with a matching release tip.
	if [[ "$RELEASE_MODE" == "forward" && "$RESUME_STATE" == "fresh" ]]; then
		local current_branch local_sha remote_sha
		current_branch=$(git branch --show-current)
		if [[ "$current_branch" == "$DEFAULT_BRANCH" ]]; then
			ok "On branch ${DEFAULT_BRANCH}"
		else
			fail "Must be on branch ${DEFAULT_BRANCH} (currently on ${current_branch})"
		fi

		git fetch origin "$DEFAULT_BRANCH" --quiet
		local_sha=$(git rev-parse HEAD)
		remote_sha=$(git rev-parse "origin/${DEFAULT_BRANCH}")
		if [[ "$local_sha" == "$remote_sha" ]]; then
			ok "${DEFAULT_BRANCH} is up to date with origin/${DEFAULT_BRANCH}"
		else
			fail "${DEFAULT_BRANCH} is not up to date with origin/${DEFAULT_BRANCH} (pull or push first)"
		fi
	fi

	if [[ "$RELEASE_COMMIT_EXISTS" == false && "$DRY_RUN" != true \
		&& "$RELEASE_MODE" == "forward" && -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
		header "Resolving submodules..."
		resolve_submodules
	fi
}

run_dry_run() {
	header "Release notes preview"
	print_release_notes "$NOTES_REF"
	printf "\n"
	info "Dry run complete. No changes were made."
	print_summary
	exit 0
}

prepare_release_work() {
	if [[ "$RESUME_STATE" == "fresh" ]]; then
		if [[ "$RELEASE_MODE" == "backport" ]]; then
			next_step "Prepare release branch ${RELEASE_BRANCH}"
			ensure_release_branch "$RELEASE_BRANCH" "$SV_MAJOR" "$SV_MINOR" "$SV_PATCH"

			next_step "Create branch ${BRANCH}"
			git checkout -b "$BRANCH"
			ok "Branch created from ${RELEASE_BRANCH}"

			next_step "Cherry-pick commits"
			interactive_cherry_pick "$RELEASE_BRANCH"
		else
			next_step "Create branch ${BRANCH}"
			git checkout -b "$BRANCH"
			ok "Branch created"

			if [[ -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
				next_step "Update submodule pointers"
				stage_submodules
			fi
		fi
	fi

	if [[ "$RELEASE_COMMIT_EXISTS" == true ]]; then
		info "Release commit already present; skipping version bump and commit"
	else
		if [[ -z "$REPO_DIR" && ${#SUBMODULES[@]} -gt 0 ]]; then
			if [[ "$RELEASE_MODE" == "backport" ]]; then
				header "Resolving submodules..."
				resolve_submodules
				next_step "Update submodule pointers"
				stage_submodules
			elif [[ "$RESUME_STATE" == "local" ]]; then
				# Forward local resume: pointers resolved during validation.
				next_step "Update submodule pointers"
				stage_submodules
			fi
		fi

		bump_version "$VERSION"

		next_step "Preview release notes"
		print_release_notes

		next_step "Commit release"
		if git diff --cached --quiet; then
			info "Nothing staged - creating empty release marker commit"
			git commit --allow-empty -m "chore(release): v${VERSION}"
		else
			git commit -m "chore(release): v${VERSION}"
		fi
		ok "Committed chore(release): v${VERSION}"
	fi
}

push_and_open_pr() {
	next_step "Push branch and create PR"

	if [[ "$RESUME_STATE" == "fresh" || "$RESUME_STATE" == "local" ]]; then
		git push -u origin "$BRANCH"
		ok "Branch pushed to origin"
	elif [[ "$RESUME_STATE" == "pr" ]] \
		&& git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
		# Push only when local is strictly ahead.
		git fetch origin "$BRANCH" --quiet
		case "$(branch_sync_state)" in
			eq)
				ok "Local ${BRANCH} already matches origin"
				;;
			behind)
				info "Local ${BRANCH} is behind origin - skipping push"
				;;
			ahead)
				git push origin "$BRANCH"
				ok "Local ${BRANCH} pushed to origin"
				;;
			diverged)
				fail_diverged
				;;
		esac
	fi

	compile_changelog

	ensure_label "release"

	# Only apply labels that already exist in the repo (plus 'release')
	local existing_labels label
	if ! existing_labels=$(gh label list --limit 200 --json name \
		--jq '.[].name' 2>/dev/null); then
		fail "Could not list repo labels (gh or network error)"
	fi

	local -a pr_labels=()
	while IFS= read -r label; do
		[[ -z "$label" ]] && continue
		if [[ "$label" == "release" ]] || printf '%s\n' "$existing_labels" | grep -qxF "$label"; then
			pr_labels+=("$label")
		fi
	done < <({ printf 'release\n'; printf '%s\n' "${RELEASE_LABELS:-}"; } | sort -u)

	local -a pr_create_args=(
		--title "chore(release): v${VERSION}"
		--body "$CHANGELOG"
		--base "$PR_BASE"
		--head "$BRANCH"
		--assignee "@me"
	)
	for label in "${pr_labels[@]}"; do
		pr_create_args+=(--label "$label")
	done

	local pr_url existing_pr
	if ! existing_pr=$(gh pr list --head "$BRANCH" --state open --json number,url \
		--jq '.[0] | select(.number != null) | "\(.number) \(.url)"' 2>/dev/null); then
		fail "Could not list open PRs for ${BRANCH} (gh or network error)"
	fi
	if [[ -n "$existing_pr" ]]; then
		read -r PR_NUMBER pr_url <<< "$existing_pr"
		local -a pr_edit_args=(
			--title "chore(release): v${VERSION}"
			--body "$CHANGELOG"
		)
		for label in "${pr_labels[@]}"; do
			pr_edit_args+=(--add-label "$label")
		done
		gh pr edit "$PR_NUMBER" "${pr_edit_args[@]}" >/dev/null
		ok "PR #${PR_NUMBER} already open: ${pr_url}"
	else
		pr_url=$(gh pr create "${pr_create_args[@]}")
		PR_NUMBER="${pr_url##*/}"
		ok "PR #${PR_NUMBER} created: ${pr_url}"
	fi
}

wait_for_merge() {
	next_step "Wait for PR merge"
	poll_pr "$PR_NUMBER"
}

return_and_tag() {
	next_step "Return to ${PR_BASE}"
	git fetch origin "$PR_BASE" --quiet
	git checkout "$PR_BASE"
	git pull origin "$PR_BASE" --quiet
	ok "On ${PR_BASE} at $(git rev-parse --short HEAD)"

	next_step "Create signed tag"
	if [[ -n "$(git tag --list "$TAG")" ]]; then
		ok "Tag ${TAG} already exists locally - skipping creation"
	else
		# Rebuild notes from updated PR_BASE (do not reuse pre-merge CHANGELOG).
		CHANGELOG=""
		compile_changelog
		git tag -s "$TAG" -m "$CHANGELOG"
		ok "Tag ${TAG} created (signed)"
	fi

	next_step "Push tag"
	git push origin "$TAG"
	ok "Tag pushed to origin"
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

main() {
	PROJECT_NAME="$(project_name_from_remote)"

	detect_submodules
	parse_args "$@"
	enter_submodule_mode

	CURRENT_VERSION=$(detect_version)

	print_run_header
	resolve_version_interactive
	validate_semver
	detect_release_mode
	require_gh

	if [[ "$YANK" == true ]]; then
		run_yank
	fi

	# Tag-complete exits here (gh --jq only); external jq needed after this.
	detect_resume_state
	require_jq
	enter_resume_workspace
	mark_release_commit_exists
	assert_version_bump_ok
	prompt_submodule_refs
	validate_preconditions

	if [[ "$DRY_RUN" == true ]]; then
		run_dry_run
	fi

	STEP=0
	run_release_fsm

	header "Release complete!"
	print_summary
}

main "$@"
