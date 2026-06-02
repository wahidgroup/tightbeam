.PHONY: help help-ref version setup check build clean test lint doc test-all fuzz-build fuzz-test analyze-fuzz clean-fuzz release check-yanked audit

# Project metadata for help/version
PROJECT := tightbeam
VERSION := $(shell awk -F\" '/^\s*version\s*=\s*"/{print $$2; exit}' Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

# Extract version and flags from positional args (e.g., `make release v0.7.0 --derive`)
RELEASE_VERSION := $(filter v%,$(MAKECMDGOALS))
RELEASE_FLAGS   := $(filter-out --,$(filter --%,$(MAKECMDGOALS)))

# Print wrapper function
define PRINT_PAGER
@{ $(1); } | less -FRX
endef

# Default target (prints help)
help:
	$(call PRINT_PAGER,$(MAKE) help-body)

help-body:
	@printf 'USAGE:\n'
	@printf '    make <target> [features="<comma-separated features>"] [no-default=1] [ARGS="<clippy-args>"]\n\n'
	@printf 'DESCRIPTION:\n'
	@printf '    Build, lint, test, and document the %s workspace following POSIX/GNU CLI conventions.\n\n' '$(PROJECT)'
	@printf 'TARGETS:\n'
	@printf '    help            Show this help and exit\n'
	@printf '    help-ref        Show reference documentation links\n'
	@printf '    version         Show project version information\n'
	@printf '    setup           Setup the development environment\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build all projects (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run all tests (honors cargo features and no-default)\n'
	@printf '    test-all        Run tests with all feature combinations\n'
	@printf '    fuzz-build      Build AFL-instrumented fuzz targets (requires cargo-afl)\n'
	@printf '    fuzz-test       Build and run AFL fuzz testing for 60 seconds\n'
	@printf '    analyze-fuzz    Analyze a specific crash/hang file (requires file=...)\n'
	@printf '    clean-fuzz      Remove fuzz output artifacts\n'
	@printf '    lint            Run linters (fix mode via fix=1; extra clippy args via ARGS)\n'
	@printf '    audit           Run security audit (RustSec cargo-audit)\n'
	@printf '    doc             Build documentation (all features)\n'
	@printf '    release         Release both crates by default, prompting for each version (make release [--dry-run] [--allow-staged])\n'
	@printf '                    Single crate: make release v0.7.0 single=1 (tightbeam) | make release v0.1.5 --derive (derive) | --yank\n'
	@printf '    check-yanked    Check if current version has been yanked\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1/true), passes --no-default-features to Cargo\n'
	@printf '    ARGS            Extra arguments for clippy (e.g., "--allow-dirty --allow-staged")\n'
	@printf '    fix             If set (e.g., fix=1), apply fixes: cargo fmt + clippy --fix\n'
	@printf '    derive          Preset tightbeam-derive version for the combined release (e.g., derive=0.1.5)\n'
	@printf '    single          If set (e.g., single=1), release only tightbeam instead of both crates\n\n'
	@printf 'ENVIRONMENT:\n'
	@printf '    CARGO_TERM_COLOR, RUSTFLAGS, RUSTC_WRAPPER (honored by Cargo/rustc)\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make build features="std,tcp,tokio"\n'
	@printf '    make test no-default=1 features="testing"\n'
	@printf '    make lint fix=1\n'
	@printf '    make release\n'
	@printf '    make release v0.7.0 derive=0.1.5\n'
	@printf '    make release v0.7.0 single=1\n\n'
	@printf 'EXIT STATUS:\n'
	@printf '    0    Success\n'
	@printf '    >0   Error occurred\n\n'

help-ref:
	@printf 'REFERENCES:\n'
	@printf '    GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html\n'
	@printf '    POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html\n\n'

# Version info (similar to -V/--version in CLI tools)
version:
	@v='$(VERSION)'; c='$(GIT_COMMIT)'; d='$(GIT_DIRTY)'; [ -n "$$v" ] || v=unknown; \
	printf '%s %s (%s%s)\n' '$(PROJECT)' "$$v" "$$c" "$$d"

# Setup local development
setup:
	@echo "Setting up the development environment..."
	@echo "Installing development tools..."
	rustup component add rustfmt clippy
	@echo "Installing cross-compilation targets..."
	rustup target add wasm32-unknown-unknown

# Build all projects
build:
	@echo "Building tightbeam..."
	cargo build --release $(if $(features),--features "$(features)")

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf built
	rm -rf target

# Check
check:
	@echo "Checking tightbeam..."
	cargo check $(if $(features),--features "$(features)")

# Run all tests
test: build
	@echo "Running tests..."
	cargo test $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

# Run tests with all feature combinations
test-all: build  ## Run curated feature combination tests
	@echo "Running tests with all feature combinations..."
	./scripts/test_features.sh

# Build AFL-instrumented fuzz targets
fuzz-build:
	@./scripts/fuzz-build.sh

# Run AFL fuzz testing for a short time (60 seconds for CI/smoke testing)
# Options:
#   skip-missing-crashes=1  - Skip crash reporting config check (AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1)
#   skip-cpu-freq=1         - Skip CPU frequency scaling check (AFL_SKIP_CPUFREQ=1)
fuzz-test: fuzz-build
	@./scripts/fuzz-test.sh \
		$(if $(filter 1,$(skip-missing-crashes)),--skip-missing-crashes) \
		$(if $(filter 1,$(skip-cpu-freq)),--skip-cpu-freq)

# Analyze a specific fuzz crash or hang
# Usage: make analyze-fuzz file=built/fuzz/out/default/crashes/id:000000...
analyze-fuzz:
	@./scripts/fuzz-analyze.sh "$(file)"

# Clean fuzz artifacts
clean-fuzz:
	@echo "Cleaning fuzz artifacts..."
	rm -rf built/fuzz/out
	@echo "Fuzz output directory cleaned."

# Linters: enable fix mode with `fix=1`; pass extra clippy args via ARGS="...".
ifneq ($(strip $(fix)),)
FMT_CMD     := cargo fmt --all
CLIPPY_MODE := --fix
CLIPPY_DENY :=
LINT_MODE   := fix
else
FMT_CMD     := cargo fmt --all --check
CLIPPY_MODE :=
CLIPPY_DENY := -- -D warnings
LINT_MODE   := check
endif

# Swallow option-like extra MAKECMDGOALS so make doesn't error on them
# Supports: `--`, `--foo`, `--foo=bar`
--:
	@:
--%:
	@:
v%:
	@:

# Check if current version has been yanked
check-yanked:
	@./scripts/check-yanked.sh

# Run security audit (RustSec advisory database)
audit:
	@./scripts/audit.sh

# Release workflow
release:
	@./scripts/release.sh "$(RELEASE_VERSION)" $(RELEASE_FLAGS) $(if $(derive),--derive=$(derive)) $(if $(both),--both) $(if $(single),--single)

# Run linters
lint:
	@echo "Running linters (mode: $(LINT_MODE))..."
	@echo "Formatting: $(FMT_CMD)"
	$(FMT_CMD)
	@echo "Clippy: cargo clippy --all-targets --all-features $(CLIPPY_MODE) $(ARGS) $(CLIPPY_DENY)"
	cargo clippy --all-targets --all-features $(CLIPPY_MODE) $(ARGS) $(CLIPPY_DENY)

# Build documentation
doc:
	@echo "Building documentation..."
	cargo doc --open --all-features
