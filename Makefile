.PHONY: all help help-body help-ref version setup check build clean test lint doc-lint spellcheck doc test-all fuzz-build fuzz-test analyze-fuzz clean-fuzz release release-derive check-yanked audit ci

.NOTPARALLEL: ci

.DEFAULT_GOAL := help

# Project metadata for help/version
PROJECT := tightbeam
VERSION := $(shell awk -F\" '/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/{print $$2; exit}' Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

# Cargo feature passthroughs (e.g., `make test features="testing"`).
CARGO_FLAGS := $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

ifneq ($(filter 1,$(fix)),)
LINT_MODE := fix
else
LINT_MODE := check
endif

AUDIT_MODE := $(LINT_MODE)

ifneq ($(filter 1,$(debug)),)
export RUST_LOG = debug
endif

RELEASE_VERSION := $(version)

define PRINT_PAGER
@{ $(1); } | less -FRX
endef

help:
	$(call PRINT_PAGER,$(MAKE) help-body)

help-body:
	@printf 'USAGE:\n'
	@printf '    make <target> [fix=1] [debug=1] [features="<comma-separated>"] [no-default=1]\n'
	@printf '                  [version=vX.Y.Z] [dry-run=1] [allow-staged=1] [yank=1]\n'
	@printf '                  [ARGS="<clippy-args>"]\n\n'
	@printf 'DESCRIPTION:\n'
	@printf '    Build, lint, test, and document the %s workspace following POSIX/GNU CLI conventions.\n\n' '$(PROJECT)'
	@printf 'TARGETS:\n'
	@printf '    all             Setup then build\n'
	@printf '    help            Show this help and exit\n'
	@printf '    help-ref        Show reference documentation links\n'
	@printf '    version         Show project version information\n'
	@printf '    setup           Setup the development environment (idempotent)\n'
	@printf '    check           Run code check (honors cargo features)\n'
	@printf '    build           Build all projects (honors cargo features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run all tests (honors cargo features and no-default)\n'
	@printf '    test-all        Run tests with all feature combinations\n'
	@printf '    fuzz-build      Build AFL-instrumented fuzz targets (requires cargo-afl)\n'
	@printf '    fuzz-test       Build and run AFL fuzz testing for 60 seconds\n'
	@printf '    analyze-fuzz    Analyze a specific crash/hang file (requires file=...)\n'
	@printf '    clean-fuzz      Remove fuzz output artifacts\n'
	@printf '    lint            Lint + spellcheck + rustdoc (fix=1 to auto-fix; extra clippy args via ARGS)\n'
	@printf '    spellcheck      Spellcheck the repository with typos\n'
	@printf '    audit           Run security audit (RustSec cargo-audit; fix=1 reserved)\n'
	@printf '    ci              Full pipeline: lint + build + test-all\n'
	@printf '    doc             Build documentation (all features; -D warnings)\n'
	@printf '    release         Release workflow (see OPTIONS)\n'
	@printf '    release-derive  Derive-only release: tag tightbeam-derive (see OPTIONS)\n'
	@printf '    check-yanked    Check if current version has been yanked (derive=1 for derive)\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    fix             If set (e.g., fix=1), apply fmt + clippy --fix; rustdoc still denies warnings\n'
	@printf '    debug           If set (e.g., debug=1), export RUST_LOG=debug\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1), passes --no-default-features to Cargo\n'
	@printf '    ARGS            Extra arguments for clippy (e.g., "--no-deps")\n'
	@printf '    version         Release version (e.g., version=v0.9.1)\n'
	@printf '    dry-run         If set (e.g., dry-run=1), preview release without changes\n'
	@printf '    allow-staged    If set (e.g., allow-staged=1), include staged files in release\n'
	@printf '    yank            If set (e.g., yank=1), yank a published release instead\n'
	@printf '    derive          If set (e.g., derive=1), check-yanked targets tightbeam-derive\n'
	@printf 'EXAMPLES:\n'
	@printf '    make build features="std,tcp,tokio"\n'
	@printf '    make test no-default=1 features="testing"\n'
	@printf '    make lint fix=1\n'
	@printf '    make release version=v0.9.1\n'
	@printf '    make release version=v0.9.1 dry-run=1\n'
	@printf '    make release-derive version=v0.1.8\n\n'
	@printf 'EXIT STATUS:\n'
	@printf '    0    Success\n'
	@printf '    >0   Error occurred\n\n'

help-ref:
	@printf 'REFERENCES:\n'
	@printf '    GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html\n'
	@printf '    POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html\n'
	@printf '    GNU Make Goals: https://www.gnu.org/software/make/manual/html_node/Goals.html\n\n'

version:
	@v='$(VERSION)'; c='$(GIT_COMMIT)'; d='$(GIT_DIRTY)'; [ -n "$$v" ] || v=unknown; \
	printf '%s %s (%s%s)\n' '$(PROJECT)' "$$v" "$$c" "$$d"

setup:
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

all: setup build
	@echo "Build complete."

check: setup
	@echo "Checking $(PROJECT)..."
	cargo check $(CARGO_FLAGS)

build: setup
	@echo "Building $(PROJECT)..."
	cargo build --release $(CARGO_FLAGS)

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf built target .make

test: setup
	@echo "Running tests..."
	cargo test $(CARGO_FLAGS)

test-all: setup
	@echo "Running tests with all feature combinations..."
	./scripts/test_features.sh

fuzz-build: setup
	@./scripts/fuzz-build.sh

# Options:
#   skip-missing-crashes=1  - Skip crash reporting config check
#   skip-cpu-freq=1         - Skip CPU frequency scaling check
fuzz-test: fuzz-build
	@./scripts/fuzz-test.sh \
		$(if $(filter 1,$(skip-missing-crashes)),--skip-missing-crashes) \
		$(if $(filter 1,$(skip-cpu-freq)),--skip-cpu-freq)

# Usage: make analyze-fuzz file=built/fuzz/out/default/crashes/id:000000...
analyze-fuzz:
	@./scripts/fuzz-analyze.sh "$(file)"

clean-fuzz:
	@echo "Cleaning fuzz artifacts..."
	rm -rf built/fuzz/out
	@echo "Fuzz output directory cleaned."

lint: setup
	@echo "Running linters (mode: $(LINT_MODE))..."
ifeq ($(LINT_MODE),fix)
	cargo fmt --all
	cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features $(ARGS)
else
	cargo fmt --all --check
	cargo clippy --all-targets --all-features $(ARGS) -- -D warnings
endif
	@$(MAKE) doc-lint
	@$(MAKE) spellcheck

# Rustdoc has no cargo --fix path for intra-doc / private-link warnings.
# Both lint and doc deny them so CI and local builds fail closed the same way.
doc-lint: setup
	@echo "Checking rustdoc (RUSTDOCFLAGS=-D warnings)..."
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

spellcheck: setup
	@echo "Checking spelling..."
	typos

doc: doc-lint
	@echo "Documentation build complete."

audit: setup
	@chmod +x scripts/audit.sh
	@AUDIT_MODE=$(AUDIT_MODE) ./scripts/audit.sh

ci:
	$(MAKE) lint
	$(MAKE) build
	$(MAKE) test-all

release: setup
	@chmod +x scripts/release.sh
	@DRY_RUN="$(if $(filter 1,$(dry-run)),1,)" \
		ALLOW_STAGED="$(if $(filter 1,$(allow-staged)),1,)" \
		YANK="$(if $(filter 1,$(yank)),1,)" \
		./scripts/release.sh "$(RELEASE_VERSION)"

release-derive: setup
	@chmod +x scripts/release-derive.sh
	@DRY_RUN="$(if $(filter 1,$(dry-run)),1,)" \
		YANK="$(if $(filter 1,$(yank)),1,)" \
		./scripts/release-derive.sh "$(RELEASE_VERSION)"

check-yanked:
	@./scripts/check-yanked.sh $(if $(filter 1,$(derive)),--derive)
