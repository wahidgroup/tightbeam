.PHONY: help help-ref version setup build clean test lint doc test-all

# Project metadata for help/version
PROJECT := tightbeam
VERSION := $(shell awk -F\" '/^\s*version\s*=\s*"/{print $$2; exit}' Cargo.toml 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "+dirty")

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
	@printf '    build           Build all projects (honors features)\n'
	@printf '    clean           Clean build artifacts\n'
	@printf '    test            Run all tests (honors features and no-default)\n'
	@printf '    test-all        Run tests with all feature combinations\n'
	@printf '    lint            Run linters (pass extra args via ARGS)\n'
	@printf '    doc             Build documentation (all features)\n\n'
	@printf 'OPTIONS / VARIABLES:\n'
	@printf '    features        Comma-separated Cargo feature list passed as --features\n'
	@printf '    no-default      If set (e.g., 1/true), passes --no-default-features to Cargo\n'
	@printf '    ARGS            Extra arguments for clippy (e.g., "--fix --allow-matrixd")\n\n'
	@printf 'ENVIRONMENT:\n'
	@printf '    CARGO_TERM_COLOR, RUSTFLAGS, RUSTC_WRAPPER (honored by Cargo/rustc)\n\n'
	@printf 'EXAMPLES:\n'
	@printf '    make build features="std,tcp,tokio"\n'
	@printf '    make test no-default=1 features="testing"\n'
	@printf '    make lint ARGS="--fix --allow-matrixd"\n\n'
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

# Build all projects
build:
	@echo "Building tightbeam..."
	cargo build --release $(if $(features),--features "$(features)")
	@echo "Generating feature test scripts..."
	mkdir -p built
	rustc scripts/generate_feature_tests.rs -o built/generate_feature_tests
	./built/generate_feature_tests --output-dir built

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean

# Run all tests
test: build
	@echo "Running tests..."
	cargo test $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

# Run tests with all feature combinations
test-all: build
	@echo "Running tests with all feature combinations..."
	./built/test_all_features.sh

# Run linters
lint:
	@echo "Running linters..."
	cargo clippy --all-targets --all-features $(ARGS) -- -D warnings
	cargo fmt --check

# Build documentation
doc:
	@echo "Building documentation..."
	cargo doc --open --all-features