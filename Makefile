.PHONY: help help-ref version setup check build clean test lint doc test-all fuzz-build fuzz-test analyze-fuzz clean-fuzz release check-yanked

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
	@printf '    lint            Run linters (pass extra clippy args via ARGS)\n'
	@printf '    doc             Build documentation (all features)\n'
	@printf '    release         Release workflow (make release v0.7.0 [--dry-run] [--allow-staged] [--yank] [--derive])\n'
	@printf '    check-yanked    Check if current version has been yanked\n\n'
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
	@echo "Building AFL-instrumented fuzz targets..."
	@which cargo-afl >/dev/null 2>&1 || { \
		echo "Error: cargo-afl not found. Install with: cargo install cargo-afl"; \
		exit 1; \
	}
	@set -e; \
	for target in simple_workflow complex_workflow verification; do \
		echo "  - fuzz_$$target"; \
		RUSTFLAGS="--cfg fuzzing" cargo afl build --bin fuzz_$$target --features "std,testing-fuzz"; \
	done
	@echo "  - fuzz_chess"
	RUSTFLAGS="--cfg fuzzing" cargo afl build --bin fuzz_chess --features "std,testing-fuzz,testing-fdr,testing-csp"
	@echo ""
	@echo "Fuzz targets built successfully!"
	@echo ""
	@if [ -d tightbeam/fuzz ]; then \
		echo "Available fuzz targets in tightbeam/fuzz/:"; \
		ls -1 tightbeam/fuzz | sed 's/^/  - /'; \
	else \
		echo "No fuzz directory found at tightbeam/fuzz."; \
	fi
	@echo ""

# Run AFL fuzz testing for a short time (60 seconds for CI/smoke testing)
# Options:
#   skip-missing-crashes=1  - Skip crash reporting config check (AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1)
#   skip-cpu-freq=1         - Skip CPU frequency scaling check (AFL_SKIP_CPUFREQ=1)
fuzz-test: fuzz-build
	@echo "Cleaning previous fuzz output..."
	@rm -rf built/fuzz/out
	@echo "Running AFL fuzz testing for 60 seconds..."
	@mkdir -p built/fuzz/in built/fuzz/out
	@echo "seed" > built/fuzz/in/seed.txt
	@echo ""
	@echo "Locating fuzz target binary..."
	@FUZZ_TARGET=$$(ls target/debug/fuzz_* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -z "$$FUZZ_TARGET" ]; then \
		echo "Error: Could not find any fuzz binary in target/debug/"; \
		echo "Run 'make fuzz-build' first"; \
		exit 1; \
	fi; \
	echo "Found: $$FUZZ_TARGET"; \
	echo ""; \
	AFL_ENV=""; \
	if [ "$(skip-missing-crashes)" = "1" ]; then \
		AFL_ENV="$$AFL_ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"; \
		echo "Note: Skipping crash reporting config check"; \
	fi; \
	if [ "$(skip-cpu-freq)" = "1" ]; then \
		AFL_ENV="$$AFL_ENV AFL_SKIP_CPUFREQ=1"; \
		echo "Note: Skipping CPU frequency scaling check"; \
	fi; \
	echo "Starting fuzzer (60 second timeout)..."; \
	echo ""; \
	eval "$$AFL_ENV timeout 60 cargo afl fuzz -i built/fuzz/in -o built/fuzz/out \"$$FUZZ_TARGET\" > /dev/null 2>&1" || true; \
	echo ""; \
	echo "Fuzz testing completed!"; \
	if [ -d "built/fuzz/out/default" ]; then \
		echo "Results saved to built/fuzz/out/"; \
		CRASHES=$$(ls -1 built/fuzz/out/default/crashes/ 2>/dev/null | grep -v README | wc -l); \
		HANGS=$$(ls -1 built/fuzz/out/default/hangs/ 2>/dev/null | grep -v README | wc -l); \
		QUEUE=$$(ls -1 built/fuzz/out/default/queue/ 2>/dev/null | grep -v '^\.synced$$' | wc -l); \
		echo "  Test cases generated: $$QUEUE"; \
		echo "  Crashes found: $$CRASHES"; \
		echo "  Hangs found: $$HANGS"; \
		echo ""; \
		if [ -f "built/fuzz/out/default/fuzzer_stats" ]; then \
			echo "Fuzzing Statistics:"; \
			EXECS=$$(grep "^execs_done" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			EXECS_SEC=$$(grep "^execs_per_sec" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			STABILITY=$$(grep "^stability" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			BITMAP=$$(grep "^bitmap_cvg" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			EDGES=$$(grep "^edges_found" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			TOTAL_EDGES=$$(grep "^total_edges" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			CYCLES=$$(grep "^cycles_done" built/fuzz/out/default/fuzzer_stats | awk '{print $$3}'); \
			echo "  Executions: $$EXECS ($$EXECS_SEC/sec)"; \
			echo "  Stability: $$STABILITY"; \
			echo "  Coverage: $$BITMAP ($$EDGES/$$TOTAL_EDGES edges)"; \
			echo "  Cycles: $$CYCLES"; \
		fi; \
		echo ""; \
		if [ "$$CRASHES" -gt 0 ]; then \
			echo "[!] Crashes detected! Review them at:"; \
			echo "    built/fuzz/out/default/crashes/"; \
			echo ""; \
		fi; \
		if [ "$$HANGS" -gt 0 ]; then \
			echo "[!] Hangs detected! Review them at:"; \
			echo "    built/fuzz/out/default/hangs/"; \
			echo ""; \
		fi; \
	else \
		echo "No output generated - fuzzer may have exited early"; \
	fi; \
	echo "To run longer fuzzing sessions manually:"; \
	echo "  cargo afl fuzz -i built/fuzz/in -o built/fuzz/out $$FUZZ_TARGET"; \
	echo ""; \
	echo "For production fuzzing, configure system properly with: cargo afl system-config"; \
	echo ""

# Analyze a specific fuzz crash or hang
# Usage: make analyze-fuzz file=built/fuzz/out/default/crashes/id:000000...
analyze-fuzz:
	@if [ -z "$(file)" ]; then \
		echo "Error: Please specify a file to analyze"; \
		echo "Usage: make analyze-fuzz file=built/fuzz/out/default/crashes/id:000000..."; \
		echo ""; \
		echo "Available crashes:"; \
		ls -1 built/fuzz/out/default/crashes/ 2>/dev/null | grep -v README || echo "  (none)"; \
		echo ""; \
		echo "Available hangs:"; \
		ls -1 built/fuzz/out/default/hangs/ 2>/dev/null | grep -v README || echo "  (none)"; \
		exit 1; \
	fi; \
	echo "Analyzing: $(file)"; \
	echo ""; \
	FUZZ_TARGET=$$(ls target/debug/deps/fuzzing-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -z "$$FUZZ_TARGET" ]; then \
		echo "Error: Fuzz target not built. Run 'make fuzz-build' first."; \
		exit 1; \
	fi; \
	echo "Running with input from $(file)..."; \
	echo ""; \
	$$FUZZ_TARGET < "$(file)" || echo "Exit code: $$?"

# Clean fuzz artifacts
clean-fuzz:
	@echo "Cleaning fuzz artifacts..."
	rm -rf built/fuzz/out
	@echo "Fuzz output directory cleaned."

# Collect extra args passed after the target (e.g., `make lint -- --fix ...`)
# Strip the target name and the bare `--` separator
LINT_ARGS := $(filter-out lint,$(MAKECMDGOALS))
LINT_ARGS := $(filter-out --,$(LINT_ARGS))
# Back-compat: also honor ARGS=... if provided
ifneq ($(strip $(ARGS)),)
LINT_ARGS += $(ARGS)
endif

# Decide fmt/clippy behavior based on presence of --fix
ifeq (,$(findstring --fix,$(LINT_ARGS)))
FMT_CMD := cargo fmt --all --check
CLIPPY_EXTRA := -- -D warnings
LINT_MODE := check
else
FMT_CMD := cargo fmt --all
CLIPPY_EXTRA :=
LINT_MODE := fix
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

# Release workflow
release:
	@./scripts/release.sh "$(RELEASE_VERSION)" $(RELEASE_FLAGS)

# Run linters
lint:
	@echo "Running linters (mode: $(LINT_MODE))..."
	@echo "Formatting: $(FMT_CMD)"
	$(FMT_CMD)
	@echo "Clippy: cargo clippy --all-targets --all-features $(LINT_ARGS) $(CLIPPY_EXTRA)"
	cargo clippy --all-targets --all-features $(LINT_ARGS) $(CLIPPY_EXTRA)

# Build documentation
doc:
	@echo "Building documentation..."
	cargo doc --open --all-features
