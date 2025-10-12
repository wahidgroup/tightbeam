.PHONY: help setup build clean test lint doc test-all

# Default target
help:
	@echo "TightBeam Framework Commands:"
	@echo "  setup    - Setup the development environment"
	@echo "  build    - Build all projects"
	@echo "  clean    - Clean build artifacts"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run linters (use ARGS=\"--fix --allow-staged\" for fixes)"
	@echo "  doc      - Build documentation"
	@echo "  test-all - Run tests with all feature combinations"
	@echo ""
	@echo "Feature-specific builds:"
	@echo "  make build --features \"std,tcp,tokio\""
	@echo "  make build --features \"aes-gcm,sha3,secp256k1\""
	@echo "  make build --features \"zstd,compress\""
	@echo "  make build --features \"x509,signature\""
	@echo ""
	@echo "Testing with specific features:"
	@echo "  make test --features \"testing,std,tcp,tokio\""
	@echo "  make test --no-default-features --features \"testing\""

# Setup local development
setup:
	@echo "Setting up the development environment..."
	@echo "Installing development tools..."
	rustup component add rustfmt clippy

# Build all projects
build:
	@echo "Building TightBeam..."
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