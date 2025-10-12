.PHONY: help build clean test lint doc

# Default target
help:
	@echo "TightBeam Framework Commands:"
	@echo "  build    - Build all projects"
	@echo "  clean    - Clean build artifacts"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run linters (use ARGS=\"--fix --allow-staged\" for fixes)"
	@echo "  doc      - Build documentation"
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

# Build all projects
build:
	@echo "Building TightBeam..."
	cargo build --release $(if $(features),--features "$(features)")

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean

# Run all tests
test:
	@echo "Running tests..."
	cargo test $(if $(features),--features "$(features)") $(if $(no-default),--no-default-features)

# Run linters
lint:
	@echo "Running linters..."
	cargo clippy --all-targets --all-features $(ARGS) -- -D warnings
	cargo fmt --check

# Build documentation
doc:
	@echo "Building documentation..."
	cargo doc --open --all-features