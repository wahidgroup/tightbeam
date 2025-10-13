# Contributing to tightbeam

Thank you for your interest in contributing to tightbeam! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to a professional and respectful development environment. Contributors MUST:

- Be respectful and constructive in discussions
- Focus on technical merit and project goals
- Help maintain a welcoming environment for all contributors

## Getting Started

### Prerequisites

Contributors MUST have:

- Rust toolchain meeting or exceeding the workspace `rust-version` in Cargo.toml
- Git
- Make

### Development Setup

To prepare a development environment, you SHOULD:

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/tightbeam.git
   cd tightbeam
   ```
3. Set up the development environment:
   ```bash
   make setup
   ```
4. Run tests to verify everything works:
   ```bash
   make test
   ```

## Development Workflow

### Commands

The following commands MAY be used during development:

```bash
# Basic development
make help                              # Help
make build                             # Build all projects
make clean                             # Clean build artifacts  
make test                              # Run all tests
make lint                              # Run linters
make lint ARGS="--fix --allow-matrixd"  # Run linters with fixes
make doc                               # Build documentation

# Feature-specific builds
make build features="std,tcp,tokio"
make build features="aes-gcm,sha3,secp256k1"
make build features="zstd,compress"
make build features="x509,signature"

# Testing with specific features
make test features="testing,std,tcp,tokio" 
make test features="testing" no-default=1

# Development server (from project root)
make dev
```

### Code Style

Contributors MUST:

- Use hard tabs (this repository enforces tabs)
- Follow standard Rust formatting (`cargo fmt`)
- Use `make lint` and address all warnings before submitting
- Write comprehensive documentation for public APIs

Contributors SHOULD:

- Include examples in documentation where appropriate

### Commit Guidelines

Contributors SHOULD:

- Use clear, descriptive commit messages
- Keep commits focused on a single change
- Reference issues in commit messages when applicable
- Follow conventional commit format where possible:
  ```
  type(scope): description
  
  feat: add new compression algorithm
  fix: resolve race condition in transport layer
  docs: update ASN.1 specification examples
  test: add integration tests for V2 features
  ```

## Types of Contributions

### Bug Reports

When reporting bugs, you MUST include:

- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Rust version, features used)
- Minimal test case if possible

### Feature Requests

For new features, contributors MUST:

1. Check if a TIP (tightbeam improvement proposal) is needed
2. Discuss the feature in an issue first
3. Consider backwards compatibility
4. Provide use cases and rationale
5. Utilize RustCrypto crates for cryptographic implementations

### Documentation

Contributors MUST:

- Update relevant documentation for any changes
- Ensure examples compile and work correctly
- Update ASN.1 specifications for protocol changes

Contributors SHOULD:

- Consider adding TIPs for significant changes

### Security

For security-related contributions, contributors MUST:

- Follow responsible disclosure practices
- Consider cryptographic best practices
- Update security profiles if needed
- Ensure compliance with relevant standards

## tightbeam Improvement Proposals (TIPs)

For significant changes, contributors MUST follow the TIP process:

1. Read [TIP-1](tips/tip-0001.md) for guidelines
2. Draft your TIP in `tips/` directory
3. Submit as a pull request for discussion
4. Build consensus through community feedback

## License

By contributing, you agree that your contributions will be licensed under the same dual MIT/Apache-2.0 license as the project.