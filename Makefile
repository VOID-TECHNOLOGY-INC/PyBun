# PyBun Development Makefile
# Alternative to justfile for systems without just installed
# Usage: make <target>

.PHONY: all build build-release test test-verbose lint fmt fmt-check check \
        run help example docs docs-build clean rebuild ci release info \
        watch watch-test deps-update deps-outdated audit

# Default target
all: check

# =============================================================================
# Development Commands
# =============================================================================

# Build the project in debug mode
build:
	cargo build

# Build the project in release mode
build-release:
	cargo build --release

# Run all tests
test:
	cargo test

# Run tests with verbose output
test-verbose:
	cargo test -- --nocapture

# Run the linter (clippy)
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt -- --check

# Run all checks (fmt, lint, test)
check: fmt-check lint test

# =============================================================================
# Run Commands
# =============================================================================

# Run pybun with --help
help:
	cargo run -- --help

# Run example script
example:
	cargo run -- run examples/hello.py

# =============================================================================
# Documentation
# =============================================================================

# Generate and open documentation
docs:
	cargo doc --open

# Generate documentation without opening
docs-build:
	cargo doc

# =============================================================================
# Clean Up
# =============================================================================

# Clean build artifacts
clean:
	cargo clean

# Clean and rebuild
rebuild: clean build

# =============================================================================
# CI / Release Commands
# =============================================================================

# Run CI checks (what CI runs)
ci: fmt-check lint test

# Build release binaries for current platform
release: build-release
	@echo "Release binary at: target/release/pybun"

# Show project info
info:
	@echo "PyBun - Python Bundle Tool"
	@echo "=========================="
	@cargo --version
	@rustc --version
	@echo ""
	@echo "Project:"
	@cat Cargo.toml | grep -E "^(name|version|edition)" | head -3

# =============================================================================
# Development Helpers
# =============================================================================

# Watch for changes and rebuild (requires cargo-watch)
watch:
	cargo watch -x build

# Watch for changes and run tests (requires cargo-watch)
watch-test:
	cargo watch -x test

# Update dependencies
deps-update:
	cargo update

# Check for outdated dependencies (requires cargo-outdated)
deps-outdated:
	cargo outdated || echo "Note: Install cargo-outdated with 'cargo install cargo-outdated'"

# Security audit (requires cargo-audit)
audit:
	cargo audit || echo "Note: Install cargo-audit with 'cargo install cargo-audit'"

