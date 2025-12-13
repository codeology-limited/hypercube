.PHONY: all build test clean release install uninstall bump-patch bump-minor bump-major

# Install location
INSTALL_DIR := /usr/local/bin
BINARY := hypercube

# Default target - build debug and install
all: build install-debug

# Build debug version
build:
	cargo build

# Build release version
release: clean-binary
	cargo build --release
	@echo "Installing release version to $(INSTALL_DIR)/$(BINARY)..."
	@sudo cp target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY)
	@echo "Installed: $$($(INSTALL_DIR)/$(BINARY) --version)"

# Install debug version
install-debug: build
	@echo "Installing debug version to $(INSTALL_DIR)/$(BINARY)..."
	@sudo cp target/debug/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY)
	@echo "Installed: $$($(INSTALL_DIR)/$(BINARY) --version)"

# Remove installed binary
uninstall:
	@echo "Removing $(INSTALL_DIR)/$(BINARY)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY)

# Clean just the binary (not full clean)
clean-binary:
	@rm -f $(INSTALL_DIR)/$(BINARY) 2>/dev/null || true

# Run all tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Clean build artifacts
clean:
	cargo clean

# Check code without building
check:
	cargo check

# Run clippy lints
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Bump patch version (0.1.x) - auto-increments on release
bump-patch:
	@VERSION=$$(cat VERSION); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	MINOR=$$(echo $$VERSION | cut -d. -f2); \
	PATCH=$$(echo $$VERSION | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo $$NEW_VERSION > VERSION; \
	echo "Version bumped to $$NEW_VERSION"

# Bump minor version (0.x.0)
bump-minor:
	@VERSION=$$(cat VERSION); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	MINOR=$$(echo $$VERSION | cut -d. -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	echo $$NEW_VERSION > VERSION; \
	echo "Version bumped to $$NEW_VERSION"

# Bump major version (x.0.0)
bump-major:
	@VERSION=$$(cat VERSION); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	echo $$NEW_VERSION > VERSION; \
	echo "Version bumped to $$NEW_VERSION"

# Show current version
version:
	@echo "VERSION file: $$(cat VERSION)"
	@echo "BUILD_NUMBER: $$(cat BUILD_NUMBER)"
	@if [ -f $(INSTALL_DIR)/$(BINARY) ]; then \
		echo "Installed: $$($(INSTALL_DIR)/$(BINARY) --version)"; \
	else \
		echo "Not installed"; \
	fi
