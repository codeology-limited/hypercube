.PHONY: all build test clean release install uninstall bump-patch bump-minor bump-major hypercube codebreaker

INSTALL_DIR := /usr/local/bin
HYPERCUBE_BIN := hypercube
CODEBREAKER_BIN := codebreaker
VERSION_FILE := hypercube/VERSION
BUILD_FILE := hypercube/BUILD_NUMBER

all: build install-debug

build:
	cargo build --workspace

hypercube:
	cargo build --package hypercube

codebreaker:
	cargo build --package codebreaker

release: clean-binary
	cargo build --workspace --release
	@echo "Installing release version to $(INSTALL_DIR)..."
	@sudo cp target/release/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(HYPERCUBE_BIN)
	@sudo cp target/release/$(CODEBREAKER_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN)
	@sudo chmod +x $(INSTALL_DIR)/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN)
	@echo "Installed: $$($(INSTALL_DIR)/$(HYPERCUBE_BIN) --version)"

install-debug: build
	@echo "Installing debug versions to $(INSTALL_DIR)..."
	@sudo cp target/debug/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(HYPERCUBE_BIN)
	@sudo cp target/debug/$(CODEBREAKER_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN)
	@sudo chmod +x $(INSTALL_DIR)/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN)
	@echo "Installed Hypercube: $$($(INSTALL_DIR)/$(HYPERCUBE_BIN) --version)"

uninstall:
	@echo "Removing binaries from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN)

clean-binary:
	@rm -f $(INSTALL_DIR)/$(HYPERCUBE_BIN) $(INSTALL_DIR)/$(CODEBREAKER_BIN) 2>/dev/null || true

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
	@VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	MINOR=$$(echo $$VERSION | cut -d. -f2); \
	PATCH=$$(echo $$VERSION | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	echo "Version bumped to $$NEW_VERSION"

# Bump minor version (0.x.0)
bump-minor:
	@VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	MINOR=$$(echo $$VERSION | cut -d. -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	echo "Version bumped to $$NEW_VERSION"

# Bump major version (x.0.0)
bump-major:
	@VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	echo "Version bumped to $$NEW_VERSION"

# Show current version
version:
	@echo "Hypercube VERSION: $$(cat $(VERSION_FILE))"
	@echo "Hypercube BUILD_NUMBER: $$(cat $(BUILD_FILE))"
	@if [ -f $(INSTALL_DIR)/$(HYPERCUBE_BIN) ]; then \
		echo "Installed Hypercube: $$($(INSTALL_DIR)/$(HYPERCUBE_BIN) --version)"; \
	else \
		echo "Hypercube not installed"; \
	fi
	@if [ -f $(INSTALL_DIR)/$(CODEBREAKER_BIN) ]; then \
		echo "Installed Codebreaker: $$($(INSTALL_DIR)/$(CODEBREAKER_BIN) --version)"; \
	else \
		echo "Codebreaker not installed"; \
	fi
