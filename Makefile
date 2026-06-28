# Makefile for NanoKVM Project

# Configuration
IMAGE_NAME := nanokvm-builder
UID := $(shell id -u)
GID := $(shell id -g)
PWD := $(shell pwd)

# Docker run common parameters
DOCKER_RUN_BASE := docker run -e UID=$(UID) -e GID=$(GID) -v $(PWD):/home/build/NanoKVM --rm
RUST_TARGET ?=
RUST_BUILD_ARGS := --manifest-path server-rust/Cargo.toml --release
ifneq ($(strip $(RUST_TARGET)),)
RUST_BUILD_ARGS += --target $(RUST_TARGET)
endif

# Build commands
GO_BUILD_CMD := cd /home/build/NanoKVM/server && go mod tidy && CGO_ENABLED=1 GOOS=linux GOARCH=riscv64 CC=riscv64-unknown-linux-musl-gcc CGO_CFLAGS="-mcpu=c906fdv -march=rv64imafdcv0p7xthead -mcmodel=medany -mabi=lp64d" go build
SUPPORT_BUILD_CMD := . ./home/build/MaixCDK/bin/activate && cd /home/build/NanoKVM/support/sg2002 && ./build kvm_system && ./build kvm_system add_to_kvmapp

SYSTEM_UPDATE_VERSION ?= 0.0.0-dev
SYSTEM_UPDATE_TARGET ?= sg2002-licheervnano-sd
SYSTEM_UPDATE_PAYLOAD ?= build/system-update-payload
SYSTEM_UPDATE_OUT ?= build/system-updates
SYSTEM_UPDATE_TAG ?= hardened-system-$(SYSTEM_UPDATE_VERSION)
VENDOR_SDK_OUTPUT ?= build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd
VENDOR_SDK_UPGRADE ?= $(VENDOR_SDK_OUTPUT)/upgrade.zip
VENDOR_SDK_INSPECTION ?= build/vendor-upgrade-inspection.json

.PHONY: help check-root builder-image rebuild-image check-image shell app rust-app web-app rust-kvmapp sd-image vendor-sdk vendor-sdk-stock vendor-sdk-inspect system-update-bundle system-update-metadata support all clean

# Default target
all: app support

# Help target
help:
	@echo "NanoKVM Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  help          - Show this help message"
	@echo "  check-image   - Check builder Docker image and show versions"
	@echo "  builder-image - Build Docker image if not exists"
	@echo "  rebuild-image - Force rebuild Docker image"
	@echo "  shell         - Enter interactive builder environment"
	@echo "  app           - Build Go application server"
	@echo "  rust-app      - Build Rust application server skeleton"
	@echo "  web-app       - Build frontend into web/dist"
	@echo "  rust-kvmapp   - Package Rust backend into build/kvmapp-rust"
	@echo "  sd-image      - Build patched Hardened NanoKVM SD image from NANOKVM_BASE_IMAGE"
	@echo "  vendor-sdk    - Bootstrap the pinned Sipeed LicheeRV Nano vendor SDK checkout"
	@echo "  vendor-sdk-stock - Build the stock SDK image with a Buildroot-safe PATH"
	@echo "  vendor-sdk-inspect - Validate vendor upgrade.zip and write JSON inspection"
	@echo "  system-update-bundle   - Package a staged system-update payload"
	@echo "  system-update-metadata - Generate GitHub latest JSON for the system bundle"
	@echo "  support       - Build hardware support libraries"
	@echo "  all           - Build both app and support (default)"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Docker must be installed and running"
	@echo "  - Must not run as root user"

# Security check - prevent running as root
check-root:
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "Can't run as root"; \
		exit 1; \
	fi

# Check if builder image exists and show versions
check-image: check-root
	@echo "Checking builder image..."
	@echo "Golang version: " && \
		docker run --rm -i $(IMAGE_NAME) go version && \
		echo "" && \
		echo "Host-tools version:" && \
		docker run --rm -i $(IMAGE_NAME) riscv64-unknown-linux-musl-gcc -v && \
		echo ""

# Build Docker image if it doesn't exist
builder-image: check-root
	@if ! docker image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Building Docker image..."; \
		docker build -t $(IMAGE_NAME) -f docker/Dockerfile ./; \
	else \
		echo "Docker image $(IMAGE_NAME) already exists."; \
	fi

# Force rebuild Docker image
rebuild-image: check-root
	@echo "Force rebuilding Docker image..."
	@docker build --no-cache -t $(IMAGE_NAME) -f docker/Dockerfile ./

# Enter interactive shell (equivalent to build.sh with no arguments)
shell: check-root builder-image
	@echo "Switching into builder..."
	@$(DOCKER_RUN_BASE) -it $(IMAGE_NAME) /bin/bash -c ". ./home/build/MaixCDK/bin/activate && cd /home/build/NanoKVM ; exec bash"

# Build Go application
app: check-root builder-image
	@echo "Building app..."
	@$(DOCKER_RUN_BASE) -it $(IMAGE_NAME) /bin/bash -c '$(GO_BUILD_CMD)'

# Build Rust application skeleton locally
rust-app:
	@echo "Building Rust app skeleton..."
	@cargo build $(RUST_BUILD_ARGS)

# Build frontend assets
web-app:
	@echo "Building frontend..."
	@cd web && corepack pnpm install --frozen-lockfile && corepack pnpm build

# Package Rust backend into the kvmapp deployment layout
rust-kvmapp: rust-app
	@echo "Packaging Rust kvmapp..."
	@RUST_TARGET="$(RUST_TARGET)" scripts/package-rust-kvmapp.sh

# Full boot/rootfs builds still require the external LicheeRV Nano SDK flow.
# This target patches a trusted NanoKVM base image with the current Rust kvmapp.
sd-image:
	@scripts/build-rust-sd-image.sh

# Bootstrap the external Sipeed SDK checkout used for reproducible stock image
# work. The SDK itself stays under build/vendor and is not committed.
vendor-sdk:
	@scripts/bootstrap-vendor-sdk.sh

# Build the unmodified stock SDK image. This intentionally sanitizes PATH
# because Buildroot rejects WSL/Windows PATH entries containing spaces.
vendor-sdk-stock:
	@scripts/build-vendor-sdk-stock.sh

# Validate the vendor OTA zip without extracting or flashing it. The JSON output
# is a reproducible input for deciding future system-update bundle contents.
vendor-sdk-inspect:
	@scripts/inspect-vendor-upgrade.py "$(VENDOR_SDK_UPGRADE)" "$(VENDOR_SDK_INSPECTION)"

# Package a staged system-update payload.
# Expected payload layout:
#   $(SYSTEM_UPDATE_PAYLOAD)/boot/<file>    -> /boot/<file>
#   $(SYSTEM_UPDATE_PAYLOAD)/rootfs/<path>  -> /<path>
system-update-bundle:
	@scripts/create-system-update-bundle.sh "$(SYSTEM_UPDATE_VERSION)" "$(SYSTEM_UPDATE_TARGET)" "$(SYSTEM_UPDATE_PAYLOAD)" "$(SYSTEM_UPDATE_OUT)"

system-update-metadata:
	@scripts/create-system-update-metadata.sh "$(SYSTEM_UPDATE_VERSION)" "$(SYSTEM_UPDATE_TAG)" "$(SYSTEM_UPDATE_OUT)/hardened-nanokvm-system-$(SYSTEM_UPDATE_VERSION).tar.gz" "$(SYSTEM_UPDATE_OUT)/system-latest.json"

# Build hardware support libraries
support: check-root builder-image
	@echo "Building support..."
	@$(DOCKER_RUN_BASE) -it $(IMAGE_NAME) /bin/bash -c '$(SUPPORT_BUILD_CMD)'

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@if [ -f server/NanoKVM-Server ]; then \
		rm -f server/NanoKVM-Server; \
		echo "Removed server/NanoKVM-Server"; \
	fi
	@if [ -d support/sg2002/build ]; then \
		rm -rf support/sg2002/build; \
		echo "Removed support/sg2002/build"; \
	fi
	@if [ -d build/kvmapp-rust ]; then \
		rm -rf build/kvmapp-rust; \
		echo "Removed build/kvmapp-rust"; \
	fi
	@echo "Clean completed."
