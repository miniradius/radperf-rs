# radperf-rs build helper.
#
# Run `make` (or `make help`) to list the targets, then `make <target>`.
# Binaries are written to $(DIST), which defaults to `dist/`.

define BANNER
                _                  __
  _ __ __ _  __| |_ __   ___ _ __ / _|      _ __ ___
 | '__/ _` |/ _` | '_ \ / _ \ '__| |_ _____| '__/ __|
 | | | (_| | (_| | |_) |  __/ |  |  _|_____| |  \__ \ 
 |_|  \__,_|\__,_| .__/ \___|_|  |_|       |_|  |___/
                 |_|
endef
export BANNER

CARGO          ?= cargo
RUSTUP         ?= rustup
DIST           ?= dist

UNAME_S        := $(shell uname -s)

# Rust target triples.
LINUX_ARM64    := aarch64-unknown-linux-gnu
LINUX_AMD64    := x86_64-unknown-linux-gnu
DARWIN_ARM64   := aarch64-apple-darwin

# Cross linker for the Linux x86_64 target (from the gcc-x86-64-linux-gnu
# package). Override with `make AMD64_LINKER=... linux-amd64`.
AMD64_LINKER   ?= x86_64-linux-gnu-gcc

BIN            := radperf

# How each target is produced, depending on the host:
#   * On Linux, darwin is cross-linked with zig (cargo-zigbuild) and the Linux
#     x86_64 target uses the gcc cross linker.
#   * On macOS, darwin is native (no zig) and the Linux targets are
#     cross-linked with zig.
ifeq ($(UNAME_S),Darwin)
  LINUX_ARM64_CMD  := $(CARGO) zigbuild
  LINUX_AMD64_CMD  := $(CARGO) zigbuild
  DARWIN_ARM64_CMD := $(CARGO) build
  AMD64_ENV        :=
else
  LINUX_ARM64_CMD  := $(CARGO) build
  LINUX_AMD64_CMD  := $(CARGO) build
  DARWIN_ARM64_CMD := $(CARGO) zigbuild
  AMD64_ENV        := CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$(AMD64_LINKER)
endif

# Bare `make` prints the help instead of building everything.
.DEFAULT_GOAL := help

.PHONY: help all linux-arm64 linux-amd64 darwin-arm64 \
        deps deps-rust deps-linux-amd64 deps-darwin \
        test clean

help: ## Show this help
	@printf '%s\n' "$$BANNER"
	@echo "radperf build targets (run 'make <target>'):"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'
	@echo
	@echo "Host: $(UNAME_S)   Variables: DIST=$(DIST)  AMD64_LINKER=$(AMD64_LINKER)"

# ---------------------------------------------------------------------------
# Builds
# ---------------------------------------------------------------------------

all: linux-arm64 linux-amd64 darwin-arm64 ## Build all three binaries

# Native on Linux; cross-linked with zig on macOS.
linux-arm64: ## Linux aarch64
	$(LINUX_ARM64_CMD) --release --target $(LINUX_ARM64)
	@mkdir -p $(DIST)
	cp target/$(LINUX_ARM64)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64
	@echo "wrote $(DIST)/$(BIN)-linux-arm64"

# Uses the gcc cross linker on Linux; cross-linked with zig on macOS.
linux-amd64: ## Linux x86_64
	$(AMD64_ENV) $(LINUX_AMD64_CMD) --release --target $(LINUX_AMD64)
	@mkdir -p $(DIST)
	cp target/$(LINUX_AMD64)/release/$(BIN) $(DIST)/$(BIN)-linux-amd64
	@echo "wrote $(DIST)/$(BIN)-linux-amd64"

# Native on macOS; cross-linked with zig on Linux.
darwin-arm64: ## macOS Apple Silicon (aarch64)
	$(DARWIN_ARM64_CMD) --release --target $(DARWIN_ARM64)
	@mkdir -p $(DIST)
	cp target/$(DARWIN_ARM64)/release/$(BIN) $(DIST)/$(BIN)-darwin-arm64
	@echo "wrote $(DIST)/$(BIN)-darwin-arm64"

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

deps: deps-rust deps-linux-amd64 deps-darwin ## Install Rust targets and cross tools

deps-rust: ## Add the Rust target triples
	$(RUSTUP) target add $(LINUX_ARM64) $(LINUX_AMD64) $(DARWIN_ARM64)

ifeq ($(UNAME_S),Darwin)
deps-linux-amd64: ## Tools for the Linux x86_64 target (macOS: zig)
	@command -v zig >/dev/null 2>&1 || echo "install zig (e.g. 'brew install zig') for Linux cross builds"
	@command -v cargo-zigbuild >/dev/null 2>&1 || echo "run 'cargo install cargo-zigbuild' for Linux cross builds"
deps-darwin: ## Tools for the darwin target (macOS: native toolchain)
	@echo "macOS: darwin-arm64 uses the native Apple toolchain, no extra tools needed"
else
deps-linux-amd64: ## Tools for the Linux x86_64 target (cross linker)
	sudo apt-get install -y gcc-x86-64-linux-gnu
deps-darwin: ## Tools for the darwin target (zig + cargo-zigbuild)
	sudo apt-get install -y zig
	$(CARGO) install cargo-zigbuild
endif

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

test: ## Run the test suite
	$(CARGO) test

clean: ## Remove target/ and dist/
	$(CARGO) clean
	rm -rf $(DIST)
