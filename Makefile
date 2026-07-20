SHELL := /bin/bash

PROJECT_NAME := $(shell sed -n 's/^[[:space:]]*name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)
PROJECT_VERSION := $(shell sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)
ifeq ($(PROJECT_NAME),)
    $(error Error: Cargo.toml not found or invalid)
endif

TOP_DIR := $(CURDIR)
CARGO := cargo
PREFIX ?= $(HOME)/.local
# Args passed to the binary by `make run`, e.g. `make run ARGS="facts"`.
ARGS ?= install-preview

$(info ------------------------------------------)
$(info Project: $(PROJECT_NAME) v$(PROJECT_VERSION))
$(info ------------------------------------------)

.PHONY: build b compile c run r test t check check-all test-all clippy rustdoc fmt fmt-check clean verify install help h

build:
	@$(CARGO) build

b: build

compile:
	@$(CARGO) clean
	@$(MAKE) build

c: compile

run:
	@$(CARGO) run --bin $(PROJECT_NAME) -- $(ARGS)

r: run

test:
	@$(CARGO) test --all-targets

t: test

check:
	@$(CARGO) check --all-targets

check-all:
	@$(CARGO) check --all-targets --all-features

fmt:
	@$(CARGO) fmt --all

fmt-check:
	@$(CARGO) fmt --all -- --check

clippy:
	@$(CARGO) clippy --all-targets --all-features -- -D warnings

rustdoc:
	@RUSTDOCFLAGS="-Dwarnings" $(CARGO) doc --all-features --no-deps

test-all:
	@$(CARGO) test --all-targets --all-features

clean:
	@$(CARGO) clean

verify: fmt-check check test clippy

# Build a release binary and drop it on PATH (matches the manual dev workflow).
install:
	@$(CARGO) build --release
	@install -Dm755 target/release/$(PROJECT_NAME) $(PREFIX)/bin/$(PROJECT_NAME)
	@echo "installed $(PROJECT_NAME) -> $(PREFIX)/bin/$(PROJECT_NAME)"

help:
	@echo
	@echo "Usage: make [target]"
	@echo
	@echo "Available targets:"
	@echo "  build        Build the binary (debug)"
	@echo "  compile      Clean and rebuild"
	@echo "  run          Run the binary (ARGS=\"$(ARGS)\" by default)"
	@echo "  test         Run all tests"
	@echo "  check        Run cargo check on all targets"
	@echo "  check-all    Run cargo check on all targets/all features"
	@echo "  test-all     Run cargo test on all targets/all features"
	@echo "  clippy       Run clippy with warnings denied"
	@echo "  rustdoc      Build docs with warnings denied"
	@echo "  fmt          Format the workspace"
	@echo "  fmt-check    Check formatting"
	@echo "  clean        Remove Cargo build artifacts"
	@echo "  verify       Run the local gate (fmt-check, check, test, clippy)"
	@echo "  install      Build release + install to \$$PREFIX/bin ($(PREFIX)/bin)"
	@echo

h: help
