REGEXPED := ../../../../regexped

# The SAME ten patterns and the same set, built two ways. `make` drives the raw
# WASM ABI from a native host; `make component-run` drives the Component Model
# interface from the same kind of host. Same inputs, same output — the contrast
# is entirely in main.rs versus main_component.rs.
COMP_CFG   := regexped-component.yaml
COMP_DIR   := component
COMP_WASM  := $(COMP_DIR)/secrets.wasm
COMP_WIT   := $(COMP_DIR)/secrets.wit

INPUTS := "nothing sensitive here" \
          "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" \
          "Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab" \
          "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
          "key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab stripe=sk_live_AbCdEfGhIjKlMnOpQrStUvWx"

.PHONY: all compile build run clean component component-build component-run compare

all: run

# --- the MODULE route ---------------------------------------------------------

# Compile the 10-pattern set to a standalone WASM module.
# No merge step: the set WASM is self-contained (exports its own memory).
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
compile: regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Build the Rust host binary (native, not WASM). --bin, because the component
# host in this directory cannot compile until the component exists.
build:
	cargo build --release --bin secret-scanner

# Run: compile patterns, build host, then scan test inputs.
run: compile build
	@echo "=== module route: a native host over the raw WASM ABI ==="
	@$(MAKE) --no-print-directory drive BIN=secret-scanner

# --- the COMPONENT route ------------------------------------------------------

# Step 1 - compile the same set into a component, plus the sibling .wit the host
# binds against. The .wit is a prerequisite of the host binary, not just an
# artefact: bindgen! reads it at COMPILE time.
$(COMP_WASM) $(COMP_WIT): $(COMP_CFG) $(REGEXPED)
	$(REGEXPED) compile --config=$(COMP_CFG)

component: $(COMP_WASM)

# Step 2 - build the component host. No stub is generated or used: a stub is for
# a guest compiled to WASM, and this is a native binary.
component-build: $(COMP_WIT)
	cargo build --release --bin secret-scanner-component

component-run: component component-build
	@echo "=== component route: the same host over the WIT interface ==="
	@$(MAKE) --no-print-directory drive BIN=secret-scanner-component

# Both routes over the same inputs, so a difference in any answer shows up as a
# diff rather than as two outputs to read side by side.
compare: compile build component component-build
	@$(MAKE) --no-print-directory -s drive BIN=secret-scanner > .out-module
	@$(MAKE) --no-print-directory -s drive BIN=secret-scanner-component > .out-component
	@diff .out-module .out-component \
	  && echo "IDENTICAL: both routes report the same matches"
	@rm -f .out-module .out-component

# drive runs one binary over every input. Shared so the two routes cannot drift
# apart in what they are asked.
drive:
	@for i in $(INPUTS); do \
	    echo ""; echo "--- input: $$i"; \
	    ./target/release/$(BIN) "$$i"; \
	done

clean:
	cargo clean
	rm -f secrets.wasm .out-module .out-component
	rm -rf $(COMP_DIR)
