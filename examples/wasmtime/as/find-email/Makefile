# find-email: find email addresses and their named groups (TDFA)
#
# regexped must be built first: run `make` in the repo root.
#
# This Makefile installs NOTHING. AssemblyScript and its WASI shim come from
# `npm install` in this directory, and wasm-merge and wasmtime must be on PATH —
# README.md says how to install each. `make build` stops with a message naming
# the missing one rather than fetching it.
#
#   make         build final.wasm
#   make run     build if needed, then run it with wasmtime
REGEXPED   := ../../../../regexped
# The compiler `npm install` puts in node_modules; override with ASC=/path/to/asc.
ASC        ?= node_modules/.bin/asc
ASC_FLAGS  := --config asconfig.json
# asconfig.json extends this file, so the shim must be installed HERE — a
# global AssemblyScript install does not provide it.
WASI_SHIM  := node_modules/@assemblyscript/wasi-shim/asconfig.json

MAIN_WASM  := main.wasm
REGEX_WASM := email.wasm
FINAL_WASM := final.wasm
STUB       := stub.ts

.PHONY: all generate build compile merge run clean check-tools

all: merge

# Step 1 – generate AssemblyScript stub from config
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
$(STUB): regexped.yaml $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 2 – compile AssemblyScript source to WASM
check-tools:
	@test -x "$(ASC)" || { echo "error: AssemblyScript compiler not found at $(ASC). Run 'npm install' in this directory (see README.md), or set ASC=/path/to/asc" >&2; exit 1; }
	@test -f "$(WASI_SHIM)" || { echo "error: @assemblyscript/wasi-shim not found in node_modules. Run 'npm install' in this directory (see README.md)" >&2; exit 1; }

$(MAIN_WASM): index.ts $(STUB) asconfig.json | check-tools
	$(ASC) index.ts $(ASC_FLAGS) -o $@

build: $(MAIN_WASM)

# Step 3 – compile the regexp pattern to WASM
$(REGEX_WASM): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and regexp WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml $(REGEXPED)
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with wasmtime
run: $(FINAL_WASM)
	wasmtime run $(FINAL_WASM)

# Build outputs only: node_modules and package-lock.json are what you
# installed, and are left alone.
clean:
	rm -f $(STUB) $(MAIN_WASM) $(REGEX_WASM) $(FINAL_WASM)
