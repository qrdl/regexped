# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
CC         := clang-19
CFLAGS     := --target=wasm32-wasi -nostdlib -Wl,--no-entry

MAIN_WASM  := main.wasm
REGEX_WASM := url_parts.wasm
FINAL_WASM := final.wasm

# --- the COMPONENT build -------------------------------------------------------
# Same patterns, same main.c, different output KIND. Everything it produces lives
# under component/ so the two builds cannot collide.
COMP_CFG    := regexped-component.yaml
COMP_DIR    := component
COMP_STUB   := $(COMP_DIR)/stub.h
COMP_REGEX  := $(COMP_DIR)/url_parts.wasm
COMP_CORE   := $(COMP_DIR)/core.wasm
COMP_GUEST  := $(COMP_DIR)/guest.wasm
COMP_FINAL  := $(COMP_DIR)/composed.wasm

# The wasip1 adapter, needed because main.c talks wasi_snapshot_preview1 directly
# (args_get, fd_write, proc_exit) while a component speaks wasi:cli. It ships in
# the wasi-preview1-component-adapter-provider crate; override ADAPTER to point
# at your own copy.
ADAPTER ?= $(firstword $(wildcard $(HOME)/.cargo/registry/src/*/wasi-preview1-component-adapter-provider-*/artefacts/wasi_snapshot_preview1.command.wasm))

# --- the wasip2 COMPONENT build ------------------------------------------------
# Same patterns, same main.c, same generated stub — a third BUILD, not a third
# output kind. clang wraps into a component at LINK time here, so there is no
# embed/new step and no adapter flag: wasm-component-ld bundles the adapter.
#
# The price is `wit-bindgen c`, needed for ONE file: the component-type object.
# That metadata has to be in the objects before the linker runs, and regexped
# cannot emit a wasm object file — which is exactly why the wasip1 route above
# exists and needs no code generator.
P2_DIR   := wasip2
P2_TYPES := $(P2_DIR)/wb/url_parts_consumer_component_type.o
P2_GUEST := $(P2_DIR)/guest.wasm
P2_FINAL := $(P2_DIR)/composed.wasm

# wasm-component-ld is clang's linker for this target. rustup ships it inside the
# toolchain rather than on PATH; override WASM_COMPONENT_LD_DIR if yours is
# elsewhere, or drop the PATH prefix if it is already on PATH.
WASM_COMPONENT_LD_DIR ?= $(firstword $(wildcard $(HOME)/.rustup/toolchains/*/lib/rustlib/*/bin))

.PHONY: all generate build compile merge run clean component component-run wasip2 wasip2-run

all: run

# Step 1 – generate C stubs from config (produces both stub.h and stub.c)
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
stub.h: regexped.yaml $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml
stub.c: stub.h

generate: stub.h stub.c

# Step 2 – compile C source to WASM
$(MAIN_WASM): main.c stub.h stub.c
	$(CC) $(CFLAGS) -o $@ main.c stub.c

build: $(MAIN_WASM)

# Step 3 – compile regexp pattern to WASM
$(REGEX_WASM): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and regexp WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml $(REGEXPED)
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with test inputs
run: $(FINAL_WASM)
	@echo "=== single URL ==="
	wasmtime run $(FINAL_WASM) "https://example.com:8080/path/to/page?q=1&r=2#section"
	@echo ""
	@echo "=== two URLs in one string (demonstrates iterator) ==="
	wasmtime run $(FINAL_WASM) "visit https://example.com/page or http://api.example.org/v2?fmt=json"
	@echo ""
	@echo "=== no URLs ==="
	wasmtime run $(FINAL_WASM) "nothing here"

# --- component targets --------------------------------------------------------

# Step 1 – compile the patterns into a component, and generate its stub. Both
# land under component/; the stub is called stub.h there too, so main.c includes
# the same name and needs no change.
$(COMP_REGEX) $(COMP_STUB): $(COMP_CFG) $(REGEXPED)
	$(REGEXPED) compile  --config=$(COMP_CFG)
	$(REGEXPED) generate --config=$(COMP_CFG)

# Step 2 – compile main.c against the COMPONENT stub. -I$(COMP_DIR) is the only
# difference from the module build's compile line.
$(COMP_CORE): main.c $(COMP_STUB)
	$(CC) $(CFLAGS) -I$(COMP_DIR) -o $@ main.c $(COMP_DIR)/stub.c

# Step 3 – wrap the core module into a component. `component embed` needs the WIT
# DIRECTORY (that is how it resolves deps/), and the adapter bridges main.c's
# wasi_snapshot_preview1 imports to wasi:cli.
$(COMP_GUEST): $(COMP_CORE)
	@test -n "$(ADAPTER)" || { echo "no wasip1 adapter found; set ADAPTER=/path/to/wasi_snapshot_preview1.command.wasm" >&2; exit 1; }
	wasm-tools component embed $(COMP_DIR)/wit $(COMP_CORE) --world url-parts-consumer -o $(COMP_DIR)/embedded.wasm
	wasm-tools component new $(COMP_DIR)/embedded.wasm --adapt wasi_snapshot_preview1=$(ADAPTER) -o $@

# Step 4 – compose guest and regexp component. `wac` is to components what
# wasm-merge is to modules; without it the guest has an unsatisfied import.
$(COMP_FINAL): $(COMP_GUEST) $(COMP_REGEX)
	wac plug $(COMP_GUEST) --plug $(COMP_REGEX) -o $@

component: $(COMP_FINAL)

# Step 5 – run the component build with the same inputs as the module build. The
# output should be identical: same patterns, same main.c, same generated API.
component-run: $(COMP_FINAL)
	@echo "=== single URL (component) ==="
	wasmtime run $(COMP_FINAL) "https://example.com:8080/path/to/page?q=1&r=2#section"
	@echo ""
	@echo "=== two URLs in one string (component) ==="
	wasmtime run $(COMP_FINAL) "visit https://example.com/page or http://api.example.org/v2?fmt=json"
	@echo ""
	@echo "=== no URLs (component) ==="
	wasmtime run $(COMP_FINAL) "nothing here"

# --- wasip2 targets -----------------------------------------------------------

# Step 1 – the component-type object, the only thing wit-bindgen is used for.
# Its .c/.h are DISCARDED: the bindings come from regexped's stub.
$(P2_TYPES): $(COMP_STUB)
	@mkdir -p $(P2_DIR)
	wit-bindgen c $(COMP_DIR)/wit --out-dir $(P2_DIR)/wb

# Step 2 – compile AND wrap in one step. Note what is absent: no
# `wasm-tools component embed`, no `component new`, no --adapt.
$(P2_GUEST): main.c $(COMP_STUB) $(P2_TYPES)
	@test -n "$(WASM_COMPONENT_LD_DIR)" || { echo "wasm-component-ld not found; set WASM_COMPONENT_LD_DIR" >&2; exit 1; }
	PATH="$(WASM_COMPONENT_LD_DIR):$$PATH" $(CC) --target=wasm32-wasip2 -nostdlib -Wl,--no-entry 		-I$(COMP_DIR) -o $@ main.c $(COMP_DIR)/stub.c $(P2_TYPES)

# Step 3 – compose, exactly as the wasip1 route does.
$(P2_FINAL): $(P2_GUEST) $(COMP_REGEX)
	wac plug $(P2_GUEST) --plug $(COMP_REGEX) -o $@

wasip2: $(P2_FINAL)

wasip2-run: $(P2_FINAL)
	@echo "=== single URL (wasip2 component) ==="
	wasmtime run $(P2_FINAL) "https://example.com:8080/path/to/page?q=1&r=2#section"
	@echo ""
	@echo "=== two URLs in one string (wasip2 component) ==="
	wasmtime run $(P2_FINAL) "visit https://example.com/page or http://api.example.org/v2?fmt=json"
	@echo ""
	@echo "=== no URLs (wasip2 component) ==="
	wasmtime run $(P2_FINAL) "nothing here"

clean:
	rm -f stub.h stub.c $(MAIN_WASM) $(REGEX_WASM) $(FINAL_WASM)
	rm -rf $(COMP_DIR) $(P2_DIR)
