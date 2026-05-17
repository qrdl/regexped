# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../../regexped
WASM_TARGET := wasm32-wasip1

MAIN_WASM   := target/$(WASM_TARGET)/release/url_guard.wasm
PATTERN_WASM := patterns.wasm
FINAL_WASM  := final.wasm

.PHONY: all generate build compile merge clean

all: merge

# Step 1 – generate Rust stubs
stubs.rs: regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: stubs.rs

# Step 2 – compile Rust source to WASM
$(MAIN_WASM): lib.rs stubs.rs Cargo.toml
	cargo build --target $(WASM_TARGET) --release

build: $(MAIN_WASM)

# Step 3 – compile all attack patterns to WASM
$(PATTERN_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(PATTERN_WASM)

# Step 4 – merge app WASM and pattern WASM into a single deployable module
$(FINAL_WASM): $(MAIN_WASM) $(PATTERN_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(PATTERN_WASM)

merge: $(FINAL_WASM)

clean:
	cargo clean
	rm -f stubs.rs $(PATTERN_WASM) $(FINAL_WASM)
