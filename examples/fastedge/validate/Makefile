# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../../regexped
WASM_TARGET := wasm32-wasip1

MAIN_WASM   := target/$(WASM_TARGET)/release/validate.wasm
REGEX_WASM := regexps.wasm
FINAL_WASM  := final.wasm

.PHONY: all generate build compile merge run clean

all: merge

# Step 1 – generate Rust stubs (all patterns into one file)
stubs.rs: regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: stubs.rs

# Step 2 – compile Rust source to WASM
$(MAIN_WASM): lib.rs stubs.rs Cargo.toml
	cargo build --target $(WASM_TARGET) --release

build: $(MAIN_WASM)

# Step 3 – compile all regex patterns to WASM
$(REGEX_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and all regex WASMs into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

clean:
	cargo clean
	rm -f stubs.rs $(REGEX_WASM) $(FINAL_WASM)
