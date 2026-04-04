# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_TARGET := wasm32-wasip1

MAIN_WASM  := target/$(WASM_TARGET)/release/url_parts.wasm
REGEX_WASM := url_parts.wasm
FINAL_WASM := final.wasm

.PHONY: all generate build compile merge run clean

all: run

# Step 1 – generate Rust stub from config
src/stub.rs: regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: src/stub.rs

# Step 2 – compile Rust source to WASM
$(MAIN_WASM): src/main.rs src/stub.rs Cargo.toml
	cargo build --target $(WASM_TARGET) --release

build: $(MAIN_WASM)

# Step 3 – compile regex pattern to WASM (OnePass engine with capture tracking)
$(REGEX_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and regex WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml
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

clean:
	cargo clean
	rm -f src/stub.rs $(REGEX_WASM) $(FINAL_WASM)
