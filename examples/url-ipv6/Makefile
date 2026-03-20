# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_TARGET := wasm32-wasip1

MAIN_WASM  := target/$(WASM_TARGET)/release/url_ipv6.wasm
REGEX_WASM := url_ipv6.wasm
FINAL_WASM := final.wasm

.PHONY: all stub compile build merge run clean

all: run

# Step 1 – generate Rust stub from config
src/stub.rs: regexped.yaml
	$(REGEXPED) stub --config=regexped.yaml --out-dir=. --rust

stub: src/stub.rs

# Step 2 – compile Rust source to WASM
$(MAIN_WASM): src/main.rs src/stub.rs Cargo.toml
	cargo build --target $(WASM_TARGET) --release

build: $(MAIN_WASM)

# Step 3 – compile regex pattern to WASM
#           (reads main WASM to determine where to place DFA tables in memory)
$(REGEX_WASM): regexped.yaml $(MAIN_WASM)
	$(REGEXPED) compile --config=regexped.yaml --wasm-input=$(MAIN_WASM) --out-dir=.

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and regex WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml $(MAIN_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with a few test inputs
run: $(FINAL_WASM)
	@echo "=== not a URL ==="
	wasmtime run $(FINAL_WASM) "hello world"
	@echo ""
	@echo "=== IPv4 URL (not matched) ==="
	wasmtime run $(FINAL_WASM) "https://example.com/page"
	@echo ""
	@echo "=== IPv6 URL, no port ==="
	wasmtime run $(FINAL_WASM) "https://[2001:db8::1]/api"
	@echo ""
	@echo "=== IPv6 URL with port ==="
	wasmtime run $(FINAL_WASM) "https://[::1]:8080/health"
	@echo ""
	@echo "=== IPv6 loopback, path and query ==="
	wasmtime run $(FINAL_WASM) "http://[fe80::1]/index?page=1"

clean:
	cargo clean
	rm -f src/stub.rs $(REGEX_WASM) $(FINAL_WASM)
