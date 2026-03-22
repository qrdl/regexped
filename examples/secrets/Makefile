# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_TARGET := wasm32-wasip1

MAIN_WASM   := target/$(WASM_TARGET)/release/secrets.wasm
REGEX_WASMS := github.wasm jwt.wasm aws.wasm
FINAL_WASM  := final.wasm

.PHONY: all stub build compile merge run clean

all: run

# Step 1 – generate Rust stubs (one file per pattern)
src/github_stub.rs src/jwt_stub.rs src/aws_stub.rs: regexped.yaml
	$(REGEXPED) stub --config=regexped.yaml --out-dir=. --rust

stub: src/github_stub.rs src/jwt_stub.rs src/aws_stub.rs

# Step 2 – compile Rust source to WASM
$(MAIN_WASM): src/main.rs src/github_stub.rs src/jwt_stub.rs src/aws_stub.rs Cargo.toml
	cargo build --target $(WASM_TARGET) --release

build: $(MAIN_WASM)

# Step 3 – compile all regex patterns to WASM
$(REGEX_WASMS): regexped.yaml $(MAIN_WASM)
	$(REGEXPED) compile --config=regexped.yaml --wasm-input=$(MAIN_WASM) --out-dir=.

compile: $(REGEX_WASMS)

# Step 4 – merge main WASM and all regex WASMs into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASMS) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml $(MAIN_WASM) $(REGEX_WASMS)

merge: $(FINAL_WASM)

# Step 5 – run with test inputs
run: $(FINAL_WASM)
	@echo "=== clean text ==="
	wasmtime run $(FINAL_WASM) "nothing sensitive here"
	@echo ""
	@echo "=== GitHub personal access token ==="
	wasmtime run $(FINAL_WASM) "Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"
	@echo ""
	@echo "=== JWT ==="
	wasmtime run $(FINAL_WASM) "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	@echo ""
	@echo "=== AWS access key ==="
	wasmtime run $(FINAL_WASM) "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	@echo ""
	@echo "=== multiple secrets in one string (demonstrates iterator) ==="
	wasmtime run $(FINAL_WASM) "key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"

clean:
	cargo clean
	rm -f src/github_stub.rs src/jwt_stub.rs src/aws_stub.rs $(REGEX_WASMS) $(FINAL_WASM)
