REGEXPED := ../../../../regexped

.PHONY: all compile build run clean

all: run

# Compile the 10-pattern set to a standalone WASM module.
# No merge step: the set WASM is self-contained (exports its own memory).
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
compile: regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Build the Rust host binary (native, not WASM).
build:
	cargo build --release

# Run: compile patterns, build host, then scan test inputs.
run: compile build
	@echo "=== clean text ==="
	cargo run --release -- "nothing sensitive here"
	@echo ""
	@echo "=== AWS access key ==="
	cargo run --release -- "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	@echo ""
	@echo "=== GitHub PAT ==="
	cargo run --release -- "Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"
	@echo ""
	@echo "=== JWT ==="
	cargo run --release -- "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	@echo ""
	@echo "=== multiple secrets (all reported in one scan pass) ==="
	cargo run --release -- "key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab stripe=sk_live_AbCdEfGhIjKlMnOpQrStUvWx"

clean:
	cargo clean
	rm -f secrets.wasm
