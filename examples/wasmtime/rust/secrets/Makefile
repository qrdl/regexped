# regexped must be built first: run `make` in the repo root.
#
# A COMPONENT example consumed through a GENERATED stub. Four steps: compile the
# patterns into a component, generate the stub, build the consumer as a guest
# component, compose the two. The last step is `regexped merge` — the same
# command a module build uses, which dispatches on wasm_format and calls `wac`
# where a module build calls `wasm-merge`.
REGEXPED  := ../../../../regexped
COMPONENT := secrets.wasm
WIT       := secrets.wit
STUB      := stubs.rs
GUEST     := target/wasm32-wasip2/release/secrets.wasm
FINAL     := composed.wasm

.PHONY: all compile generate build compose run clean

all: run

# Step 1 – compile the patterns into a component, plus the sibling .wit.
# $(REGEXPED) is a prerequisite because the component depends on the COMPILER as
# much as on the config.
$(COMPONENT) $(WIT): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(COMPONENT)

# Step 2 – generate the Rust stub. Its API is identical to the module-format
# stub's; only what sits under it differs.
$(STUB): regexped.yaml $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 3 – build the consumer as a GUEST component. wasm32-wasip2 emits a
# component directly, so no cargo-component is needed.
$(GUEST): main.rs $(STUB) Cargo.toml
	cargo build --target wasm32-wasip2 --release

build: $(GUEST)

# Step 4 – compose the guest with the regexp component. Until this runs the guest
# has an unsatisfied import and will not instantiate. --main is the SOCKET (the
# component with the unsatisfied import); the positionals are regexped's own.
$(FINAL): $(GUEST) $(COMPONENT)
	$(REGEXPED) merge --config=regexped.yaml --main=$(GUEST) $(COMPONENT)

compose: $(FINAL)

# Step 5 – run with test inputs
run: $(FINAL)
	@echo "=== clean text ==="
	wasmtime run $(FINAL) "nothing sensitive here"
	@echo ""
	@echo "=== GitHub personal access token ==="
	wasmtime run $(FINAL) "Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"
	@echo ""
	@echo "=== JWT ==="
	wasmtime run $(FINAL) "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	@echo ""
	@echo "=== AWS access key ==="
	wasmtime run $(FINAL) "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	@echo ""
	@echo "=== multiple secrets in one string (demonstrates the generated iterator) ==="
	wasmtime run $(FINAL) "key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"

clean:
	cargo clean
	rm -f $(COMPONENT) $(WIT) $(STUB) $(FINAL)
