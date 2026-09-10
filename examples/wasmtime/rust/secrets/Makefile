# regexped must be built first: run `make` in the repo root.
#
# This example is a COMPONENT: three steps, not five. There is no stub
# generation (the host binds against the WIT) and no merge (a component owns its
# own memory), and the host is a native binary rather than a wasm32-wasip1 one.
REGEXPED  := ../../../../regexped
COMPONENT := secrets.wasm
WIT       := secrets.wit
HOST      := target/release/secrets

.PHONY: all compile build run clean

all: run

# Step 1 – compile the patterns into a component, plus the sibling .wit.
# $(REGEXPED) is a prerequisite because the component depends on the COMPILER as
# much as on the config.
$(COMPONENT) $(WIT): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(COMPONENT)

# Step 2 – build the host. It depends on the WIT: bindgen! reads it at COMPILE
# time, so a stale interface is a build error rather than a runtime surprise.
$(HOST): main.rs Cargo.toml $(WIT)
	cargo build --release

build: $(HOST)

# Step 3 – run with test inputs
run: $(HOST) $(COMPONENT)
	@echo "=== clean text ==="
	./$(HOST) "nothing sensitive here"
	@echo ""
	@echo "=== GitHub personal access token ==="
	./$(HOST) "Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"
	@echo ""
	@echo "=== JWT ==="
	./$(HOST) "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	@echo ""
	@echo "=== AWS access key ==="
	./$(HOST) "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	@echo ""
	@echo "=== multiple secrets in one string (the host's own drive loop) ==="
	./$(HOST) "key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"

clean:
	cargo clean
	rm -f $(COMPONENT) $(WIT)
