# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
GO         := go

APP_WASM   := app.wasm
REGEX_WASM := sqli.wasm
FINAL_WASM := final.wasm
STUB       := stub.go

.PHONY: all generate build compile merge run clean

all: run

# Step 1 – generate Go stub from config
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
$(STUB): regexped.yaml $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 2 – compile Go source to WASM (wasip1)
$(APP_WASM): main.go $(STUB) go.mod
	GOOS=wasip1 GOARCH=wasm $(GO) build -o $@ .

build: $(APP_WASM)

# Step 3 – compile regexp patterns to WASM
$(REGEX_WASM): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge Go WASM and regexp WASM into a single module
$(FINAL_WASM): $(APP_WASM) $(REGEX_WASM) regexped.yaml $(REGEXPED)
	$(REGEXPED) merge --config=regexped.yaml --main=$(APP_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run
run: $(FINAL_WASM)
	@echo "=== SQL injection detection (Backtracking engine) ==="
	wasmtime $(FINAL_WASM)

clean:
	rm -f $(APP_WASM) $(REGEX_WASM) $(FINAL_WASM) $(STUB)
