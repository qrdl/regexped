# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_MERGE  := ../../../binaryen/bin/wasm-merge
MAIN_WASM   := main.wasm
REGEX_WASMS := urls.wasm
FINAL_WASM  := final.wasm
JS_STUB     := regex.ts

.PHONY: all build run clean

all: build

# Step 1 – generate a minimal main WASM (memory-only, used for table layout)
$(MAIN_WASM):
	$(REGEXPED) generate --dummy_main --out-dir=.

# Step 2 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml $(MAIN_WASM)
	$(REGEXPED) compile --config=regexped.yaml --wasm-input=$(MAIN_WASM)

# Step 3 – merge into a single self-contained WASM
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASMS) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml $(MAIN_WASM) $(REGEX_WASMS)

# Step 4 – generate TypeScript ES module stub
$(JS_STUB): regexped.yaml $(FINAL_WASM)
	$(REGEXPED) generate --config=regexped.yaml --ts

build: $(JS_STUB)

# Step 5 – run the example (pipe text via stdin)
# Requires Node.js 22+ (--experimental-strip-types) or tsx (npm install -g tsx)
TSX ?= npx --yes tsx
run: build
	@echo "Visit https://example.com or check http://foo.org/path?q=1 for details." | $(TSX) main.ts

clean:
	rm -f $(MAIN_WASM) $(REGEX_WASMS) $(FINAL_WASM) $(JS_STUB)
