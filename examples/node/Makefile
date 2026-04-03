# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_MERGE  := ../../../binaryen/bin/wasm-merge
REGEX_WASMS := urls.wasm
FINAL_WASM  := final.wasm
JS_STUB     := regex.ts

.PHONY: all build run clean

all: build

# Step 1 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – merge into a single self-contained WASM
$(FINAL_WASM): $(REGEX_WASMS) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --dummy-main $(REGEX_WASMS)

# Step 3 – generate TypeScript ES module stub
$(JS_STUB): regexped.yaml $(FINAL_WASM)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 4 – run the example (pipe text via stdin)
# Requires Node.js 22+ (--experimental-strip-types) or tsx (npm install -g tsx)
TSX ?= npx --yes tsx
run: build
	@echo "Visit https://example.com or check http://foo.org/path?q=1 for details." | $(TSX) main.ts

clean:
	rm -f $(REGEX_WASMS) $(FINAL_WASM) $(JS_STUB)
