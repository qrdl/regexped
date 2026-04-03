# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
WASM_MERGE  := ../../../binaryen/bin/wasm-merge
REGEX_WASMS := regexps.wasm
FINAL_WASM  := final.wasm
JS_STUB     := regex.js

.PHONY: all build run clean

all: build

# Step 1 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – merge into a single self-contained WASM
$(FINAL_WASM): $(REGEX_WASMS) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --dummy-main $(REGEX_WASMS)

# Step 3 – generate JS ES module stub
$(JS_STUB): regexped.yaml $(FINAL_WASM)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 4 – serve locally (requires Python 3)
run: build
	@echo "Open http://localhost:8080 in your browser"
	python3 -m http.server 8080

clean:
	rm -f $(REGEX_WASMS) $(FINAL_WASM) $(JS_STUB)
