# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../../regexped
REGEX_WASMS := urls.wasm
JS_STUB     := regexp.ts
# TypeScript is compiled with the GLOBAL tsc, strict (see tsconfig.json), and the
# JavaScript it emits into dist/ is what node runs. Node's type definitions come
# from the global @types directory: tsc does not look in the global node_modules
# on its own, and where that is differs between setups (nvm, Homebrew, system
# npm), so it is discovered here and passed on the command line. Override either:
#   make run TSC=/path/to/tsc NODE_TYPE_ROOTS=/path/to/@types
TSC             ?= tsc
NODE_TYPE_ROOTS ?= $(shell npm root -g 2>/dev/null)/@types
OUT_JS          := dist/main.js

.PHONY: all build run clean check-tools

all: build

# Step 1 – compile regexp patterns to WASM
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
$(REGEX_WASMS): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate TypeScript ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS) $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

# Fails with a specific message, before tsc is invoked, when a tool is missing.
# npm is needed only to discover NODE_TYPE_ROOTS, so it is not required when
# that is given.
check-tools:
ifeq ($(origin NODE_TYPE_ROOTS),file)
	@command -v npm >/dev/null 2>&1 || { echo "error: 'npm' not found on PATH; it is needed to locate the global @types directory (or set NODE_TYPE_ROOTS)" >&2; exit 1; }
endif
	@command -v $(TSC) >/dev/null 2>&1 || { echo "error: '$(TSC)' not found on PATH. Install TypeScript: npm install -g typescript" >&2; exit 1; }
	@test -f "$(NODE_TYPE_ROOTS)/node/package.json" || { echo "error: Node type definitions not found at $(NODE_TYPE_ROOTS)/node/package.json. Install them: npm install -g @types/node" >&2; exit 1; }

# Step 3 – type-check and compile main.ts and the stub to dist/
$(OUT_JS): main.ts $(JS_STUB) tsconfig.json | check-tools
	$(TSC) -p . --typeRoots "$(NODE_TYPE_ROOTS)" --types node

build: $(OUT_JS)

# Step 4 – run the example (pipe text via stdin)
run: build
	@echo "Visit https://example.com or check http://foo.org/path?q=1 for details." | node $(OUT_JS)

clean:
	rm -rf $(REGEX_WASMS) $(JS_STUB) dist
