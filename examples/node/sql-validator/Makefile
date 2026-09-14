# regexped must be built first: run `make` in the repo root.
REGEXPED     := ../../../regexped
PATTERN_WASM := patterns.wasm
TS_STUB      := stubs.ts
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

# Step 1 – compile SQL patterns to WASM
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
$(PATTERN_WASM): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate TypeScript stub
$(TS_STUB): regexped.yaml $(PATTERN_WASM) $(REGEXPED)
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
$(OUT_JS): main.ts $(TS_STUB) tsconfig.json | check-tools
	$(TSC) -p . --typeRoots "$(NODE_TYPE_ROOTS)" --types node

build: $(OUT_JS)

# Step 4 – run the validator (pipe SQL statements via stdin, one per line)
run: build
	@printf '%s\n' \
		'SELECT * FROM users WHERE id = 1' \
		'SELECT FROM users' \
		'SELECT id, name FROM accounts WHERE active = 1' \
		'INSERT INTO logs (msg) VALUES ("hello")' \
		'INSERT users VALUES (1)' \
		'UPDATE users SET active = 0 WHERE id = 1' \
		'UPDATE users active = 0' \
		'DELETE FROM users WHERE id = 1' \
		'DELETE users' \
		| node $(OUT_JS)

clean:
	rm -rf $(PATTERN_WASM) $(TS_STUB) dist
