# regexped must be built first: run `make` in the repo root.
#
# This Makefile installs NOTHING: `make dev` and `make deploy` need Wrangler
# installed and on PATH (see README.md), and stop with a message if it is not.
REGEXPED    := ../../regexped
WRANGLER    ?= wrangler
REGEX_WASMS := regexps.wasm
JS_STUB     := regexp.js

.PHONY: all build run dev deploy clean check-wrangler

all: build

# Step 1 – compile regexp patterns to WASM
# $(REGEXPED) is a prerequisite of every rule below that runs it: the generated
# stubs and the compiled .wasm depend on the COMPILER as much as on the config.
# Without it a rebuild after a compiler change keeps the stale .wasm and the
# merge fails with an import/export type mismatch.
$(REGEX_WASMS): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate JS ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS) $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# A Worker does not run as a local program, so `make run` — which examples/Makefile
# calls in every example — only says what to use instead.
run:
	@echo "workers: nothing to run locally — use 'make dev' for a local Wrangler server, or 'make deploy'"

check-wrangler:
	@command -v $(WRANGLER) >/dev/null 2>&1 || { echo "error: '$(WRANGLER)' not found on PATH. Install Wrangler (see README.md): npm install -g wrangler" >&2; exit 1; }

# Step 3 – run locally with Wrangler
dev: build | check-wrangler
	$(WRANGLER) dev

# Step 4 – deploy to Cloudflare (requires: wrangler login)
deploy: build | check-wrangler
	$(WRANGLER) deploy

clean:
	rm -f $(REGEX_WASMS) $(JS_STUB)
