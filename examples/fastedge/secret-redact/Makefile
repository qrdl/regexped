# regexped must be built first: run `make` in the repo root.
#
# A FastEdge HTTP application in JAVASCRIPT, built with the FastEdge JS SDK.
# Two steps: compile the patterns into a component, then `fastedge-build`
# bundles src/index.js, generates the bindings to the component's interface
# and composes the two into one binary. No stub and no `regexped merge`: the
# SDK writes the bindings and composes.
#
# This Makefile installs nothing: run `npm install` here once first, which
# installs the SDK (`fastedge-build`) and the FastEdge test runner.
REGEXPED  := ../../../regexped
COMPONENT := secrets.wasm
WIT       := secrets.wit
INTERFACE := regexped:secrets/sets
FINAL     := secret-redact.wasm
# Written by fastedge-build: the TypeScript declarations of the component's
# interface, which its syntax check reads.
DECLS     := src/fastedge-components.d.ts

.PHONY: all compile build run test clean check-npm

all: build

check-npm:
	@test -d node_modules/@gcoredev/fastedge-sdk-js -a -d node_modules/@gcoredev/fastedge-test || { \
	  echo "error: run 'npm install' first: it installs @gcoredev/fastedge-sdk-js and @gcoredev/fastedge-test" >&2; exit 1; }

# Step 1 – compile the patterns into a component, plus the sibling .wit.
# Both come from ONE compile: a grouped target (`&:`, GNU make 4.3 or later),
# so either one missing or out of date reruns it.
$(COMPONENT) $(WIT) &: regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

compile: $(COMPONENT)

# Step 2 – build the app and compose the component into it. The result is what
# FastEdge runs.
$(FINAL): src/index.js $(COMPONENT) | check-npm
	npx fastedge-build --input src/index.js --output $(FINAL) --component $(INTERFACE)=$(COMPONENT)

build: $(FINAL)

# Run the app under the FastEdge runtime (fastedge-run, through
# @gcoredev/fastedge-test) in front of a local origin, print each response and
# check it.
run: $(FINAL) | check-npm
	node test.mjs --print

# The same checks, without printing the responses.
test: $(FINAL) | check-npm
	npm test

clean:
	rm -f $(COMPONENT) $(WIT) $(FINAL) $(DECLS)
