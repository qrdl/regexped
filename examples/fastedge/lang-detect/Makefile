# regexped must be built first: run `make` in the repo root.
#
# A FastEdge HTTP application built as a COMPONENT. Four steps: compile the
# patterns into a component, generate the Rust stub, build the app as a
# wasi:http guest component, compose the two. The last step is `regexped
# merge`, which dispatches on wasm_format and calls `wac` for a component.
REGEXPED  := ../../../regexped
COMPONENT := langdetect.wasm
WIT       := langdetect.wit
STUB      := stubs.rs
GUEST     := target/wasm32-wasip2/release/lang_detect.wasm
FINAL     := lang-detect.wasm
PORT      ?= 8080
URL       := http://127.0.0.1:$(PORT)/

.PHONY: all compile generate build compose serve run test clean

all: compose

# Step 1 – compile the patterns into a component, plus the sibling .wit.
# Both come from ONE compile, so they hang off a stamp.
.component.stamp: regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml
	@touch $@

$(COMPONENT) $(WIT): .component.stamp ;

compile: $(COMPONENT)

# Step 2 – generate the Rust stub.
$(STUB): regexped.yaml $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 3 – build the app as a GUEST component exporting wasi:http.
$(GUEST): lib.rs $(STUB) Cargo.toml
	cargo build --target wasm32-wasip2 --release

build: $(GUEST)

# Step 4 – compose the app with the regexp component. Until this runs the app
# has an unsatisfied import. The result is what FastEdge runs.
$(FINAL): $(GUEST) $(COMPONENT)
	$(REGEXPED) merge --config=regexped.yaml --main=$(GUEST) $(COMPONENT)

compose: $(FINAL)

# Serve the app locally until Ctrl-C. -Scli grants the wasi:cli imports the
# Rust standard library brings in; FastEdge provides them.
serve: $(FINAL)
	wasmtime serve -Scli --addr 127.0.0.1:$(PORT) $(FINAL)

# Serve the app in the background, POST each sample text, stop the server.
run: $(FINAL)
	@if curl -s -o /dev/null $(URL); then \
	  echo "port $(PORT) is in use: make run PORT=<another>"; exit 1; fi; \
	wasmtime serve -Scli --addr 127.0.0.1:$(PORT) $(FINAL) 2>.serve.log & pid=$$!; \
	trap 'kill $$pid 2>/dev/null' EXIT; \
	until curl -s -o /dev/null $(URL); do \
	  kill -0 $$pid 2>/dev/null || { cat .serve.log; exit 1; }; sleep 0.2; done; \
	for text in 'Hello world' 'Grüße aus Köln' 'Un café, por favor' \
	    'Zażółć gęślą jaźń' 'Příliš žluťoučký kůň' 'Привет' 'Привіт' 'Съешь' \
	    'Ђорђе' 'Καλημέρα κόσμε' 'Привет, Grüße'; do \
	  printf '%s → ' "$$text"; curl -s --data-binary "$$text" $(URL); echo; \
	done

# Run lang-detect.wasm under the FastEdge runtime itself — fastedge-run, through
# @gcoredev/fastedge-test — and assert every sample's answer (test.mjs). Run
# `npm install` once first; this Makefile installs nothing.
test: $(FINAL)
	@test -d node_modules/@gcoredev/fastedge-test || { \
	  echo "error: run 'npm install' first: it installs @gcoredev/fastedge-test" >&2; exit 1; }
	npm test

clean:
	cargo clean
	rm -f $(COMPONENT) $(WIT) $(STUB) $(FINAL) .component.stamp .serve.log
