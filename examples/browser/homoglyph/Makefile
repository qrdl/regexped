# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../../regexped
REGEX_WASMS := regexps.wasm
JS_STUB     := regexp.js
PORT        ?= 8080

.PHONY: all build run clean

all: build

# Step 1 – compile the patterns to a standalone WASM module. They name Unicode
# script classes and characters above U+007F, so they compile in Unicode mode.
# $(REGEXPED) is a prerequisite because the module depends on the COMPILER as
# much as on the config.
$(REGEX_WASMS): regexped.yaml $(REGEXPED)
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate the JS ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS) $(REGEXPED)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 3 – serve this page alone (requires Python 3). `make run` one directory
# up serves it together with the other browser example.
run: build
	@echo "Open http://localhost:$(PORT) in your browser"
	python3 -m http.server $(PORT)

clean:
	rm -f $(REGEX_WASMS) $(JS_STUB)
