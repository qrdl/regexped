# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
REGEX_WASMS := regexps.wasm
JS_STUB     := regex.js

.PHONY: all build run clean

all: build

# Step 1 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate JS ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 3 – serve locally (requires Python 3)
run: build
	@echo "Open http://localhost:8080 in your browser"
	python3 -m http.server 8080

clean:
	rm -f $(REGEX_WASMS) $(JS_STUB)
