# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
REGEX_WASMS := urls.wasm
JS_STUB     := regex.ts

.PHONY: all build run clean

all: build

# Step 1 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate TypeScript ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 3 – run the example (pipe text via stdin)
# Requires Node.js 22+ (--experimental-strip-types) or tsx (npm install -g tsx)
TSX ?= npx --yes tsx
run: build
	@echo "Visit https://example.com or check http://foo.org/path?q=1 for details." | $(TSX) main.ts

clean:
	rm -f $(REGEX_WASMS) $(JS_STUB)
