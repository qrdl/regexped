# regexped must be built first: run `make` in the repo root.
REGEXPED    := ../../regexped
REGEX_WASMS := regexps.wasm
JS_STUB     := regex.js

.PHONY: all build dev deploy clean

all: build

# Step 1 – compile regex patterns to WASM
$(REGEX_WASMS): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate JS ES module stub
$(JS_STUB): regexped.yaml $(REGEX_WASMS)
	$(REGEXPED) generate --config=regexped.yaml

build: $(JS_STUB)

# Step 3 – run locally with wrangler (requires: npm install -g wrangler)
dev: build
	npx wrangler dev

# Step 4 – deploy to Cloudflare (requires: wrangler login)
deploy: build
	npx wrangler deploy

clean:
	rm -f $(REGEX_WASMS) $(JS_STUB)
