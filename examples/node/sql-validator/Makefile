# regexped must be built first: run `make` in the repo root.
REGEXPED     := ../../../regexped
PATTERN_WASM := patterns.wasm
TS_STUB      := stubs.ts

.PHONY: all build run clean

all: build

# Step 1 – compile SQL patterns to WASM
$(PATTERN_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

# Step 2 – generate TypeScript stub
$(TS_STUB): regexped.yaml $(PATTERN_WASM)
	$(REGEXPED) generate --config=regexped.yaml

build: $(TS_STUB)

# Step 3 – run the validator (pipe SQL statements via stdin, one per line)
# Requires Node.js 22+ (--experimental-strip-types) or tsx (npm install -g tsx)
TSX ?= npx --yes tsx
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
		| $(TSX) main.ts

clean:
	rm -f $(PATTERN_WASM) $(TS_STUB)
