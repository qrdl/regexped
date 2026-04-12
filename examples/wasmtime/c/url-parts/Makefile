# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
CC         := clang-19
CFLAGS     := --target=wasm32-wasi -nostdlib -Wl,--no-entry

MAIN_WASM  := main.wasm
REGEX_WASM := url_parts.wasm
FINAL_WASM := final.wasm

.PHONY: all generate build compile merge run clean

all: run

# Step 1 – generate C stubs from config (produces both stub.h and stub.c)
stub.h: regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml
stub.c: stub.h

generate: stub.h stub.c

# Step 2 – compile C source to WASM
$(MAIN_WASM): main.c stub.h stub.c
	$(CC) $(CFLAGS) -o $@ main.c stub.c

build: $(MAIN_WASM)

# Step 3 – compile regex pattern to WASM
$(REGEX_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge main WASM and regex WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(REGEX_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with test inputs
run: $(FINAL_WASM)
	@echo "=== single URL ==="
	wasmtime run $(FINAL_WASM) "https://example.com:8080/path/to/page?q=1&r=2#section"
	@echo ""
	@echo "=== two URLs in one string (demonstrates iterator) ==="
	wasmtime run $(FINAL_WASM) "visit https://example.com/page or http://api.example.org/v2?fmt=json"
	@echo ""
	@echo "=== no URLs ==="
	wasmtime run $(FINAL_WASM) "nothing here"

clean:
	rm -f stub.h stub.c $(MAIN_WASM) $(REGEX_WASM) $(FINAL_WASM)
