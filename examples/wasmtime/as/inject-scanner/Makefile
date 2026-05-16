# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
ASC        := npx --yes asc
ASC_FLAGS  := --config asconfig.json

MAIN_WASM  := main.wasm
THREAT_WASM := threats.wasm
FINAL_WASM := final.wasm
STUB       := stub.ts

.PHONY: all generate build compile merge run clean

all: run

# Step 1 – generate AssemblyScript stub from config
$(STUB): regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 2 – compile AssemblyScript source to WASM
node_modules/.package-lock.json:
	npm install

$(MAIN_WASM): index.ts $(STUB) node_modules/.package-lock.json
	$(ASC) index.ts $(ASC_FLAGS) -o $@

build: $(MAIN_WASM)

# Step 3 – compile threat patterns to WASM (two sets in one module)
$(THREAT_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(THREAT_WASM)

# Step 4 – merge main WASM and threat patterns WASM into a single module
$(FINAL_WASM): $(MAIN_WASM) $(THREAT_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(MAIN_WASM) $(THREAT_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with wasmtime
run: $(FINAL_WASM)
	wasmtime run $(FINAL_WASM)

clean:
	rm -f $(STUB) $(MAIN_WASM) $(THREAT_WASM) $(FINAL_WASM)
	rm -rf node_modules package-lock.json
