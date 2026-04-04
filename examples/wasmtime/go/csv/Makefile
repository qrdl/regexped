# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
GO         := go

APP_WASM   := app.wasm
REGEX_WASM := csv_regex.wasm
FINAL_WASM := final.wasm
STUB       := stub.go

.PHONY: all generate build compile merge run clean

all: run

# Step 1 – generate Go stub from config
$(STUB): regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 2 – compile Go source to WASM (wasip1)
$(APP_WASM): main.go $(STUB) go.mod
	GOOS=wasip1 GOARCH=wasm $(GO) build -o $@ .

build: $(APP_WASM)

# Step 3 – compile regex patterns to WASM
$(REGEX_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(REGEX_WASM)

# Step 4 – merge Go WASM and regex WASM into a single module
$(FINAL_WASM): $(APP_WASM) $(REGEX_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(APP_WASM) $(REGEX_WASM)

merge: $(FINAL_WASM)

# Step 5 – run with sample CSV input
run: $(FINAL_WASM)
	@echo "=== parse CSV (find_csv_row + parse_csv_row) ==="
	wasmtime $(FINAL_WASM) < testdata.csv

clean:
	rm -f $(APP_WASM) $(REGEX_WASM) $(FINAL_WASM) $(STUB)
