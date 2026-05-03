# regexped must be built first: run `make` in the repo root.
REGEXPED   := ../../../../regexped
GO         := go

APP_WASM   := app.wasm
SECRET_WASM := secrets.wasm
FINAL_WASM := final.wasm
STUB       := stub.go

.PHONY: all generate build compile merge run clean

all: merge

# Step 1 – generate Go stub from config
$(STUB): regexped.yaml
	$(REGEXPED) generate --config=regexped.yaml

generate: $(STUB)

# Step 2 – compile Go source to WASM (wasip1)
$(APP_WASM): main.go $(STUB) go.mod
	GOOS=wasip1 GOARCH=wasm $(GO) build -o $@ .

build: $(APP_WASM)

# Step 3 – compile secret patterns to WASM
$(SECRET_WASM): regexped.yaml
	$(REGEXPED) compile --config=regexped.yaml

compile: $(SECRET_WASM)

# Step 4 – merge app WASM and patterns WASM into a single module
$(FINAL_WASM): $(APP_WASM) $(SECRET_WASM) regexped.yaml
	$(REGEXPED) merge --config=regexped.yaml --main=$(APP_WASM) $(SECRET_WASM)

merge: $(FINAL_WASM)

clean:
	rm -f $(APP_WASM) $(SECRET_WASM) $(FINAL_WASM) $(STUB)
