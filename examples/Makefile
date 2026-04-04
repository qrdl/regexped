WASMTIME_RUST := wasmtime/rust/url-ipv6 wasmtime/rust/secrets
WASMTIME_GO   := wasmtime/go/csv wasmtime/go/sql-injection
WASMTIME_C    := wasmtime/c/url-parts
WASMTIME      := $(WASMTIME_RUST) $(WASMTIME_GO) $(WASMTIME_C)
OTHER         := browser node workers

.PHONY: all clean $(WASMTIME) $(OTHER)

all: $(WASMTIME) $(OTHER)

$(WASMTIME) $(OTHER):
	$(MAKE) -C $@

clean:
	for d in $(WASMTIME) $(OTHER); do $(MAKE) -C $$d clean; done
