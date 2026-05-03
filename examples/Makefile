WASMTIME_RUST := wasmtime/rust/url-ipv6 wasmtime/rust/secrets
WASMTIME_GO   := wasmtime/go/csv wasmtime/go/sql-injection wasmtime/go/secret-scanner
WASMTIME_C    := wasmtime/c/url-parts
WASMTIME_AS   := wasmtime/as/find-email
WASMTIME      := $(WASMTIME_RUST) $(WASMTIME_GO) $(WASMTIME_C) $(WASMTIME_AS)
FASTEDGE      := fastedge/validate fastedge/url-guard
OTHER         := browser node workers

.PHONY: all clean $(WASMTIME) $(OTHER)

all: $(WASMTIME) $(FASTEDGE) $(OTHER)

$(WASMTIME) $(FASTEDGE) $(OTHER):
	$(MAKE) -C $@

clean:
	for d in $(WASMTIME) $(FASTEDGE) $(OTHER); do $(MAKE) -C $$d clean; done
