WASMTIME_RUST := wasmtime/rust/url-ipv6 wasmtime/rust/secrets wasmtime/rust/secret-scanner
WASMTIME_GO   := wasmtime/go/csv wasmtime/go/sql-injection wasmtime/go/secret-scanner
WASMTIME_C    := wasmtime/c/url-parts
WASMTIME_AS   := wasmtime/as/find-email wasmtime/as/inject-scanner
WASMTIME      := $(WASMTIME_RUST) $(WASMTIME_GO) $(WASMTIME_C) $(WASMTIME_AS)
FASTEDGE      := fastedge/validate fastedge/url-guard
OTHER         := browser node workers

# $(FASTEDGE) must be here too: those targets are named after directories that
# EXIST, so without .PHONY make considers them up to date and silently skips
# the recipe — `make all` then reported success having never built them.
.PHONY: all clean $(WASMTIME) $(FASTEDGE) $(OTHER)

all: $(WASMTIME) $(FASTEDGE) $(OTHER)

$(WASMTIME) $(FASTEDGE) $(OTHER):
	$(MAKE) -C $@

clean:
	for d in $(WASMTIME) $(FASTEDGE) $(OTHER); do $(MAKE) -C $$d clean; done
