WASMTIME_RUST := wasmtime/rust/url-validate wasmtime/rust/secrets wasmtime/rust/secret-scanner
WASMTIME_GO   := wasmtime/go/csv wasmtime/go/sql-injection wasmtime/go/secret-scanner
WASMTIME_C    := wasmtime/c/url-parts
WASMTIME_AS   := wasmtime/as/find-email wasmtime/as/inject-scanner
WASMTIME      := $(WASMTIME_RUST) $(WASMTIME_GO) $(WASMTIME_C) $(WASMTIME_AS)
FASTEDGE      := fastedge/validate fastedge/url-guard fastedge/script-detect fastedge/ua-parser fastedge/secret-redact
# browser is LAST: its `make run` serves the page until you press Ctrl-C, so
# everything after it in a top-level `make run` would never run.
OTHER         := node workers browser
EXAMPLES      := $(WASMTIME) $(FASTEDGE) $(OTHER)

# `make`, `make run` and `make clean` here run the SAME target in every example
# directory, in the order above: `make` builds every example, `make run` runs
# every one (workers, fastedge/validate and fastedge/url-guard only say why there
# is nothing to run locally; fastedge/script-detect and fastedge/ua-parser serve
# themselves on port 8080 for a few requests; fastedge/secret-redact runs under
# FastEdge's own runtime in front of a local origin). fastedge/secret-redact
# needs `npm install` in its directory before either: its SDK and test runner
# are npm packages. fastedge/ua-parser needs componentize-go and Go 1.27.1 or
# later (GOTOOLCHAIN=go1.27.3 fetches one).
# `make <dir>` builds one example.
#
# $(FASTEDGE) must be here too: those targets are named after directories that
# EXIST, so without .PHONY make considers them up to date and silently skips
# the recipe — `make all` then reported success having never built them.
.PHONY: all run clean $(EXAMPLES)

all:
	@set -e; for d in $(EXAMPLES); do $(MAKE) -C $$d; done

run:
	@set -e; for d in $(EXAMPLES); do $(MAKE) -C $$d run; done

clean:
	@for d in $(EXAMPLES); do $(MAKE) -C $$d clean; done

$(EXAMPLES):
	$(MAKE) -C $@
