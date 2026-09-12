package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// validateFormat checks wasm_format and the keys that only mean something
// under it. It runs from LoadConfig, so both `compile` and `generate` see the
// same verdict — which is the whole reason the output kind is a config key and
// not a CLI flag.
//
// warnf receives non-fatal diagnostics; LoadConfig passes a stderr writer.
func validateFormat(cfg *BuildConfig, warnf func(string, ...any)) error {
	switch cfg.WasmFormat {
	case "", formatModule, formatComponent:
	default:
		return fmt.Errorf("unknown wasm_format %q (expected %q or %q)",
			cfg.WasmFormat, formatModule, formatComponent)
	}

	if cfg.WitVersion != "" {
		if err := validateSemver(cfg.WitVersion); err != nil {
			return fmt.Errorf("wit_version %q %v", cfg.WitVersion, err)
		}
		// Inert under `module`: there is no WIT, no package and no export name
		// to put a version into. WARN rather than fail — a usable module is
		// still produced, so failing the build is disproportionate — but never
		// stay silent: the user believes they versioned their interface, and
		// since adding a version is a breaking change for consumers they would
		// otherwise learn the truth from downstream.
		if !cfg.Component() {
			warnf("warning: wit_version %q is ignored for wasm_format: %s (it only applies to components)",
				cfg.WitVersion, formatModule)
		}
	}

	if !cfg.Component() {
		// wit_package / wit_world are equally inert; same reasoning.
		for _, k := range []struct{ field, value string }{
			{"wit_package", cfg.WitPackage},
			{"wit_world", cfg.WitWorld},
		} {
			if k.value != "" {
				warnf("warning: %s %q is ignored for wasm_format: %s (it only applies to components)",
					k.field, k.value, formatModule)
			}
		}
		return nil
	}

	// ---- component only, from here down.

	// Sets ARE supported as of phase 3.2. Their raw ABI — the caller-owned gate
	// array, the bitmask/bitmap `_all` split — does not cross the component
	// boundary: `_all` lifts to a list of ids, and `find` becomes a resource
	// that owns the drive. One thing is still refused, below.
	//
	// `hints: [batch-find]` has no component form. Batching amortises host
	// crossings for a caller that intends to consume everything, and it is
	// declared on the SET, so it cannot be silently ignored the way an inert
	// key can: the user asked for a second entry point that the component
	// interface does not expose.
	for _, s := range cfg.Sets {
		for _, h := range s.Hints {
			if h == "batch-find" {
				return fmt.Errorf("set %q: hints: [batch-find] is not supported for wasm_format: %s — the component interface exposes one position per call through the find resource",
					s.Name, formatComponent)
			}
		}
	}

	// The name is REQUIRED here: it becomes the WIT package, the world, and
	// the package prefix of every canonical export name. There is no filename
	// fallback as there is for `merge`, and no default is invented — an empty
	// one would reach wasm-tools as `package regexped:;` and fail there, which
	// is a tool error where a config error belongs.
	if cfg.ImportModule == "" && cfg.WitPackage == "" {
		return fmt.Errorf("import_module (or wit_package) is required for wasm_format: %s: it names the WIT package, the world, and every export", formatComponent)
	}
	// Surface an unrepresentable name now, by the key the user must edit,
	// rather than at the wasm-tools call.
	if _, err := cfg.WitPackageName(); err != nil {
		return err
	}
	if _, err := cfg.WitWorldName(); err != nil {
		return err
	}
	return nil
}

// validateStubTypeForFormat rejects the stub types that cannot be generated
// for the configured output kind.
//
// ONE message, not two. Until phase 2 there was a second one ending in "yet",
// for types that were merely deferred; after it shipped there are none, and the
// arm that produced it was unreachable — ResolveStubType returns exactly one of
// the seven known types or an error, and all seven are named below. It was
// removed rather than left as a message no config could produce.
//
// `rust` and `c` are SUPPORTED as of 2026-09-10 — see
// generate/rust_component_stub.go and generate/c_component_stub.go. They reach
// the metadata a component consumer needs by different routes, because their
// builds differ: Rust links the component in one step and needs the metadata
// present, so its stub carries `wit_bindgen::generate!`; C builds a plain core
// module, so the metadata is attached afterwards by `wasm-tools component embed`
// and its stub needs no third-party dependency at all.
//
// `go`, `as`, `js` and `ts` say no such thing, because none of them is a
// component target. Stock Go has no wasip2 target, so a Go component stub would
// have to be TinyGo — possible later. AssemblyScript has no planned route. JS
// and TS are excluded on VALUE rather than feasibility: no JavaScript runtime
// loads a component (`WebAssembly.instantiate` implements the core module
// format only), so a transpiler is mandatory, and `jco transpile` produces a
// core module plus glue — which is exactly where `wasm_format: module` starts.
// A JS user would pay a tool and a build step to arrive where they already are.
func validateStubTypeForFormat(cfg *BuildConfig, stubType string) error {
	if !cfg.Component() {
		if stubType == "wit" {
			return fmt.Errorf("stub_type %q requires wasm_format: %s", stubType, formatComponent)
		}
		return nil
	}
	switch stubType {
	case "wit", "rust", "c":
		return nil
	default:
		// go, as, js, ts — see above for why each is permanent.
		return fmt.Errorf("stub type %s is not supported for wasm_format: %s", stubType, formatComponent)
	}
}

// validateSemver accepts exactly `MAJOR.MINOR.PATCH` of digits. Anything
// richer (pre-release, build metadata) is refused rather than half-supported:
// the value lands inside every export name, so a form the toolchain parses
// differently from us is a silent mismatch.
func validateSemver(v string) error {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return fmt.Errorf("is not a semver triple (expected MAJOR.MINOR.PATCH)")
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("has an empty component (expected MAJOR.MINOR.PATCH)")
		}
		if _, err := strconv.ParseUint(p, 10, 32); err != nil {
			return fmt.Errorf("has the non-numeric component %q (expected MAJOR.MINOR.PATCH)", p)
		}
	}
	return nil
}

// warnToStderr is LoadConfig's warnf.
func warnToStderr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
