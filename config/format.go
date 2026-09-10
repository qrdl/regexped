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

	// Sets have their own ABI — the caller-owned gate array, the opaque cursor,
	// the bitmask/bitmap `_all` split — and the stubs, not the WASM, own the
	// drive loop. Lifting that into a stateless component export is real work,
	// deferred to a later phase; refuse it rather than emit half of it.
	if len(cfg.Sets) > 0 {
		return fmt.Errorf("sets are not supported for wasm_format: %s yet", formatComponent)
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
// TWO different messages, deliberately. `rust`/`js`/`ts`/`c` say "yet",
// because their FFI/import shape simply cannot link against a component and a
// later phase replaces the error with a real generator. `go` and `as` say no
// such thing: neither is a component target. Stock Go has no wasip2 target so
// a component stub would have to be TinyGo, which may come later;
// AssemblyScript has no planned route at all.
func validateStubTypeForFormat(cfg *BuildConfig, stubType string) error {
	if !cfg.Component() {
		if stubType == "wit" {
			return fmt.Errorf("stub_type %q requires wasm_format: %s", stubType, formatComponent)
		}
		return nil
	}
	switch stubType {
	case "wit":
		return nil
	case "go", "as":
		return fmt.Errorf("stub type %s is not supported for wasm_format: %s", stubType, formatComponent)
	default:
		return fmt.Errorf("stub type %s is not supported for wasm_format: %s yet", stubType, formatComponent)
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
