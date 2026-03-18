#!/usr/bin/env bash
# bench.sh — compile a regex pattern and benchmark it against the regex crate.
#
# Usage:
#   ./bench.sh <name> <pattern> <input1> [input2 ...]
#
# Pattern compilation happens once. Each input gets a separate run reported
# as <name>-1, <name>-2, etc.
# Build/compile progress goes to stderr; only results go to stdout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_TARGET="wasm32-wasip1"

REGEX_WASM="$SCRIPT_DIR/regex_harness/target/$WASM_TARGET/release/regex_harness.wasm"
REGEXPED_WASM="$SCRIPT_DIR/regexped_harness/target/$WASM_TARGET/release/regexped_harness.wasm"

if [ $# -lt 3 ]; then
    echo "Usage: bench.sh <name> <pattern> <input1> [input2 ...]" >&2
    exit 1
fi

NAME="$1"
PATTERN="$2"
shift 2
INPUTS=("$@")

OUTDIR="$SCRIPT_DIR/out/$NAME"
mkdir -p "$OUTDIR"

# ── Build harnesses if not already built ─────────────────────────────────────
if [ ! -f "$REGEX_WASM" ]; then
    echo "==> Building regex_harness..." >&2
    cargo build --manifest-path "$SCRIPT_DIR/regex_harness/Cargo.toml" \
        --target "$WASM_TARGET" --release >&2
fi

if [ ! -f "$REGEXPED_WASM" ]; then
    echo "==> Building regexped_harness..." >&2
    cargo build --manifest-path "$SCRIPT_DIR/regexped_harness/Cargo.toml" \
        --target "$WASM_TARGET" --release >&2
fi

# ── Generate YAML config ──────────────────────────────────────────────────────
# printf '%s' passes PATTERN as the value of %s, so \, $, ', % are all literal.
{
    printf 'wasm_merge: ~/projects/binaryen/bin/wasm-merge\n'
    printf 'output:     %s/regexped.wasm\n' "$OUTDIR"
    printf 'regexes:\n'
    printf '  - wasm_file:     pattern.wasm\n'
    printf '    import_module: pattern\n'
    printf '    stub_file:     stub.rs\n'
    printf '    export_name:   pattern_match\n'
    printf '    func_name:     pattern_match\n'
    printf '    pattern: |-\n'
    printf '      %s\n' "$PATTERN"
} > "$OUTDIR/regexped.yaml"

# ── Compile pattern to WASM ───────────────────────────────────────────────────
echo "==> Compiling pattern '$NAME'..." >&2
(cd "$SCRIPT_DIR" && go run .. compile \
    --config="$OUTDIR/regexped.yaml" \
    --wasm-input="$REGEXPED_WASM" \
    --out-dir="$OUTDIR") >&2

# ── Merge ─────────────────────────────────────────────────────────────────────
echo "==> Merging..." >&2
(cd "$SCRIPT_DIR" && go run .. merge \
    --config="$OUTDIR/regexped.yaml" \
    --output="$OUTDIR/regexped.wasm" \
    "$REGEXPED_WASM" "$OUTDIR/pattern.wasm") >&2

# ── Measure compile time once, show it with every input ──────────────────────
COMPILE=$(wasmtime run "$REGEX_WASM" "$PATTERN" "${INPUTS[0]}" 2>/dev/null | grep -o 'compile: [^[:space:]]*')

echo ""
i=1
for INPUT in "${INPUTS[@]}"; do
    echo "[$NAME-$i] '$INPUT'"
    printf '  regex crate:  %s  ' "$COMPILE"
    wasmtime run "$REGEX_WASM" "$PATTERN" "$INPUT" 2>/dev/null | grep -o 'match:.*'
    printf '  regexped:     '
    wasmtime run "$OUTDIR/regexped.wasm" "$INPUT" 2>/dev/null
    i=$((i+1))
done
