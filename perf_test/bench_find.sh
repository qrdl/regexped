#!/usr/bin/env bash
# bench_find.sh — compile a regex pattern in find mode and benchmark it.
#
# Usage:
#   ./bench_find.sh <name> <pattern> <input1> [input2 ...]
#
# Compares regexped find mode against the regex crate's find().

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_TARGET="wasm32-wasip1"

REGEX_FIND_WASM="$SCRIPT_DIR/regex_find_harness/target/$WASM_TARGET/release/regex_find_harness.wasm"
REGEXPED_FIND_WASM="$SCRIPT_DIR/regexped_find_harness/target/$WASM_TARGET/release/regexped_find_harness.wasm"

if [ $# -lt 3 ]; then
    echo "Usage: bench_find.sh <name> <pattern> <input1> [input2 ...]" >&2
    exit 1
fi

NAME="$1"
PATTERN="$2"
shift 2
INPUTS=("$@")

OUTDIR="$SCRIPT_DIR/out/$NAME"
mkdir -p "$OUTDIR"

# ── Build find harnesses if not already built ─────────────────────────────────
if [ ! -f "$REGEX_FIND_WASM" ]; then
    echo "==> Building regex_find_harness..." >&2
    cargo build --manifest-path "$SCRIPT_DIR/regex_find_harness/Cargo.toml" \
        --target "$WASM_TARGET" --release >&2
fi

if [ ! -f "$REGEXPED_FIND_WASM" ]; then
    echo "==> Building regexped_find_harness..." >&2
    cargo build --manifest-path "$SCRIPT_DIR/regexped_find_harness/Cargo.toml" \
        --target "$WASM_TARGET" --release >&2
fi

# ── Generate YAML config (find mode) ─────────────────────────────────────────
{
    printf 'wasm_merge: ~/projects/binaryen/bin/wasm-merge\n'
    printf 'output:     %s/regexped.wasm\n' "$OUTDIR"
    printf 'regexes:\n'
    printf '  - wasm_file:     pattern.wasm\n'
    printf '    import_module: pattern\n'
    printf '    stub_file:     stub.rs\n'
    printf '    export_name:   pattern_find\n'
    printf '    func_name:     pattern_find\n'
    printf '    mode:          find\n'
    printf '    pattern: |-\n'
    printf '      %s\n' "$PATTERN"
} > "$OUTDIR/regexped.yaml"

# ── Compile pattern to WASM (find mode) ──────────────────────────────────────
echo "==> Compiling pattern '$NAME' (find mode)..." >&2
(cd "$SCRIPT_DIR" && go run .. compile \
    --config="$OUTDIR/regexped.yaml" \
    --wasm-input="$REGEXPED_FIND_WASM" \
    --out-dir="$OUTDIR") >&2

# ── Merge ─────────────────────────────────────────────────────────────────────
echo "==> Merging..." >&2
(cd "$SCRIPT_DIR" && go run .. merge \
    --config="$OUTDIR/regexped.yaml" \
    --output="$OUTDIR/regexped.wasm" \
    "$REGEXPED_FIND_WASM" "$OUTDIR/pattern.wasm") >&2

# ── Benchmark ────────────────────────────────────────────────────────────────
COMPILE=$(wasmtime run "$REGEX_FIND_WASM" "$PATTERN" "${INPUTS[0]}" 2>/dev/null | grep -o 'compile: [^[:space:]]*')

echo ""
i=1
for INPUT in "${INPUTS[@]}"; do
    echo "[$NAME-$i] '$INPUT'"
    printf '  regex crate:  %s  ' "$COMPILE"
    wasmtime run "$REGEX_FIND_WASM" "$PATTERN" "$INPUT" 2>/dev/null | grep -o 'find:.*'
    printf '  regexped:     '
    wasmtime run "$OUTDIR/regexped.wasm" "$INPUT" 2>/dev/null
    i=$((i+1))
done
