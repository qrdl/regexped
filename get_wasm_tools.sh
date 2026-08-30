#!/usr/bin/env bash
#
# Fetch the `wasm-tools` binary, which several tests use to VALIDATE the
# modules the compiler emits.
#
# That validation is not redundant with the Go test suite: a module with a
# call to a non-existent function index, a mismatched local count or a bad
# section length is well-formed as far as our emitters are concerned and only
# fails when a runtime loads it. wasm-tools is what turns that into a test
# failure. The tests SKIP when it is missing, so an environment without it
# runs green while checking nothing — which is why CI installs it explicitly.
#
# Modelled on get_wasm_merge.sh, including its "follow the redirect from
# /releases/latest" trick, so neither script pins a version that goes stale.
#
# Usage: ./get_wasm_tools.sh [dest-dir]     (default: alongside this script)

set -euo pipefail

DEST_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
DEST="$DEST_DIR/wasm-tools"

if command -v wasm-tools >/dev/null 2>&1; then
    echo "wasm-tools already in PATH ($(command -v wasm-tools)), skipping download"
    exit 0
fi
if [ -f "$DEST" ]; then
    echo "wasm-tools already exists at $DEST, skipping download"
    exit 0
fi

# Follow redirect from /releases/latest to get the actual version tag.
LOCATION=$(curl -sI https://github.com/bytecodealliance/wasm-tools/releases/latest \
    | grep -i '^location:' \
    | tr -d '\r' \
    | awk '{print $2}')

if [ -z "$LOCATION" ]; then
    echo "error: could not determine latest wasm-tools release" >&2
    exit 1
fi

VERSION=$(basename "$LOCATION")   # e.g. v1.239.0
echo "Latest wasm-tools release: $VERSION"

ARCH_SUFFIX="x86_64-linux"
# The tarball drops the leading `v`: v1.239.0 -> wasm-tools-1.239.0-...
STEM="wasm-tools-${VERSION#v}-${ARCH_SUFFIX}"
TARBALL="${STEM}.tar.gz"
URL="https://github.com/bytecodealliance/wasm-tools/releases/download/${VERSION}/${TARBALL}"

echo "Downloading $URL ..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$TARBALL"
tar -xz -f "$TMP/$TARBALL" -C "$TMP" --strip-components=1 "${STEM}/wasm-tools"
mv "$TMP/wasm-tools" "$DEST"
chmod +x "$DEST"

echo "wasm-tools installed to $DEST"
"$DEST" --version
