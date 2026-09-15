#!/usr/bin/env bash
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)/wasm-merge"

if [ -f "$DEST" ]; then
    echo "wasm-merge already exists, skipping download"
    exit 0
fi

# Follow redirect from /releases/latest to get actual version tag
LOCATION=$(curl -sI https://github.com/WebAssembly/binaryen/releases/latest \
    | grep -i '^location:' \
    | tr -d '\r' \
    | awk '{print $2}')

if [ -z "$LOCATION" ]; then
    echo "error: could not determine latest Binaryen release" >&2
    exit 1
fi

VERSION=$(basename "$LOCATION")   # e.g. version_122
echo "Latest Binaryen release: $VERSION"

ARCH_SUFFIX="x86_64-linux"

TARBALL="binaryen-${VERSION}-${ARCH_SUFFIX}.tar.gz"
URL="https://github.com/WebAssembly/binaryen/releases/download/${VERSION}/${TARBALL}"

echo "Downloading $URL ..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$TARBALL"
tar -xz -f "$TMP/$TARBALL" -C "$TMP" --strip-components=2 "binaryen-${VERSION}/bin/wasm-merge"
mv "$TMP/wasm-merge" "$DEST"
chmod +x "$DEST"

echo "wasm-merge installed to $DEST"
