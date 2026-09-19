#!/usr/bin/env bash
#
# Fetch the `wasm-merge` binary, which `regexped merge` shells out to for
# `wasm_format: module`.
#
# Usage: ./docker/get_wasm_merge.sh [arch] [dest]
#
#   arch   amd64 or arm64. Default: this machine's, or amd64 when this machine
#          is neither.
#   dest   where to put it. An existing DIRECTORY gets `wasm-merge` appended;
#          anything else is taken as the file to write. Default: alongside this
#          script, i.e. docker/, the build context.
#
# The file name matters for the image. A multi-platform `docker buildx` build
# shares ONE context between the per-architecture builds, so both binaries have
# to sit in docker/ at once and the Dockerfile picks with TARGETARCH — which is
# why release.yml asks for `docker/wasm-merge-amd64` and `-arm64` by name,
# while ci.yml, which only wants one on PATH, keeps passing a directory.

set -euo pipefail

. "$(cd "$(dirname "$0")" && pwd)/arch.sh"

ARCH=$(normalise_arch "${1:-}")
DEST=$(resolve_dest "${2:-}" wasm-merge "$(dirname "$0")")

if [ -f "$DEST" ]; then
    echo "wasm-merge already exists at $DEST, skipping download"
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
echo "Latest Binaryen release: $VERSION ($ARCH)"

case "$ARCH" in
    amd64) ARCH_SUFFIX="x86_64-linux" ;;
    arm64) ARCH_SUFFIX="aarch64-linux" ;;
esac

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
