#!/usr/bin/env bash
#
# Fetch the `wac` binary, which `regexped merge` shells out to for
# `wasm_format: component` — the composition tool that is to components what
# wasm-merge is to modules.
#
# Modelled on get_wasm_tools.sh, including its "follow the redirect from
# /releases/latest" trick, so neither script pins a version that goes stale.
# Unlike the other two, wac ships the binary itself as the release asset rather
# than a tarball, so there is nothing to unpack.
#
# Usage: ./get_wac.sh [dest-dir]     (default: alongside this script)

set -euo pipefail

DEST_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
DEST="$DEST_DIR/wac"

if command -v wac >/dev/null 2>&1; then
    echo "wac already in PATH ($(command -v wac)), skipping download"
    exit 0
fi
if [ -f "$DEST" ]; then
    echo "wac already exists at $DEST, skipping download"
    exit 0
fi

# Follow redirect from /releases/latest to get the actual version tag.
LOCATION=$(curl -sI https://github.com/bytecodealliance/wac/releases/latest \
    | grep -i '^location:' \
    | tr -d '\r' \
    | awk '{print $2}')

if [ -z "$LOCATION" ]; then
    echo "error: could not determine latest wac release" >&2
    exit 1
fi

VERSION=$(basename "$LOCATION")   # e.g. v0.11.0
echo "Latest wac release: $VERSION"

ASSET="wac-cli-x86_64-unknown-linux-musl"
URL="https://github.com/bytecodealliance/wac/releases/download/${VERSION}/${ASSET}"

echo "Downloading $URL ..."
curl -fsSL "$URL" -o "$DEST"
chmod +x "$DEST"

echo "wac installed to $DEST"
"$DEST" --version
