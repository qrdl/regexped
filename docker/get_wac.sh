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
# Usage: ./docker/get_wac.sh [arch] [dest]
#
#   arch   amd64 or arm64. Default: this machine's, or amd64 when this machine
#          is neither.
#   dest   where to put it. An existing DIRECTORY gets `wac` appended; anything
#          else is taken as the file to write. Default: alongside this script,
#          i.e. docker/, the build context.
#
# With an EXPLICIT dest the PATH short-circuit is skipped, as in
# get_wasm_tools.sh: the caller wants the release binary at that path. The
# Docker build is that caller — the release asset is a static musl binary, while
# a wac found on the host's PATH (a `cargo install`, say) may be linked against
# the host's glibc, which the image need not match.

set -euo pipefail

. "$(cd "$(dirname "$0")" && pwd)/arch.sh"

ARCH=$(normalise_arch "${1:-}")
DEST=$(resolve_dest "${2:-}" wac "$(dirname "$0")")

if [ -z "${2:-}" ] && command -v wac >/dev/null 2>&1; then
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
echo "Latest wac release: $VERSION ($ARCH)"

case "$ARCH" in
    amd64) ASSET="wac-cli-x86_64-unknown-linux-musl" ;;
    arm64) ASSET="wac-cli-aarch64-unknown-linux-musl" ;;
esac
URL="https://github.com/bytecodealliance/wac/releases/download/${VERSION}/${ASSET}"

echo "Downloading $URL ..."
curl -fsSL "$URL" -o "$DEST"
chmod +x "$DEST"

echo "wac installed to $DEST"
# Only runnable when it was built for THIS machine; a cross-fetched binary is
# for the image, not for here.
if [ "$ARCH" = "$(normalise_arch "")" ]; then
    "$DEST" --version
fi
