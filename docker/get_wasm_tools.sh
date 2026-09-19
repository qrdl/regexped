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
# Usage: ./docker/get_wasm_tools.sh [arch] [dest]
#
#   arch   amd64 or arm64. Default: this machine's, or amd64 when this machine
#          is neither.
#   dest   where to put it. An existing DIRECTORY gets `wasm-tools` appended;
#          anything else is taken as the file to write. Default: alongside this
#          script, i.e. docker/, the build context.
#
# With an EXPLICIT dest the PATH short-circuit is skipped: the caller wants the
# release binary at that path. The Docker build is that caller — a wasm-tools
# found on the host's PATH may be linked against the host's glibc, which the
# image does not carry, so copying it in builds an image whose wasm-tools does
# not start.
#
# The file name matters for the image: a multi-platform `docker buildx` build
# shares ONE context between the per-architecture builds, so both binaries have
# to sit in docker/ at once and the Dockerfile picks with TARGETARCH. That is
# why release.yml asks for `docker/wasm-tools-amd64` and `-arm64` by name,
# while ci.yml, which only wants one on PATH, keeps passing a directory.

set -euo pipefail

. "$(cd "$(dirname "$0")" && pwd)/arch.sh"

ARCH=$(normalise_arch "${1:-}")
DEST=$(resolve_dest "${2:-}" wasm-tools "$(dirname "$0")")

if [ -z "${2:-}" ] && command -v wasm-tools >/dev/null 2>&1; then
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
echo "Latest wasm-tools release: $VERSION ($ARCH)"

case "$ARCH" in
    amd64) ARCH_SUFFIX="x86_64-linux" ;;
    arm64) ARCH_SUFFIX="aarch64-linux" ;;
esac
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
# Only runnable when it was built for THIS machine — which means the OS as well
# as the CPU. Every asset above is a LINUX binary, so on macOS the architectures
# can match while the binary still cannot execute, and `set -e` would abort the
# fetch (and `make docker`) right after a successful download.
if [ "$(uname -s)" = "Linux" ] && [ "$ARCH" = "$(normalise_arch "")" ]; then
    "$DEST" --version
fi
