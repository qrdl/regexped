#!/usr/bin/env bash
#
# Shared argument handling for the three get_*.sh scripts: which architecture
# to fetch, and where to put the result.
#
# Sourced, not executed.

# normalise_arch maps an argument, or this machine, onto amd64 or arm64.
#
# An EMPTY argument means "this machine", and a machine that is neither gets
# amd64 — the only architecture all three upstreams have always shipped, and
# the one the image was built for before it was multi-platform. A machine
# whose own architecture has no release is better served by a binary that runs
# under emulation than by a download that 404s.
normalise_arch() {
    local want="${1:-}"
    if [ -z "$want" ]; then
        case "$(uname -m)" in
            x86_64|amd64)   want=amd64 ;;
            aarch64|arm64)  want=arm64 ;;
            *)              want=amd64 ;;
        esac
    fi
    case "$want" in
        amd64|arm64) printf '%s\n' "$want" ;;
        *) echo "error: unsupported architecture '$want' (want amd64 or arm64)" >&2; return 1 ;;
    esac
}

# resolve_dest turns the caller's destination into the file to write.
#
# An existing DIRECTORY gets the tool name appended, which is what ci.yml means
# by /usr/local/bin and what the Makefile means by docker/. Anything else is
# taken as the file itself, which is how release.yml asks for
# `docker/wasm-tools-arm64`: a multi-platform build shares one context between
# its per-architecture builds, so the two binaries cannot both be called
# `wasm-tools`.
resolve_dest() {
    local dest="${1:-}" tool="$2" fallback_dir="$3"
    if [ -z "$dest" ]; then
        printf '%s\n' "$(cd "$fallback_dir" && pwd)/$tool"
    elif [ -d "$dest" ]; then
        printf '%s\n' "${dest%/}/$tool"
    else
        printf '%s\n' "$dest"
    fi
}

# Run directly rather than sourced, this prints the architecture the same
# defaulting would choose — which is how the Makefile names the files it
# assembles without restating the rule.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    normalise_arch "${1:-}"
fi
