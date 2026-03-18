#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$SCRIPT_DIR/bench.sh"

# ── Test cases ────────────────────────────────────────────────────────────────

EMAIL='[a-zA-Z0-9_%+\-]+(?:\.[a-zA-Z0-9_%+\-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z][a-zA-Z]+'

URL_IPV4='[Hh][Tt][Tt][Pp][Ss]?://(?:[a-zA-Z0-9._~!$&'"'"'()*+,;=:-]+@)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(?:[0-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:[/?#][/a-zA-Z0-9._~!$&'"'"'()*+,;=:@%?#-]*)?'

# IPv6: RFC 4291 pure form (all 8-group compressed variants), wrapped in [] per RFC 3986
URL_IPV6='[Hh][Tt][Tt][Pp][Ss]?://(?:[a-zA-Z0-9._~!$&'"'"'()*+,;=:-]+@)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\[(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::)\]|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(?:[0-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:[/?#][/a-zA-Z0-9._~!$&'"'"'()*+,;=:@%?#-]*)?'

# ── Run ───────────────────────────────────────────────────────────────────────

"$BENCH" email "$EMAIL" \
    "user@example.com" \
    "user.name+tag@sub.domain.org" \
    "not-an-email"

echo ""

"$BENCH" url-ipv4 "$URL_IPV4" \
    "https://192.168.1.1:8080/path/to/resource?q=1&r=2#section" \
    "https://user:pass@sub.example.com:8443/path/to/resource?q=1&r=2#section" \
    "https://user:password@sub.domain.example.com:8443/path/to/some/resource/page.html?param1=value1&param2=value2&param3=value3#section-anchor" \
    "not-a-url"

echo ""

"$BENCH" url-ipv6 "$URL_IPV6" \
    "https://user:pass@[2001:db8:85a3::8a2e:370:7334]:8443/path/to/resource?q=1#section" \
    "https://[::1]/path" \
    "https://user:password@sub.domain.example.com:8443/path/to/some/resource/page.html?param1=value1&param2=value2&param3=value3#section-anchor" \
    "not-a-url"
