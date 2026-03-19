#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$SCRIPT_DIR/bench.sh"
BENCH_FIND="$SCRIPT_DIR/bench_find.sh"

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

echo ""

# SQL injection detection: non-anchored find over a ~1KB HTTP request body.
# Pattern matches classic injection forms: ' OR 1=1, ' AND 2=2, UNION SELECT, etc.
SQL_INJECT="'[[:space:]]*(?:OR|AND)[[:space:]]+[0-9]+[[:space:]]*=[[:space:]]*[0-9]+|UNION[[:space:]]+(?:ALL[[:space:]]+)?SELECT|'[[:space:]]*;[[:space:]]*(?:DROP|TRUNCATE)[[:space:]]+TABLE"

# ~1 KB input: safe query prefix + injection payload in the middle + trailing data
SQL_CLEAN="$(printf 'POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=%s&page=1&sort=name&order=asc&limit=20&offset=0&filter=active&category=electronics&brand=acme&minprice=0&maxprice=999&format=json&callback=cb&session=abc123def456&csrf=xyz789&ts=1700000000' "$(python3 -c "print('a'*400)")")"
SQL_INJECT_INPUT="$(printf 'POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=%s&page=1' "$(python3 -c "print('a'*200 + \"' OR 1=1 --\" + 'b'*200)")")"

"$BENCH_FIND" sql-inject "$SQL_INJECT" \
    "$SQL_CLEAN" \
    "$SQL_INJECT_INPUT"
