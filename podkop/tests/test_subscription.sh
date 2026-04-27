#!/bin/ash
# Standalone tests for subscription.sh — run in a regular Linux shell.
# We stub out the parts of helpers.sh / logging.sh that subscription.sh
# uses so we can test in isolation.

set -e

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
LIB="$REPO_ROOT/podkop/files/usr/lib"

# Minimal stubs.
log() { echo "[log:${2:-info}] $1" >&2; }

# url helpers from helpers.sh
url_decode() {
    local encoded="$1"
    printf '%b' "$(echo "$encoded" | sed 's/+/ /g; s/%/\\x/g')"
}
url_get_host() {
    local url="$1"
    url="${url#*://}"
    url="${url#*@}"
    url="${url%%[/?#]*}"
    echo "${url%%:*}"
}
url_get_port() {
    local url="$1"
    url="${url#*://}"
    url="${url#*@}"
    url="${url%%[/?#]*}"
    case "$url" in
        *:*) echo "${url#*:}" ;;
        *)   echo "" ;;
    esac
}

# UCI stubs — we feed values directly via shell variables in tests.
config_list_foreach() {
    local section="$1" option="$2"
    local var
    eval "var=\$_uci_${section}_${option}"
    [ -z "$var" ] && return
    local IFS='|'
    for v in $var; do
        # shellcheck disable=SC2086
        $3 "$v"
    done
}
config_get() {
    local var="$1" section="$2" option="$3" default="$4"
    eval "$var=\${_uci_${section}_${option}-\$default}"
}

. "$LIB/subscription.sh"

WORK="$(mktemp -d)"
SUBSCRIPTION_CACHE_DIR="$WORK"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()    { pass=$((pass+1)); echo "  PASS: $1"; }
nope()  { fail=$((fail+1)); echo "  FAIL: $1"; }

echo "=== Test 1: detect format — sing-box JSON ==="
SB_JSON='{"outbounds":[{"type":"vless","tag":"NL-1","server":"a.b","server_port":443}]}'
fmt="$(subscription_detect_format "$SB_JSON")"
[ "$fmt" = "sing-box" ] && ok "sing-box detected" || nope "got '$fmt'"

echo "=== Test 2: detect format — base64 ==="
LINKS='vless://uuid@host:443?type=tcp#NL-Server
ss://Y2hhY2hhMjA6cGFzcw==@host:8388#RU-Moscow'
B64="$(printf '%s' "$LINKS" | base64 -w0)"
fmt="$(subscription_detect_format "$B64")"
[ "$fmt" = "base64" ] && ok "base64 detected" || nope "got '$fmt'"

echo "=== Test 3: detect format — plain ==="
fmt="$(subscription_detect_format "$LINKS")"
[ "$fmt" = "plain" ] && ok "plain detected" || nope "got '$fmt'"

echo "=== Test 4: parse base64 ==="
parsed="$(subscription_parse "$B64" base64)"
n=$(echo "$parsed" | wc -l)
[ "$n" = "2" ] && ok "parsed 2 lines" || nope "got $n"
echo "$parsed" | grep -q "^url vless://" && ok "vless line present" || nope "no vless"

echo "=== Test 5: parse sing-box JSON ==="
parsed="$(subscription_parse "$SB_JSON" sing-box)"
n=$(echo "$parsed" | wc -l)
[ "$n" = "1" ] && ok "parsed 1 outbound" || nope "got $n"
echo "$parsed" | grep -q '^json {' && ok "json line present" || nope "no json"

echo "=== Test 6: filter by RU keyword ==="
PF="$WORK/parsed1"
echo "$LINKS" | sed 's#^#url #' > "$PF"
US="$(printf '\037')"
out="$(subscription_apply_filter "$PF" "RU" "")"
[ "$(echo "$out" | wc -l)" = "1" ] && ok "1 RU match" || nope "$out"

echo "=== Test 7: filter SE|RU OR ==="
out="$(subscription_apply_filter "$PF" "SE|RU" "")"
[ "$(echo "$out" | wc -l)" = "1" ] && ok "OR works" || nope "$(echo "$out" | wc -l)"

echo "=== Test 8: filter NL|RU OR — both match ==="
out="$(subscription_apply_filter "$PF" "NL|RU" "")"
[ "$(echo "$out" | wc -l)" = "2" ] && ok "both match" || nope "$(echo "$out" | wc -l)"

echo "=== Test 9: filter exclude ==="
out="$(subscription_apply_filter "$PF" "" "Moscow")"
[ "$(echo "$out" | wc -l)" = "1" ] && ok "exclude Moscow" || nope ""

echo "=== Test 10: filter — country flag emoji ==="
LINKS_FLAG='vless://uuid@a.b:443#🇩🇪 Berlin
vless://uuid@a.b:443#🇳🇱 Amsterdam
vless://uuid@a.b:443#🇷🇺 Moscow'
PF2="$WORK/parsed2"
echo "$LINKS_FLAG" | sed 's#^#url #' > "$PF2"
out="$(subscription_apply_filter "$PF2" "🇩🇪" "")"
[ "$(echo "$out" | wc -l)" = "1" ] && ok "DE flag matches" || nope "got $(echo "$out" | wc -l) lines"
out="$(subscription_apply_filter "$PF2" "🇩🇪|🇳🇱" "")"
[ "$(echo "$out" | wc -l)" = "2" ] && ok "DE|NL flags match" || nope "got $(echo "$out" | wc -l) lines"

echo "=== Test 11: empty filter -> all ==="
out="$(subscription_apply_filter "$PF" "" "")"
[ "$(echo "$out" | wc -l)" = "2" ] && ok "all pass" || nope ""

echo "=== Test 12: tag extraction url ==="
tag="$(subscription_line_get_tag 'url vless://u@h:1#NL%20Server%201')"
[ "$tag" = "NL Server 1" ] && ok "url tag decoded" || nope "got '$tag'"

echo "=== Test 13: tag extraction json ==="
tag="$(subscription_line_get_tag 'json {"type":"vless","tag":"DE-3","server":"x","server_port":443}')"
[ "$tag" = "DE-3" ] && ok "json tag" || nope "got '$tag'"

echo "=== Test 14: filter_match no metachars ==="
subscription_filter_match "RU.Moscow" "RU.Moscow" && ok "literal dot" || nope ""
subscription_filter_match "RUxMoscow" "RU.Moscow" && nope "should not match wildcards" || ok "no wildcard expansion"

echo "=== Test 15: UA selection ==="
[ "$(subscription_user_agent_for auto sing-box)" = "SFA/1.11.9" ] && ok "auto+sb=SFA" || nope ""
[ "$(subscription_user_agent_for auto base64)" = "podkop" ] && ok "auto+b64=podkop" || nope ""
[ "$(subscription_user_agent_for sing-box auto)" = "SFA/1.11.9" ] && ok "explicit sb" || nope ""
[ "$(subscription_user_agent_for "MyCustom/1.0" auto)" = "MyCustom/1.0" ] && ok "custom UA" || nope ""

echo
echo "=================="
echo "PASSED: $pass"
echo "FAILED: $fail"
echo "=================="
[ "$fail" -eq 0 ]
