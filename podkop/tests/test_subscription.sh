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

#######################################################################
# v2 features: latency-range filter, fast/slow split, smart auto-update,
# multi-URL collect, dedup, Clash YAML and v2ray JSON detection.
#######################################################################

echo "=== Test 16: detect format — Clash YAML ==="
CLASH_YAML='proxies:
  - {name: NL-1, type: vless, server: a.b.c, port: 443, uuid: deadbeef, network: tcp}
  - {name: DE-2, type: trojan, server: d.e.f, port: 443, password: pw}
'
fmt="$(subscription_detect_format "$CLASH_YAML")"
[ "$fmt" = "clash" ] && ok "clash detected" || nope "got '$fmt'"

echo "=== Test 17: detect format — v2ray outbound JSON ==="
V2RAY_JSON='{
  "outbounds": [
    {
      "tag": "v2-NL-1",
      "protocol": "vless",
      "settings": {
        "vnext": [{"address": "a.b.c", "port": 443, "users": [{"id": "deadbeef", "encryption": "none", "flow": ""}]}]
      },
      "streamSettings": {"network": "tcp", "security": "none"}
    }
  ]
}'
fmt="$(subscription_detect_format "$V2RAY_JSON")"
[ "$fmt" = "v2ray" ] && ok "v2ray detected" || nope "got '$fmt'"

echo "=== Test 18: parse v2ray JSON -> json line ==="
parsed="$(subscription_parse "$V2RAY_JSON" v2ray)"
echo "$parsed" | grep -q '^json {' && ok "v2ray->json line" || nope "no json"
echo "$parsed" | grep -q '"tag":"v2-NL-1"' && ok "v2ray tag preserved" || nope "tag missing"
echo "$parsed" | grep -q '"server":"a.b.c"' && ok "v2ray server" || nope "server"

echo "=== Test 19: detect format ordering — sing-box vs v2ray ==="
# A sing-box JSON also has .outbounds; ensure detection still picks sing-box
# when route/inbounds are present.
SB_FULL='{"outbounds":[{"type":"vless","tag":"x","server":"a.b","server_port":443}],"route":{"rules":[]}}'
[ "$(subscription_detect_format "$SB_FULL")" = "sing-box" ] && ok "sing-box wins over v2ray" \
    || nope "got '$(subscription_detect_format "$SB_FULL")'"

echo "=== Test 20: smart auto-update — no streak yet → 1h baseline ==="
_uci_x_subscription_update_interval="auto"
[ "$(subscription_resolve_interval "x" "0" "")" = "1h" ] && ok "default 1h" || nope ""

echo "=== Test 21: smart auto-update — 7 unchanged → coarsen tier ==="
[ "$(subscription_resolve_interval "x" "7" "10m")" = "1h" ] && ok "10m → 1h" || nope ""
[ "$(subscription_resolve_interval "x" "7" "1h")"  = "6h" ] && ok "1h → 6h" || nope ""
[ "$(subscription_resolve_interval "x" "7" "6h")"  = "1d" ] && ok "6h → 1d" || nope ""
[ "$(subscription_resolve_interval "x" "12" "1d")" = "1d" ] && ok "1d stays" || nope ""

echo "=== Test 22: smart auto-update — change → tighten tier ==="
[ "$(subscription_resolve_interval "x" "0" "1d")" = "6h" ] && ok "1d → 6h" || nope ""
[ "$(subscription_resolve_interval "x" "0" "6h")" = "1h" ] && ok "6h → 1h" || nope ""
[ "$(subscription_resolve_interval "x" "0" "1h")" = "10m" ] && ok "1h → 10m" || nope ""
[ "$(subscription_resolve_interval "x" "0" "10m")" = "10m" ] && ok "10m floor" || nope ""

echo "=== Test 23: smart auto-update — mid-streak holds tier ==="
[ "$(subscription_resolve_interval "x" "3" "6h")" = "6h" ] && ok "streak=3 hold" || nope ""

echo "=== Test 23b: smart auto-update — non-auto config returns configured ==="
_uci_x_subscription_update_interval="6h"
[ "$(subscription_resolve_interval "x" "7" "10m")" = "6h" ] && ok "explicit 6h wins" || nope ""
unset _uci_x_subscription_update_interval

echo "=== Test 24: meta read/write — 7-field ==="
META="$WORK/m.meta"
subscription_meta_write "$META" "12345" "10" "plain" "ok" "abc123" "5" "1h"
read_back="$(subscription_meta_read "$META")"
echo "$read_back" | awk -F'\t' '{print $5"|"$6"|"$7}' | grep -q "^abc123|5|1h$" \
    && ok "round-trip 7 fields" || nope "got: $read_back"

echo "=== Test 25: meta read — legacy 4-field is tolerated ==="
printf '999\t5\tplain\tok\n' > "$META"
read_back="$(subscription_meta_read "$META")"
echo "$read_back" | awk -F'\t' '{print $1"|"$2"|"$3"|"$4"|"$6}' | grep -q "^999|5|plain|ok|0$" \
    && ok "legacy meta + streak default" || nope "got: $read_back"

echo "=== Test 26: subscription_collect_urls — legacy single ==="
_uci_secA_subscription_url="https://a.example/sub1"
unset _uci_secA_subscription_urls
got="$(subscription_collect_urls secA | tr '\n' '|')"
[ "$got" = "https://a.example/sub1|" ] && ok "single URL" || nope "got '$got'"

echo "=== Test 27: subscription_collect_urls — list only ==="
unset _uci_secB_subscription_url
_uci_secB_subscription_urls="https://b1.example|https://b2.example"
got="$(subscription_collect_urls secB | tr '\n' '|')"
[ "$got" = "https://b1.example|https://b2.example|" ] && ok "two URLs" || nope "got '$got'"

echo "=== Test 28: subscription_collect_urls — single + list combined ==="
_uci_secC_subscription_url="https://c0.example"
_uci_secC_subscription_urls="https://c1.example|https://c2.example"
got="$(subscription_collect_urls secC | wc -l | tr -d ' ')"
[ "$got" = "3" ] && ok "3 URLs combined" || nope "got '$got'"

echo "=== Test 29: dedup — same tag+endpoint kept once ==="
DUP="$WORK/dup.parsed"
cat > "$DUP" <<'EOF'
url vless://u@h.example:443?#NL-1
url vless://u@h.example:443?#NL-1
url vless://u@h2.example:443?#NL-1
url vless://u@h.example:443?#DE-1
EOF
deduped="$(_subscription_dedup_parsed "$DUP")"
n="$(echo "$deduped" | wc -l)"
# Expect: NL-1@h, NL-1@h2, DE-1@h  → 3 lines
[ "$n" = "3" ] && ok "dedup keeps 3" || nope "got $n: $deduped"

echo "=== Test 30: latency lookup — exact match ==="
LF="$WORK/lat"
printf 'NL-1\t45\nDE-2\t180\nRU-3\t-1\n' > "$LF"
[ "$(subscription_lookup_latency "$LF" "NL-1")" = "45" ] && ok "lookup NL-1=45" || nope ""
[ "$(subscription_lookup_latency "$LF" "DE-2")" = "180" ] && ok "lookup DE-2=180" || nope ""
[ "$(subscription_lookup_latency "$LF" "RU-3")" = "-1" ] && ok "lookup RU-3=-1" || nope ""
[ "$(subscription_lookup_latency "$LF" "missing")" = "" ] && ok "lookup absent=empty" || nope ""

echo "=== Test 31: ping range filter — min only ==="
PF3="$WORK/pf3"
cat > "$PF3" <<'EOF'
url vless://u@a:1#NL-1
url vless://u@b:2#DE-2
url vless://u@c:3#RU-3
EOF
out="$(subscription_apply_filter "$PF3" "" "" "$LF" 100 0)"
# NL-1=45 dropped (<100); DE-2=180 kept; RU-3=-1 kept (no measurement yet)
[ "$(echo "$out" | wc -l)" = "2" ] && ok "min=100 → 2 left" || nope "got $(echo "$out" | wc -l): $out"
echo "$out" | grep -q "NL-1" && nope "NL-1 should be excluded" || ok "NL-1 dropped"

echo "=== Test 32: ping range filter — max only ==="
out="$(subscription_apply_filter "$PF3" "" "" "$LF" 0 150)"
# NL-1=45 kept; DE-2=180 dropped; RU-3=-1 kept (passthrough)
[ "$(echo "$out" | wc -l)" = "2" ] && ok "max=150 → 2 left" || nope "got $(echo "$out" | wc -l): $out"
echo "$out" | grep -q "DE-2" && nope "DE-2 should be dropped" || ok "DE-2 dropped"

echo "=== Test 33: ping range filter — min+max range ==="
out="$(subscription_apply_filter "$PF3" "" "" "$LF" 50 200)"
# NL-1=45 dropped; DE-2=180 kept; RU-3=-1 kept
[ "$(echo "$out" | wc -l)" = "2" ] && ok "[50,200] → 2 left" || nope "got $(echo "$out" | wc -l)"

echo "=== Test 34: ping range filter — empty cache passes all ==="
out="$(subscription_apply_filter "$PF3" "" "" "" 100 200)"
[ "$(echo "$out" | wc -l)" = "3" ] && ok "no latency file → no filter" || nope ""

echo "=== Test 35: load_filtered modes — all/raw ==="
mkdir -p "$WORK/cache"
SUBSCRIPTION_CACHE_DIR="$WORK/cache"
mv "$PF3" "$WORK/cache/secD.parsed"
unset _uci_secD_subscription_filters _uci_secD_subscription_exclude
unset _uci_secD_subscription_ping_min _uci_secD_subscription_ping_max
n_all="$(subscription_load_filtered secD all | wc -l)"
n_raw="$(subscription_load_filtered secD raw | wc -l)"
[ "$n_all" = "3" ] && ok "all=3" || nope "all=$n_all"
[ "$n_raw" = "3" ] && ok "raw=3" || nope "raw=$n_raw"
SUBSCRIPTION_CACHE_DIR="$WORK"

echo "=== Test 36: HTTP URL accepted by detect+parse pipeline ==="
# fetch_format is decoupled — just confirm detection works on plain text
# returned by an http:// panel.
PLAIN='vless://u@a:1#x'
[ "$(subscription_detect_format "$PLAIN")" = "plain" ] && ok "http body plain" || nope ""

echo "=== Test 37: filter regex special chars are literal ==="
PF4="$WORK/pf4"
cat > "$PF4" <<'EOF'
url vless://u@a:1#a.b
url vless://u@a:1#axb
EOF
out="$(subscription_apply_filter "$PF4" "a.b" "")"
n="$(echo "$out" | wc -l)"
[ "$n" = "1" ] && ok "literal dot only matches a.b" || nope "got $n: $out"

echo "=== Test 38: cache path helpers ==="
SUBSCRIPTION_CACHE_DIR="$WORK"
[ "$(subscription_cache_path_raw foo)"     = "$WORK/foo.raw" ]     && ok "raw path" || nope ""
[ "$(subscription_cache_path_parsed foo)"  = "$WORK/foo.parsed" ]  && ok "parsed path" || nope ""
[ "$(subscription_cache_path_meta foo)"    = "$WORK/foo.meta" ]    && ok "meta path" || nope ""
[ "$(subscription_cache_path_latency foo)" = "$WORK/foo.latency" ] && ok "latency path" || nope ""

echo "=== Test 39: Clash YAML parsing (skipped if python3-yaml absent) ==="
if python3 -c 'import yaml' 2>/dev/null; then
    parsed="$(subscription_parse "$CLASH_YAML" clash)"
    n="$(echo "$parsed" | wc -l)"
    [ "$n" = "2" ] && ok "clash → 2 outbounds" || nope "got $n: $parsed"
    echo "$parsed" | grep -q '"tag":"NL-1"' && ok "clash tag preserved" || nope "no NL-1 tag"
else
    echo "  SKIP: python3-yaml not available"
fi

echo
echo "=================="
echo "PASSED: $pass"
echo "FAILED: $fail"
echo "=================="
[ "$fail" -eq 0 ]
