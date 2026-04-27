#!/bin/sh
# End-to-end test: spin up an HTTP server that returns base64-encoded
# subscription, then ask subscription_update_section to fetch + parse + cache.

set -e
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
LIB="$REPO_ROOT/podkop/files/usr/lib"

WORK="$(mktemp -d)"
SUBSCRIPTION_CACHE_DIR="$WORK/cache"
mkdir -p "$SUBSCRIPTION_CACHE_DIR"
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Stubs (same as the unit test).
log() { echo "[log:${2:-info}] $1" >&2; }
url_decode() {
    encoded="$1"
    printf '%b' "$(echo "$encoded" | sed 's/+/ /g; s/%/\\x/g')"
}
url_get_host() {
    url="$1"; url="${url#*://}"; url="${url#*@}"; url="${url%%[/?#]*}"
    echo "${url%%:*}"
}
url_get_port() {
    url="$1"; url="${url#*://}"; url="${url#*@}"; url="${url%%[/?#]*}"
    case "$url" in *:*) echo "${url#*:}" ;; *) echo "" ;; esac
}
config_list_foreach() {
    section="$1"; option="$2"; cb="$3"
    eval "var=\$_uci_${section}_${option}"
    [ -z "$var" ] && return
    OLD_IFS="$IFS"; IFS="|"
    for v in $var; do IFS="$OLD_IFS"; "$cb" "$v"; IFS="|"; done
    IFS="$OLD_IFS"
}
config_get() {
    var="$1"; section="$2"; option="$3"; default="$4"
    eval "$var=\${_uci_${section}_${option}-\$default}"
}

# Prepare fake subscription content.
LINKS='vless://uuid@a.example:443?type=tcp#NL-Server-1
vless://uuid@b.example:443?type=tcp#DE-Berlin
ss://Y2hhY2hhMjA6cGFzcw==@c.example:8388#RU-Moscow
trojan://pass@d.example:443?type=tcp#FI-Helsinki'

mkdir -p "$WORK/srv"
printf '%s' "$LINKS" | base64 -w0 > "$WORK/srv/sub_b64"
cat > "$WORK/srv/sub_sb" <<'EOF'
{"outbounds":[
  {"type":"vless","tag":"NL-Amsterdam","server":"a.example","server_port":443,"uuid":"u1"},
  {"type":"vless","tag":"DE-Frankfurt","server":"b.example","server_port":443,"uuid":"u2"},
  {"type":"selector","tag":"chooser","outbounds":["NL-Amsterdam","DE-Frankfurt"]},
  {"type":"direct","tag":"direct"}
]}
EOF

cd "$WORK/srv"
python3 -m http.server 18888 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.5

. "$LIB/subscription.sh"

pass=0; fail=0
ok()    { pass=$((pass+1)); echo "  PASS: $1"; }
nope()  { fail=$((fail+1)); echo "  FAIL: $1"; }

echo "=== E2E 1: subscription_update_section base64 ==="
_uci_main_subscription_url="http://127.0.0.1:18888/sub_b64"
_uci_main_subscription_format="auto"
_uci_main_subscription_user_agent="auto"
_uci_main_subscription_allow_insecure="0"
subscription_update_section main && ok "update succeeded" || nope "update failed"

[ -s "$SUBSCRIPTION_CACHE_DIR/main.parsed" ] && ok "parsed file written" || nope "no parsed"
n=$(wc -l < "$SUBSCRIPTION_CACHE_DIR/main.parsed")
[ "$n" = "4" ] && ok "4 profiles parsed" || nope "got $n profiles"

cat "$SUBSCRIPTION_CACHE_DIR/main.meta" | head
status=$(awk '{print $4}' "$SUBSCRIPTION_CACHE_DIR/main.meta")
[ "$status" = "ok" ] && ok "meta status=ok" || nope "meta status=$status"

echo "=== E2E 2: subscription_update_section sing-box JSON ==="
_uci_extra_subscription_url="http://127.0.0.1:18888/sub_sb"
_uci_extra_subscription_format="auto"
_uci_extra_subscription_user_agent="auto"
_uci_extra_subscription_allow_insecure="0"
subscription_update_section extra && ok "update succeeded" || nope "update failed"

n=$(wc -l < "$SUBSCRIPTION_CACHE_DIR/extra.parsed")
[ "$n" = "2" ] && ok "2 real outbounds (filtered out direct/selector)" || nope "got $n"

format=$(awk '{print $3}' "$SUBSCRIPTION_CACHE_DIR/extra.meta")
[ "$format" = "sing-box" ] && ok "format detected as sing-box" || nope "got '$format'"

echo "=== E2E 3: subscription_load_filtered with includes ==="
US="$(printf '\037')"
_uci_main_subscription_filters="DE${US}NL"
out=$(subscription_load_filtered main)
[ "$(echo "$out" | wc -l)" = "2" ] && ok "filter matched 2" || nope "got $(echo "$out" | wc -l): $out"

_uci_main_subscription_filters="DE|RU"
out=$(subscription_load_filtered main)
[ "$(echo "$out" | wc -l)" = "2" ] && ok "OR filter DE|RU = 2 (DE-Berlin + RU-Moscow)" || nope "got $(echo "$out" | wc -l)"

_uci_main_subscription_filters=""
_uci_main_subscription_exclude="Moscow"
out=$(subscription_load_filtered main)
[ "$(echo "$out" | wc -l)" = "3" ] && ok "exclude Moscow leaves 3" || nope "got $(echo "$out" | wc -l)"

echo "=== E2E 4: status JSON ==="
_uci_main_subscription_filters="DE${US}NL"
_uci_main_subscription_exclude=""
status=$(subscription_status_json main)
echo "$status" | jq -e '.section == "main" and .status == "ok" and .total == 4 and .filtered == 2' >/dev/null \
    && ok "status JSON valid" || nope "$status"

echo "=== E2E 5: list JSON ==="
listing=$(subscription_list_json main)
matched_count=$(echo "$listing" | jq '[.[] | select(.matched)] | length')
[ "$matched_count" = "2" ] && ok "list JSON matched=2" || nope "matched=$matched_count"

echo "=== E2E 6: fetch failure -> meta status fetch_failed ==="
_uci_bad_subscription_url="http://127.0.0.1:18888/does-not-exist"
_uci_bad_subscription_format="auto"
_uci_bad_subscription_user_agent="auto"
subscription_update_section bad && nope "should have failed" || ok "update reported failure"
[ -f "$SUBSCRIPTION_CACHE_DIR/bad.meta" ] && \
    grep -q "fetch_failed" "$SUBSCRIPTION_CACHE_DIR/bad.meta" \
    && ok "meta says fetch_failed" || nope "meta missing"

echo
echo "=================="
echo "PASSED: $pass"
echo "FAILED: $fail"
echo "=================="
[ "$fail" -eq 0 ]
