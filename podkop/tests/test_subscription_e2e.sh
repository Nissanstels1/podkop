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

echo "=== E2E 7: meta now has 7 columns (sha256, fallback flag, last_attempt) ==="
ncols=$(awk -F'\t' 'NR==1{print NF; exit}' "$SUBSCRIPTION_CACHE_DIR/main.meta")
[ "$ncols" = "7" ] && ok "meta has 7 columns" || nope "got $ncols"

sha=$(awk -F'\t' 'NR==1{print $5; exit}' "$SUBSCRIPTION_CACHE_DIR/main.meta")
[ -n "$sha" ] && [ ${#sha} = "64" ] && ok "sha256 stored ($sha)" || nope "missing/short sha=$sha"

echo "=== E2E 8: status JSON exposes sha256 + fallback_in_use ==="
status=$(subscription_status_json main)
echo "$status" | jq -e '.sha256 != null and .sha256 != "" and .fallback_in_use == false' >/dev/null \
    && ok "status JSON has sha256 + fallback flag" || nope "$status"

echo "=== E2E 9: fetch fails — fallback to previous parsed cache + flag ==="
# Save current parsed state, then point primary at a 404 with no fallback.
_uci_main_subscription_url="http://127.0.0.1:18888/does-not-exist-now"
prev_count=$(wc -l < "$SUBSCRIPTION_CACHE_DIR/main.parsed")
subscription_update_section main && nope "should have failed" || ok "update reported failure"
new_count=$(wc -l < "$SUBSCRIPTION_CACHE_DIR/main.parsed")
[ "$prev_count" = "$new_count" ] && ok "previous parsed cache preserved" || \
    nope "parsed went from $prev_count to $new_count"
status=$(subscription_status_json main)
echo "$status" | jq -e '.fallback_in_use == true and .status == "fetch_failed"' >/dev/null \
    && ok "status reports fallback_in_use=true" || nope "$status"
filtered=$(echo "$status" | jq '.filtered')
[ "$filtered" -gt 0 ] && ok "load_filtered still serves $filtered profiles" || nope "filtered=$filtered"

# Restore primary URL for the rest of the suite.
_uci_main_subscription_url="http://127.0.0.1:18888/sub_b64"
subscription_update_section main >/dev/null

echo "=== E2E 10: fallback URL chain — primary 404, fallback OK ==="
_uci_chain_subscription_url="http://127.0.0.1:18888/does-not-exist"
_uci_chain_subscription_url_fallback="http://127.0.0.1:18888/sub_b64"
_uci_chain_subscription_format="auto"
_uci_chain_subscription_user_agent="auto"
_uci_chain_subscription_allow_insecure="0"
subscription_update_section chain && ok "fallback URL succeeded" || nope "fallback failed"
n=$(wc -l < "$SUBSCRIPTION_CACHE_DIR/chain.parsed")
[ "$n" = "4" ] && ok "fallback chain parsed 4 profiles" || nope "got $n"
status=$(awk -F'\t' 'NR==1{print $4}' "$SUBSCRIPTION_CACHE_DIR/chain.meta")
[ "$status" = "ok" ] && ok "chain status=ok" || nope "got '$status'"

echo "=== E2E 11: short-circuit when sha256 unchanged ==="
# Capture pre-update timestamp, sleep briefly, run again, expect status=ok and
# (because sha did not change) parsed file is untouched.
sha1=$(awk -F'\t' 'NR==1{print $5}' "$SUBSCRIPTION_CACHE_DIR/main.meta")
mtime1=$(stat -c '%Y' "$SUBSCRIPTION_CACHE_DIR/main.parsed")
sleep 1
subscription_update_section main >/dev/null
sha2=$(awk -F'\t' 'NR==1{print $5}' "$SUBSCRIPTION_CACHE_DIR/main.meta")
mtime2=$(stat -c '%Y' "$SUBSCRIPTION_CACHE_DIR/main.parsed")
[ "$sha1" = "$sha2" ] && ok "sha256 unchanged across updates" || nope "$sha1 vs $sha2"
[ "$mtime1" = "$mtime2" ] && ok "parsed file untouched (short-circuit)" \
    || nope "parsed mtime changed: $mtime1 -> $mtime2"

echo "=== E2E 12: parsed.prev backup created on second successful update ==="
# Point at a different content for one update so we get a backup created.
cp "$WORK/srv/sub_b64" "$WORK/srv/sub_b64.copy"
echo 'vless://uuid@new.example:443?type=tcp#NEW-Server' \
    | base64 -w0 > "$WORK/srv/sub_b64"
_uci_chain_subscription_url="http://127.0.0.1:18888/sub_b64"
_uci_chain_subscription_url_fallback=""
subscription_update_section chain >/dev/null
[ -r "$SUBSCRIPTION_CACHE_DIR/chain.parsed.prev" ] \
    && ok "parsed.prev backup written" \
    || nope ".prev missing"
# Restore the original sub_b64 so subsequent test runs are stable.
cp "$WORK/srv/sub_b64.copy" "$WORK/srv/sub_b64"

echo "=== E2E 13a: progress JSON populated on a fresh section ==="
SUBSCRIPTION_PROGRESS_DIR="$WORK/progress"
_uci_progsec_subscription_url="http://127.0.0.1:18888/sub_b64"
_uci_progsec_subscription_format="auto"
_uci_progsec_subscription_user_agent="auto"
_uci_progsec_subscription_allow_insecure="0"
subscription_update_section progsec >/dev/null
prog=$(subscription_progress_json progsec)
echo "$prog" | jq -e '.section == "progsec" and (.stages | length) > 0' >/dev/null \
    && ok "progress JSON has stages" || nope "$prog"
echo "$prog" | jq -e '[.stages[].stage] | contains(["fetching","parsing","done"])' >/dev/null \
    && ok "progress includes fetching/parsing/done on first run" || nope "$prog"

echo "=== E2E 13b: progress JSON shows 'unchanged' on identical re-fetch ==="
subscription_update_section progsec >/dev/null
prog=$(subscription_progress_json progsec)
echo "$prog" | jq -e '[.stages[].stage] | contains(["unchanged","done"])' >/dev/null \
    && ok "second update emits unchanged + done" || nope "$prog"

echo "=== E2E 13c: validate JSON happy path ==="
val=$(subscription_validate_json main)
echo "$val" | jq -e '.section == "main" and .ok == true' >/dev/null \
    && ok "validate returns ok=true" || nope "$val"
echo "$val" | jq -e '[.checks[].stage] | contains(["dns","tcp","http","format","parse"])' >/dev/null \
    && ok "validate has dns/tcp/http/format/parse stages" || nope "$val"

echo "=== E2E 13d: validate JSON for missing URL section ==="
val=$(subscription_validate_json missing)
echo "$val" | jq -e '.ok == false and (.checks[0].stage == "config")' >/dev/null \
    && ok "validate flags missing subscription_url" || nope "$val"

echo "=== E2E 13e: test_url JSON for valid endpoint ==="
tu=$(subscription_test_url_json "http://127.0.0.1:18888/sub_b64" "podkop" "0")
echo "$tu" | jq -e '.ok == true and .http_code == 200 and .format_guess == "base64"' >/dev/null \
    && ok "test_url ok+200+base64" || nope "$tu"

echo "=== E2E 13f: test_url JSON for 404 ==="
tu=$(subscription_test_url_json "http://127.0.0.1:18888/does-not-exist" "podkop" "0")
echo "$tu" | jq -e '.ok == false and .http_code == 404 and (.error // "" | contains("HTTP"))' >/dev/null \
    && ok "test_url reports 404" || nope "$tu"

echo "=== E2E 13: stuck-server tracker JSON empty by default ==="
out=$(subscription_stuck_json main)
[ "$out" = "[]" ] && ok "stuck_json returns []" || nope "got '$out'"

echo "=== E2E 14: stuck-server tag tracker marks + clears + threshold ==="
SUBSCRIPTION_STUCK_THRESHOLD=2
SUBSCRIPTION_STUCK_RECOVERY_AFTER=1800
now=$(date +%s)
_subscription_stuck_mark_fail main main-1 "$now"
subscription_tag_is_stuck main main-1 && nope "should not be stuck after 1 fail" \
    || ok "1 fail < threshold (not stuck yet)"
_subscription_stuck_mark_fail main main-1 "$now"
subscription_tag_is_stuck main main-1 && ok "2 fails -> stuck" \
    || nope "expected stuck"
_subscription_stuck_clear main main-1
subscription_tag_is_stuck main main-1 && nope "should be cleared" \
    || ok "clear removes stuck flag"

echo "=== E2E 15: subscription_active_json without Clash returns available=false ==="
# Point Clash API to a definitely-closed port so the call fails fast.
out=$(CLASH_API_BASE="http://127.0.0.1:1" subscription_active_json main)
echo "$out" | jq -e '.available == false and (.reason | type == "string")' \
    >/dev/null \
    && ok "active_json fails gracefully without clash" \
    || nope "expected available=false, got '$out'"

echo "=== E2E 16: subscription_latency_json includes history field ==="
out=$(CLASH_API_BASE="http://127.0.0.1:1" subscription_latency_json main 0)
# When clash is unreachable each row has latency=null and history=[].
echo "$out" | jq -e 'all(.history | type == "array")' >/dev/null \
    && ok "latency_json rows carry history arrays" \
    || nope "missing history field: $out"

echo
echo "=================="
echo "PASSED: $pass"
echo "FAILED: $fail"
echo "=================="
[ "$fail" -eq 0 ]
