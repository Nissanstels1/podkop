#!/bin/ash
# Podkop subscription support library.
#
# A "subscription" is a remote URL that returns one of several documented
# formats. Supported formats (auto-detected by content):
#   1) sing-box JSON document with an `outbounds` array (Marzban, Remna).
#   2) base64-encoded newline list of proxy URIs (vless://, ss://, trojan://,
#      vmess://, hysteria2://, socks5:// ...). De-facto panel fallback.
#   3) plain newline list of proxy URIs.
#   4) Clash / clash.meta YAML (`proxies:` list).
#   5) v2ray outbound JSON (single outbound object or `{outbounds: [...]}`).
#
# A subscription section may have multiple URLs (subscription_urls list);
# bodies are fetched independently and merged with dedup-by-(tag, endpoint).
#
# This library is sourced by /usr/bin/podkop and exposes:
#
#   subscription_user_agent_for <ua_setting> <format>
#   subscription_fetch <url> <ua> <allow_insecure> > raw_body
#   subscription_detect_format <raw_body>           => sing-box|base64|plain|clash|v2ray
#   subscription_parse <body> <format>              => parsed cache lines
#   subscription_filter_match <tag> <filter_string> => 0/1
#   subscription_apply_filter <parsed_file> <filters_csv> <excludes_csv>
#       [<latency_file>] [<min_ms>] [<max_ms>]
#       => filtered cache lines
#   subscription_update_section <section>           => refresh on-disk cache
#   subscription_load_filtered <section>            => stdout: parsed lines
#   subscription_collect_urls <section>             => stdout: NL-separated URLs
#   subscription_resolve_interval <section>         => echoes effective interval
#   subscription_status_json <section>              => JSON status
#   subscription_list_json <section>                => JSON profile list
#
# Cache layout under SUBSCRIPTION_CACHE_DIR (persistent — kept on /etc):
#   <section>.raw      raw body as fetched (last URL only — for diagnostics)
#   <section>.parsed   normalised, one entry per line:
#                        - URL profile:  "url <link>"
#                        - sing-box JSON profile: "json <inline-json>"
#   <section>.meta     "<unix-ts>\t<count>\t<format>\t<status>\t<sha256>\t<unchanged_streak>\t<tier>"
#                      (legacy 4-field meta is still read; missing fields default to empty/0)
#   <section>.latency  "<tag>\t<ms>" — populated by latency collector
#
# All functions are POSIX/ash compatible and avoid `bash`-isms.

SUBSCRIPTION_CACHE_DIR="${SUBSCRIPTION_CACHE_DIR:-/etc/podkop/subscriptions}"

# --- User-Agent selection ----------------------------------------------------

# Pick the User-Agent header to send. If the user explicitly set a string
# different from the well-known presets, it is forwarded as-is.
#
# Args:
#   $1  ua_setting   "auto" | "sing-box" | "podkop" | "clash" | "<custom>"
#   $2  format       "auto" | "sing-box" | "base64" | "plain"
subscription_user_agent_for() {
    local ua_setting="$1"
    local format="$2"

    case "$ua_setting" in
        "" | auto)
            case "$format" in
                sing-box) echo "SFA/1.11.9" ;;
                *)        echo "podkop" ;;
            esac
            ;;
        sing-box | sfa | SFA)   echo "SFA/1.11.9" ;;
        podkop)                 echo "podkop" ;;
        clash | clash.meta)     echo "clash.meta" ;;
        v2rayn | v2ray)         echo "v2rayN" ;;
        *)                      echo "$ua_setting" ;;
    esac
}

# --- Fetching ----------------------------------------------------------------

# Download the subscription body to stdout. Returns non-zero on failure
# without printing anything (stderr only).
#
# Args:
#   $1 url
#   $2 user-agent  (already resolved)
#   $3 allow_insecure  ("1" to skip TLS verification)
subscription_fetch() {
    local url="$1"
    local ua="$2"
    local allow_insecure="$3"
    local extra=""

    [ -z "$url" ] && return 2

    if [ "$allow_insecure" = "1" ]; then
        extra="-k"
    fi

    # http:// is allowed but flagged — callers are expected to surface a warning
    # in the UI / logs. We do not reject the URL: many self-hosted panels run
    # plain HTTP behind a trusted LAN.
    case "$url" in
        http://*)
            log "subscription: HTTP (insecure) URL in use: $url. Subscription body is not authenticated; prefer https://." "warn"
            ;;
    esac

    # -fsSL: fail on HTTP errors, silent, follow redirects.
    # 30s connect, 60s total — subscription endpoints are usually slow.
    # --compressed: transparently handle gzip/deflate when libcurl was built
    # with zlib support. OpenWrt ships a "tiny" curl by default that does NOT
    # link zlib (and `curl --help` still lists `--compressed`), so we probe
    # `curl -V` for the explicit feature list — only there does the absence of
    # zlib show up reliably. If unavailable, identity-encode the request — most
    # subscription panels send identity-encoded bodies anyway.
    if curl -V 2>/dev/null | grep -qiE '(^|[[:space:]])libz([[:space:]]|/|$)'; then
        extra="$extra --compressed"
    fi

    # shellcheck disable=SC2086
    curl -fsSL $extra \
        --connect-timeout 30 \
        --max-time 60 \
        -A "$ua" \
        "$url"
}

# --- Format detection --------------------------------------------------------

# Detect the format of an already-fetched body.
# Echoes one of: "sing-box" | "v2ray" | "clash" | "base64" | "plain".
#
# Order-sensitive:
#   * JSON object with .outbounds[] of "real" proxy types (no inbounds, no log,
#     no policy) — v2ray (their JSON is plainer and often lacks log/dns);
#   * JSON object with .outbounds[] AND any sing-box-only top-level key — sing-box;
#   * any other JSON with .outbounds[] — sing-box (default);
#   * single JSON object with .protocol or .type that looks like a proxy — v2ray
#     single-outbound;
#   * YAML document containing `proxies:` block — clash;
#   * body that already starts with a known proxy URI scheme — plain;
#   * body that base64-decodes into a known proxy URI list — base64;
#   * fallback — base64.
subscription_detect_format() {
    local body="$1"

    if [ -z "$body" ]; then
        echo "base64"
        return
    fi

    # Trim leading whitespace for content sniffing.
    local first
    first="$(printf '%s' "$body" | LC_ALL=C tr -d '\r\n\t ' | head -c1)"

    if [ "$first" = "{" ] || [ "$first" = "[" ]; then
        # Full sing-box config: top-level object with .outbounds array AND
        # at least one sing-box-only key (route/inbounds/dns/experimental/log).
        if printf '%s' "$body" \
            | jq -e 'type == "object"
                     and ((.outbounds // []) | type) == "array"
                     and (
                         has("route") or has("inbounds") or has("experimental")
                         or (has("log") and (.log|type) == "object")
                         or (has("dns") and (.dns|type) == "object")
                     )' >/dev/null 2>&1; then
            echo "sing-box"
            return
        fi

        # v2ray-style top-level: { outbounds: [...] } without sing-box keys.
        if printf '%s' "$body" \
            | jq -e 'type == "object"
                     and ((.outbounds // []) | type) == "array"
                     and ((.outbounds[0] // {}) | has("protocol"))' \
                >/dev/null 2>&1; then
            echo "v2ray"
            return
        fi

        # v2ray single-outbound: { protocol: "vless"|..., settings: {...} }.
        if printf '%s' "$body" \
            | jq -e 'type == "object" and (.protocol // "") != ""
                     and (.settings // {}) != {}' >/dev/null 2>&1; then
            echo "v2ray"
            return
        fi

        # Bare sing-box outbounds container.
        if printf '%s' "$body" \
            | jq -e 'type == "object" and ((.outbounds // []) | type) == "array"' \
                >/dev/null 2>&1; then
            echo "sing-box"
            return
        fi
    fi

    # Clash YAML: look for a `proxies:` key at column 0 followed by a list.
    # Tolerate a leading BOM and Windows line endings.
    if printf '%s' "$body" | sed -n '1,200p' \
        | grep -Eq '^(proxies|proxy-providers)[[:space:]]*:'; then
        echo "clash"
        return
    fi

    if printf '%s' "$body" \
        | grep -Eq '^(vless|vmess|ss|trojan|hy2|hysteria2|tuic|socks4a?|socks5)://'; then
        echo "plain"
        return
    fi

    local decoded
    decoded="$(printf '%s' "$body" | LC_ALL=C tr -d '\r\n\t ' | base64 -d 2>/dev/null)"
    if [ -n "$decoded" ] \
        && printf '%s' "$decoded" \
            | grep -Eq '^(vless|vmess|ss|trojan|hy2|hysteria2|tuic|socks4a?|socks5)://'; then
        echo "base64"
        return
    fi

    echo "base64"
}

# --- Parsing -----------------------------------------------------------------

# Convert a base64 (or plain) body of proxy URIs into normalised cache lines
# of the form `url <link>`. One entry per stdout line.
_subscription_parse_links_body() {
    local body="$1"

    printf '%s' "$body" \
        | tr -d '\r' \
        | awk '
            BEGIN { schemes = "^(vless|vmess|ss|trojan|hy2|hysteria2|socks4a?|socks5)://" }
            /^[[:space:]]*$/ { next }
            /^[[:space:]]*\/\// { next }
            {
                # strip leading/trailing whitespace
                sub(/^[[:space:]]+/, "")
                sub(/[[:space:]]+$/, "")
                if ($0 ~ schemes) {
                    print "url " $0
                }
            }'
}

# Convert a sing-box JSON document into normalised cache lines
# `json <inline-json>`. Only "real" proxy outbounds are kept — internal
# logic outbounds (direct, dns, block, selector, urltest, ...) are dropped.
_subscription_parse_singbox_body() {
    local body="$1"

    # Reject sing-box internal / non-leaf outbounds — they cannot serve as a
    # proxy on their own. Emit raw (unescaped) JSON after the "json " prefix
    # so that downstream consumers can re-parse it with jq directly.
    printf '%s' "$body" | jq -r '
        .outbounds // [] | .[]
        | select(
            (.type // "") as $t
            | $t != "" and $t != "direct" and $t != "block" and $t != "dns"
              and $t != "selector" and $t != "urltest" and $t != "ssh"
        )
        | "json " + (. | tostring)
    ' 2>/dev/null
}

# Convert a v2ray-style outbound JSON document into normalised cache lines.
# Accepts either { outbounds: [...] } or a single-outbound { protocol, settings } object.
#
# v2ray outbounds use {protocol, settings, streamSettings, tag} \u2014 we translate
# them to a sing-box-shaped JSON object so the rest of the pipeline can reuse
# `sing_box_cf_add_json_outbound`.
_subscription_parse_v2ray_body() {
    local body="$1"

    # Normalise: wrap a bare single outbound as a 1-element array. Emit raw
    # (unescaped) JSON after the "json " prefix.
    printf '%s' "$body" | jq -r '
        def to_arr:
            if type == "object" and (.outbounds // null) != null then .outbounds
            elif type == "object" and (.protocol // "") != "" then [.]
            elif type == "array" then .
            else [] end;

        def first_server($s):
            if ($s.vnext // null) != null and ($s.vnext | type) == "array" then ($s.vnext[0] // {})
            elif ($s.servers // null) != null and ($s.servers | type) == "array" then ($s.servers[0] // {})
            else $s end;

        def map_protocol($p):
            if $p == "vless" then "vless"
            elif $p == "vmess" then "vmess"
            elif $p == "trojan" then "trojan"
            elif $p == "shadowsocks" then "shadowsocks"
            elif $p == "socks" then "socks"
            elif $p == "http" then "http"
            else $p end;

        to_arr
        | .[]
        | . as $o
        | (.protocol // "") as $proto
        | select($proto != "" and $proto != "freedom" and $proto != "blackhole" and $proto != "dns")
        | (first_server(.settings // {})) as $srv
        | (.streamSettings // {}) as $ss
        | {
            type: map_protocol($proto),
            tag: ((.tag // "") | tostring),
            server: ($srv.address // $srv.server // ""),
            server_port: (($srv.port // $srv.server_port // 0) | tonumber? // 0)
          }
        # v2ray vless/vmess users live under server.users[0]
        + (
            if ($srv.users // null) != null and ($srv.users | type) == "array" and ($srv.users[0] // null) != null then
              ($srv.users[0]) as $u
              | (
                  if $proto == "vless" then
                    { uuid: ($u.id // "") }
                    + (if ($u.flow // "") != "" then { flow: $u.flow } else {} end)
                  elif $proto == "vmess" then
                    { uuid: ($u.id // ""), security: ($u.security // "auto"),
                      alter_id: (($u.alterId // 0) | tonumber? // 0) }
                  elif $proto == "trojan" then
                    { password: ($u.password // "") }
                  else {} end
                )
            else {} end
        )
        # streamSettings -> sing-box transport / tls
        + (
            ($ss.network // "tcp") as $net
            | if $net == "ws" then
                { transport: { type: "ws",
                               path: (($ss.wsSettings // {}).path // "/"),
                               headers: (($ss.wsSettings // {}).headers // {}) } }
              elif $net == "grpc" then
                { transport: { type: "grpc",
                               service_name: (($ss.grpcSettings // {}).serviceName // "") } }
              elif $net == "h2" or $net == "http" then
                { transport: { type: "http",
                               path: (($ss.httpSettings // {}).path // "/") } }
              else {} end
        )
        + (
            (($ss.security // "") == "tls" or ($ss.security // "") == "reality") as $istls
            | if $istls then
                ({ enabled: true,
                   server_name: ((($ss.tlsSettings // {}).serverName)
                                 // (($ss.realitySettings // {}).serverName)
                                 // "") }
                 + (if (($ss.tlsSettings // {}).allowInsecure // false) then { insecure: true } else {} end)
                ) as $tls
                | { tls: $tls }
              else {} end
        )
        | "json " + (. | tostring)
    ' 2>/dev/null
}

# Convert a Clash / clash.meta YAML body into normalised cache lines.
#
# We parse the document with python3 (always present on OpenWrt + Podkop's
# dependency closure) and translate each `proxies:` entry into a sing-box-shaped
# inline JSON outbound, matching the same schema as `sing_box_cf_add_json_outbound`
# expects. Unsupported types fall back to "skipped" with a warning.
_subscription_parse_clash_body() {
    local body="$1"

    if ! command -v python3 >/dev/null 2>&1; then
        log "subscription: clash YAML format requires python3 \u2014 install python3-yaml on the router" "error"
        return 2
    fi

    printf '%s' "$body" | python3 -c '
import json
import sys

try:
    import yaml
except Exception:
    sys.stderr.write("python3-yaml not installed\n")
    sys.exit(2)

raw = sys.stdin.read()
try:
    doc = yaml.safe_load(raw)
except Exception as e:
    sys.stderr.write("yaml parse failed: %s\n" % e)
    sys.exit(2)

if not isinstance(doc, dict):
    sys.exit(0)

proxies = doc.get("proxies") or []
if not isinstance(proxies, list):
    sys.exit(0)

def map_type(t):
    t = (t or "").lower()
    return {
        "ss": "shadowsocks",
        "vmess": "vmess",
        "vless": "vless",
        "trojan": "trojan",
        "socks5": "socks",
        "socks": "socks",
        "http": "http",
        "hysteria2": "hysteria2",
        "hy2": "hysteria2",
        "tuic": "tuic",
    }.get(t, t)

for p in proxies:
    if not isinstance(p, dict):
        continue
    t = map_type(p.get("type"))
    if not t:
        continue
    out = {
        "type": t,
        "tag": str(p.get("name") or ""),
        "server": p.get("server") or "",
        "server_port": int(p.get("port") or 0),
    }
    # Auth fields
    if t == "shadowsocks":
        out["method"] = p.get("cipher") or p.get("method") or "aes-256-gcm"
        out["password"] = p.get("password") or ""
    elif t == "vless":
        out["uuid"] = p.get("uuid") or ""
        if p.get("flow"):
            out["flow"] = p["flow"]
    elif t == "vmess":
        out["uuid"] = p.get("uuid") or ""
        out["security"] = p.get("cipher") or "auto"
        out["alter_id"] = int(p.get("alterId") or 0)
    elif t == "trojan":
        out["password"] = p.get("password") or ""
    elif t == "socks" or t == "http":
        if p.get("username"):
            out["username"] = p["username"]
        if p.get("password"):
            out["password"] = p["password"]
    elif t == "hysteria2":
        out["password"] = p.get("password") or p.get("auth") or ""
        if p.get("up"): out["up_mbps"] = p["up"] if isinstance(p["up"], int) else 0
        if p.get("down"): out["down_mbps"] = p["down"] if isinstance(p["down"], int) else 0
    elif t == "tuic":
        out["uuid"] = p.get("uuid") or ""
        out["password"] = p.get("password") or ""

    # TLS
    tls_on = bool(p.get("tls")) or t in ("hysteria2", "tuic") or p.get("security") in ("tls", "reality")
    if tls_on:
        tls = {"enabled": True}
        sni = p.get("sni") or p.get("servername") or ""
        if sni: tls["server_name"] = sni
        if p.get("skip-cert-verify"): tls["insecure"] = True
        if p.get("alpn"): tls["alpn"] = p["alpn"] if isinstance(p["alpn"], list) else [p["alpn"]]
        # reality
        ro = p.get("reality-opts") or {}
        if ro:
            tls["reality"] = {"enabled": True}
            if ro.get("public-key"): tls["reality"]["public_key"] = ro["public-key"]
            if ro.get("short-id"): tls["reality"]["short_id"] = ro["short-id"]
            if not sni and ro.get("server-name"):
                tls["server_name"] = ro["server-name"]
        # utls
        if p.get("client-fingerprint"):
            tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
        out["tls"] = tls

    # Transport
    network = (p.get("network") or "").lower()
    if network == "ws":
        wsopts = p.get("ws-opts") or {}
        out["transport"] = {
            "type": "ws",
            "path": wsopts.get("path") or "/",
            "headers": wsopts.get("headers") or {},
        }
    elif network == "grpc":
        gopts = p.get("grpc-opts") or {}
        out["transport"] = {
            "type": "grpc",
            "service_name": gopts.get("grpc-service-name") or "",
        }
    elif network == "h2":
        hopts = p.get("h2-opts") or {}
        out["transport"] = {
            "type": "http",
            "path": hopts.get("path") or "/",
        }

    # udp-over-tcp / udp
    if t == "shadowsocks" and p.get("udp-over-tcp"):
        out["udp_over_tcp"] = True

    print("json " + json.dumps(out, ensure_ascii=False, separators=(",", ":")))
' 2>/dev/null
}

# Master parser. Echoes parsed cache lines to stdout.
#
# Args:
#   $1 body
#   $2 format  ("sing-box"|"v2ray"|"clash"|"base64"|"plain")
subscription_parse() {
    local body="$1"
    local format="$2"
    local decoded

    case "$format" in
        sing-box)
            _subscription_parse_singbox_body "$body"
            ;;
        v2ray)
            _subscription_parse_v2ray_body "$body"
            ;;
        clash | clash.meta | yaml)
            _subscription_parse_clash_body "$body"
            ;;
        base64)
            decoded="$(printf '%s' "$body" | tr -d '\r\n\t ' | base64 -d 2>/dev/null)"
            _subscription_parse_links_body "$decoded"
            ;;
        plain)
            _subscription_parse_links_body "$body"
            ;;
        *)
            return 2
            ;;
    esac
}

# --- Filtering ---------------------------------------------------------------

# Get a human-readable tag for a parsed cache line.
# Args: $1 — cache line ("url ..." or "json {...}").
subscription_line_get_tag() {
    local line="$1"
    local kind rest tag

    kind="${line%% *}"
    rest="${line#"$kind "}"

    case "$kind" in
        url)
            # Tag is the URL fragment, percent-decoded.
            tag="${rest##*#}"
            [ "$tag" = "$rest" ] && tag=""
            if [ -n "$tag" ]; then
                # url_decode is provided by helpers.sh.
                if command -v url_decode >/dev/null 2>&1; then
                    tag="$(url_decode "$tag")"
                else
                    # Fallback — at least convert %XX.
                    tag="$(printf '%b' "$(printf '%s' "$tag" | sed 's/+/ /g; s/%/\\x/g')")"
                fi
            fi
            echo "$tag"
            ;;
        json)
            printf '%s' "$rest" | jq -r '.tag // ""' 2>/dev/null
            ;;
    esac
}

# Test whether a tag matches a single filter expression. The expression is
# a `|`-separated list of plain substrings (NOT regex). Unicode-safe: we
# rely on POSIX `case` glob matching which compares bytes, so country-flag
# emoji (encoded as multi-byte UTF-8) are matched correctly as long as
# the user pasted the same emoji into the filter.
#
# Empty filter expression => always matches.
#
# Args:
#   $1 tag
#   $2 filter (e.g. "SE|RU" or "🇩🇪|🇳🇱")
subscription_filter_match() {
    local tag="$1"
    local filter="$2"
    local kw rest

    [ -z "$filter" ] && return 0

    rest="$filter"
    while [ -n "$rest" ]; do
        case "$rest" in
            *"|"*)
                kw="${rest%%|*}"
                rest="${rest#*|}"
                ;;
            *)
                kw="$rest"
                rest=""
                ;;
        esac
        [ -z "$kw" ] && continue
        case "$tag" in
            *"$kw"*) return 0 ;;
        esac
    done

    return 1
}

# Look up a tag in a latency cache file. Echoes the latency in ms, or empty
# string if no measurement is recorded for the tag.
#
# The cache file format is one record per line: `<tag>\t<ms>`.
subscription_lookup_latency() {
    local latency_file="$1"
    local tag="$2"
    [ -r "$latency_file" ] || { echo ""; return 0; }
    [ -z "$tag" ] && { echo ""; return 0; }
    awk -F'\t' -v t="$tag" '$1 == t { print $2; found=1; exit } END { if (!found) print "" }' \
        "$latency_file"
}

# Apply include + exclude + latency filters to a parsed cache file.
#
# Filters arrive as a single string with ASCII unit separator (\x1f) between
# entries — this lets callers safely embed UCI list values that may contain
# `|`, spaces, emoji, etc.
#
# An entry that contains a `|` is OR'd internally. Any include entry must
# match (OR across entries as well). If `includes` is empty, all entries
# are included. If a tag matches any exclude entry, it is dropped.
#
# Optional positional args 4-6:
#   $4 latency_file (or empty to skip latency filter)
#   $5 ping_min (ms; "" or "0" disables lower bound)
#   $6 ping_max (ms; "" or "0" disables upper bound)
#
# A profile WITHOUT a recorded latency is included by default — measurements
# accumulate over time and we don't want a fresh subscription to vanish.
subscription_apply_filter() {
    local parsed_file="$1"
    local includes="$2"
    local excludes="$3"
    local latency_file="${4:-}"
    local ping_min="${5:-0}"
    local ping_max="${6:-0}"

    # Normalise ping bounds — empty / non-numeric → disabled.
    case "$ping_min" in
        ''|*[!0-9]*) ping_min=0 ;;
    esac
    case "$ping_max" in
        ''|*[!0-9]*) ping_max=0 ;;
    esac

    # IFS to the unit separator so `for` iterates over filter entries.
    local OLD_IFS="$IFS"
    local line tag include_ok kw lat

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        tag="$(subscription_line_get_tag "$line")"

        # Includes: empty == all pass. Otherwise at least one entry matches.
        if [ -z "$includes" ]; then
            include_ok=1
        else
            include_ok=0
            IFS="$(printf '\037')"
            for kw in $includes; do
                IFS="$OLD_IFS"
                if subscription_filter_match "$tag" "$kw"; then
                    include_ok=1
                    break
                fi
                IFS="$(printf '\037')"
            done
            IFS="$OLD_IFS"
        fi
        [ "$include_ok" -eq 1 ] || continue

        # Excludes: if any entry matches, drop.
        if [ -n "$excludes" ]; then
            local exclude_hit=0
            IFS="$(printf '\037')"
            for kw in $excludes; do
                IFS="$OLD_IFS"
                if subscription_filter_match "$tag" "$kw"; then
                    exclude_hit=1
                    break
                fi
                IFS="$(printf '\037')"
            done
            IFS="$OLD_IFS"
            [ "$exclude_hit" -eq 1 ] && continue
        fi

        # Latency filter (if any bound active and a cache file is given).
        if [ -n "$latency_file" ] && { [ "$ping_min" -gt 0 ] || [ "$ping_max" -gt 0 ]; }; then
            lat="$(subscription_lookup_latency "$latency_file" "$tag")"
            if [ -n "$lat" ]; then
                case "$lat" in
                    ''|*[!0-9]*) : ;; # ignore non-numeric (e.g. timeout=-1)
                    *)
                        if [ "$ping_min" -gt 0 ] && [ "$lat" -lt "$ping_min" ]; then
                            continue
                        fi
                        if [ "$ping_max" -gt 0 ] && [ "$lat" -gt "$ping_max" ]; then
                            continue
                        fi
                        ;;
                esac
            fi
            # Tags without recorded latency: passthrough (will be measured later).
        fi

        printf '%s\n' "$line"
    done < "$parsed_file"
}

# --- Cache I/O ---------------------------------------------------------------

subscription_cache_path_raw()     { echo "$SUBSCRIPTION_CACHE_DIR/$1.raw"; }
subscription_cache_path_parsed()  { echo "$SUBSCRIPTION_CACHE_DIR/$1.parsed"; }
subscription_cache_path_meta()    { echo "$SUBSCRIPTION_CACHE_DIR/$1.meta"; }
subscription_cache_path_latency() { echo "$SUBSCRIPTION_CACHE_DIR/$1.latency"; }

subscription_cache_init() {
    [ -d "$SUBSCRIPTION_CACHE_DIR" ] || mkdir -p "$SUBSCRIPTION_CACHE_DIR"
}

# Read a tab-separated meta file and emit a single line padded to the canonical
# 7 fields: ts \t count \t format \t status \t sha256 \t streak \t tier.
# Missing fields are rendered as empty strings (or "0" for numeric streak).
subscription_meta_read() {
    local meta_file="$1"
    local ts count format status sha streak tier
    ts=""; count="0"; format=""; status="never"; sha=""; streak="0"; tier=""
    if [ -r "$meta_file" ]; then
        # IFS=tab handles legacy 4-field meta as well.
        IFS="$(printf '\t')" read -r ts count format status sha streak tier < "$meta_file"
        [ -z "$count" ]  && count="0"
        [ -z "$status" ] && status="ok"
        [ -z "$streak" ] && streak="0"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$count" "$format" "$status" "$sha" "$streak" "$tier"
}

# Write the canonical 7-field meta file.
subscription_meta_write() {
    local meta_file="$1"
    local ts="$2" count="$3" format="$4" status="$5" sha="$6" streak="$7" tier="$8"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$count" "$format" "$status" "$sha" "$streak" "$tier" \
        > "$meta_file"
}

# --- URL collection (single + multi) ----------------------------------------

# Echo, one URL per line, every URL configured for a subscription section.
# Reads both legacy `subscription_url` (single Value) and new
# `subscription_urls` (DynamicList). Empty entries are skipped.
subscription_collect_urls() {
    local section="$1"
    local single
    config_get single "$section" "subscription_url"
    [ -n "$single" ] && printf '%s\n' "$single"

    _sub_collect_url() {
        [ -n "$1" ] && printf '%s\n' "$1"
    }
    config_list_foreach "$section" "subscription_urls" _sub_collect_url
}

# Build a `\x1f`-joined string out of a UCI list option.
#
# Args:
#   $1 section
#   $2 option name
subscription_collect_list() {
    local section="$1"
    local option="$2"
    local out=""
    local US
    US="$(printf '\037')"

    _collect() {
        local v="$1"
        if [ -z "$out" ]; then
            out="$v"
        else
            out="${out}${US}${v}"
        fi
    }
    config_list_foreach "$section" "$option" _collect

    printf '%s' "$out"
}

# Compute SHA-256 of stdin or of the supplied string. Echoes the lowercase hex
# digest (or empty string on error).
_subscription_sha256() {
    local input="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$input" | sha256sum 2>/dev/null | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "$input" | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}'
    else
        echo ""
    fi
}

# Dedup parsed cache lines by `(tag, endpoint)` while preserving the first
# occurrence (so the order in the user's URL list is meaningful).
#
# Args:
#   $1 input file with parsed lines
# Stdout: deduped parsed lines.
_subscription_dedup_parsed() {
    local f="$1"
    awk '
        function endpoint_url(line,    rest, no_frag, host_port) {
            sub(/^url +/, "", line)
            no_frag = line; sub(/#.*$/, "", no_frag)
            return no_frag
        }
        /^url / {
            tag = $0; sub(/.*#/, "", tag)
            ep  = endpoint_url($0)
            key = tag "|" ep
            if (!(key in seen)) { seen[key] = 1; print }
            next
        }
        /^json / {
            # Re-emit deterministic key from the inline JSON.
            json = $0; sub(/^json +/, "", json)
            # extract tag (very crude; fine for cache lines we just emitted).
            t = ""
            if (match(json, /"tag":"[^"]*"/)) {
                t = substr(json, RSTART, RLENGTH)
                gsub(/"tag":"|"/, "", t)
            }
            s = ""
            if (match(json, /"server":"[^"]*"/)) {
                s = substr(json, RSTART, RLENGTH)
                gsub(/"server":"|"/, "", s)
            }
            p = ""
            if (match(json, /"server_port":[0-9]+/)) {
                p = substr(json, RSTART, RLENGTH)
                gsub(/"server_port":/, "", p)
            }
            key = t "|" s ":" p
            if (!(key in seen)) { seen[key] = 1; print }
            next
        }
        { print }
    ' "$f"
}

# Read settings → fetch (one or many URLs) → parse → atomic-rename to cache.
# Updates meta with new fields (sha256, unchanged_streak, tier).
#
# Args:
#   $1 section name (UCI)
#
# Side effects: writes to $SUBSCRIPTION_CACHE_DIR/.
# Returns: 0 on success, non-zero otherwise (the meta file always reflects
#          the last attempt).
subscription_update_section() {
    local section="$1"
    local ua_setting format allow_insecure
    local actual_format body parsed_tmp ts count status
    local urls url url_count
    local prev_meta_line prev_ts prev_count prev_format prev_status prev_sha prev_streak prev_tier
    local concat_body new_sha new_streak new_tier

    [ -z "$section" ] && return 2

    config_get ua_setting     "$section" "subscription_user_agent" "auto"
    config_get format         "$section" "subscription_format" "auto"
    config_get allow_insecure "$section" "subscription_allow_insecure" "0"

    urls="$(subscription_collect_urls "$section")"
    url_count="$(printf '%s' "$urls" | grep -c '.' || true)"

    if [ -z "$urls" ] || [ "$url_count" -eq 0 ]; then
        return 2
    fi

    subscription_cache_init

    # Read previous meta for streak tracking.
    prev_meta_line="$(subscription_meta_read "$(subscription_cache_path_meta "$section")")"
    IFS="$(printf '\t')" read -r prev_ts prev_count prev_format prev_status prev_sha prev_streak prev_tier <<EOF
$prev_meta_line
EOF
    [ -z "$prev_streak" ] && prev_streak="0"

    parsed_tmp="$(subscription_cache_path_parsed "$section").tmp"
    : > "$parsed_tmp"
    concat_body=""

    local ua
    ua="$(subscription_user_agent_for "$ua_setting" "$format")"

    local fetched_count=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        log "subscription[$section]: fetching $url (UA=$ua)" "info"
        body="$(subscription_fetch "$url" "$ua" "$allow_insecure" 2>/dev/null)"
        if [ -z "$body" ]; then
            log "subscription[$section]: fetch failed for $url" "warn"
            continue
        fi

        local this_format
        if [ "$format" = "auto" ] || [ -z "$format" ]; then
            this_format="$(subscription_detect_format "$body")"
        else
            this_format="$format"
        fi
        # actual_format is reported as the format of the LAST successful body.
        actual_format="$this_format"

        if ! subscription_parse "$body" "$this_format" >> "$parsed_tmp"; then
            log "subscription[$section]: parse failed for $url (format=$this_format)" "warn"
            continue
        fi

        # Concatenate raw bodies for sha256 stability across runs.
        concat_body="${concat_body}${body}"
        # Preserve the LAST raw body for diagnostics (matches legacy behaviour).
        printf '%s' "$body" > "$(subscription_cache_path_raw "$section")"
        fetched_count=$((fetched_count + 1))
    done <<EOF
$urls
EOF

    if [ "$fetched_count" -eq 0 ]; then
        rm -f "$parsed_tmp"
        ts="$(date +%s)"
        # Status: fetch_failed; preserve previous sha/streak/tier so cron
        # tier doesn't oscillate on transient failures.
        subscription_meta_write \
            "$(subscription_cache_path_meta "$section")" \
            "$ts" "0" "${format:-}" "fetch_failed" \
            "$prev_sha" "$prev_streak" "$prev_tier"
        log "subscription[$section]: all fetches failed" "error"
        return 1
    fi

    # Dedup across multiple subscriptions.
    local dedup_tmp="${parsed_tmp}.dedup"
    _subscription_dedup_parsed "$parsed_tmp" > "$dedup_tmp"
    mv "$dedup_tmp" "$parsed_tmp"

    count="$(wc -l < "$parsed_tmp" | tr -d ' ')"
    if [ -z "$count" ] || [ "$count" -eq 0 ]; then
        rm -f "$parsed_tmp"
        ts="$(date +%s)"
        subscription_meta_write \
            "$(subscription_cache_path_meta "$section")" \
            "$ts" "0" "$actual_format" "empty" \
            "$prev_sha" "$prev_streak" "$prev_tier"
        log "subscription[$section]: parsed 0 profiles" "error"
        return 1
    fi

    mv "$parsed_tmp" "$(subscription_cache_path_parsed "$section")"

    new_sha="$(_subscription_sha256 "$concat_body")"

    # Smart-update streak: if body sha is unchanged from previous, increment
    # the unchanged-streak. Otherwise reset to 0.
    if [ -n "$new_sha" ] && [ "$new_sha" = "$prev_sha" ]; then
        new_streak=$((prev_streak + 1))
    else
        new_streak=0
    fi

    # Resolve effective tier (only matters when the user picked "auto"; otherwise
    # tier is just the static interval value). Keeps prev tier as starting point.
    new_tier="$(subscription_resolve_interval "$section" "$new_streak" "$prev_tier")"

    ts="$(date +%s)"
    subscription_meta_write \
        "$(subscription_cache_path_meta "$section")" \
        "$ts" "$count" "$actual_format" "ok" \
        "$new_sha" "$new_streak" "$new_tier"

    log "subscription[$section]: ok ($count profiles, format=$actual_format, sources=$fetched_count, streak=$new_streak, tier=$new_tier)" "info"
    return 0
}

# Resolve the effective auto-update interval for a section.
#
# When the user-configured `subscription_update_interval` is one of the static
# values (10m, 1h, 6h, 1d, off) — that value is returned as-is.
#
# When set to "auto":
#   * 7 unchanged updates in a row → bump tier one step coarser
#     (10m→1h→6h→1d), capped at 1d.
#   * Any change → bump tier one step finer (1d→6h→1h→10m), floored at 10m.
#   * The current_tier hint is read from the previous meta to keep state
#     across calls. Defaults to "1h" if no hint is given.
#
# Args:
#   $1 section
#   $2 unchanged_streak (integer, optional — defaults to 0)
#   $3 current_tier hint (optional — defaults to previous tier or 1h)
subscription_resolve_interval() {
    local section="$1"
    local streak="${2:-0}"
    local current="${3:-}"
    local configured

    config_get configured "$section" "subscription_update_interval" "1h"

    case "$configured" in
        auto)
            : # fallthrough below
            ;;
        *)
            printf '%s' "$configured"
            return 0
            ;;
    esac

    if [ -z "$current" ]; then
        # No prior tier recorded → baseline.
        printf '1h'
        return 0
    fi

    if [ "$streak" -ge 7 ]; then
        # Coarsen.
        case "$current" in
            10m)  printf '1h' ;;
            1h)   printf '6h' ;;
            6h)   printf '1d' ;;
            *)    printf '1d' ;;
        esac
        return 0
    fi

    if [ "$streak" -eq 0 ]; then
        # Finer (body changed this run).
        case "$current" in
            1d)   printf '6h' ;;
            6h)   printf '1h' ;;
            1h)   printf '10m' ;;
            10m)  printf '10m' ;;
            *)    printf '1h' ;;
        esac
        return 0
    fi

    # Mid-range — keep current tier.
    printf '%s' "$current"
}

# Print all parsed-and-filtered cache lines for a section to stdout.
# Returns non-zero if no cache exists.
#
# Optional second argument:
#   "all"   (default) — apply tag includes/excludes + latency-range filter
#   "fast"  — restrict to profiles with measured latency < fast_threshold_ms
#             (or no measurement → included as "potentially fast")
#   "slow"  — restrict to profiles with measured latency >= fast_threshold_ms
#   "raw"   — no tag filter, no latency filter (used by latency collector
#             so it can probe every profile, regardless of UI filter)
subscription_load_filtered() {
    local section="$1"
    local mode="${2:-all}"
    local parsed includes excludes ping_min ping_max latency_file fast_thresh

    parsed="$(subscription_cache_path_parsed "$section")"
    [ -r "$parsed" ] || return 1

    if [ "$mode" = "raw" ]; then
        cat "$parsed"
        return 0
    fi

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"
    config_get ping_min  "$section" "subscription_ping_min"  "0"
    config_get ping_max  "$section" "subscription_ping_max"  "0"
    config_get fast_thresh "$section" "subscription_fast_threshold_ms" "100"
    latency_file="$(subscription_cache_path_latency "$section")"

    # First-pass: apply tag + ping-range filter.
    local primary
    primary="$(subscription_apply_filter "$parsed" "$includes" "$excludes" \
                                         "$latency_file" "$ping_min" "$ping_max")"

    case "$mode" in
        all)
            printf '%s\n' "$primary" | sed '/^$/d'
            ;;
        fast)
            _subscription_split_pool "$primary" "$latency_file" "$fast_thresh" "fast"
            ;;
        slow)
            _subscription_split_pool "$primary" "$latency_file" "$fast_thresh" "slow"
            ;;
        *)
            printf '%s\n' "$primary" | sed '/^$/d'
            ;;
    esac
}

# Split a pool of parsed cache lines into "fast" and "slow" buckets based on
# recorded latency cache. Lines without recorded latency go to the "fast"
# pool by convention (so a brand-new subscription still has working entries
# in the default group).
#
# Args:
#   $1 input lines (multi-line string)
#   $2 latency_file path
#   $3 fast_threshold_ms
#   $4 mode ("fast" or "slow")
_subscription_split_pool() {
    local lines="$1"
    local latency_file="$2"
    local thresh="$3"
    local mode="$4"
    local line tag lat

    case "$thresh" in
        ''|*[!0-9]*) thresh=100 ;;
    esac

    printf '%s\n' "$lines" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        tag="$(subscription_line_get_tag "$line")"
        lat="$(subscription_lookup_latency "$latency_file" "$tag")"

        if [ -z "$lat" ]; then
            # Unknown latency → fast pool by default.
            [ "$mode" = "fast" ] && printf '%s\n' "$line"
            continue
        fi

        case "$lat" in
            ''|*[!0-9]*)
                # Failed measurement (e.g. -1 timeout) → slow pool.
                [ "$mode" = "slow" ] && printf '%s\n' "$line"
                continue
                ;;
        esac

        if [ "$lat" -lt "$thresh" ]; then
            [ "$mode" = "fast" ] && printf '%s\n' "$line"
        else
            [ "$mode" = "slow" ] && printf '%s\n' "$line"
        fi
    done
}

# JSON status for /usr/bin/podkop subscription_status.
subscription_status_json() {
    local section="$1"
    local meta_file ts count format status sha streak tier filtered total fast slow
    meta_file="$(subscription_cache_path_meta "$section")"

    IFS="$(printf '\t')" read -r ts count format status sha streak tier <<EOF
$(subscription_meta_read "$meta_file")
EOF

    total="$count"
    filtered="$(subscription_load_filtered "$section" all 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
    fast="$(subscription_load_filtered "$section" fast 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
    slow="$(subscription_load_filtered "$section" slow 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
    [ -z "$filtered" ] && filtered="0"
    [ -z "$fast" ] && fast="0"
    [ -z "$slow" ] && slow="0"

    local urls_count
    urls_count="$(subscription_collect_urls "$section" | grep -c '.' || true)"
    [ -z "$urls_count" ] && urls_count="0"

    jq -n \
        --arg section "$section" \
        --arg ts "$ts" \
        --arg total "$total" \
        --arg filtered "$filtered" \
        --arg fast "$fast" \
        --arg slow "$slow" \
        --arg format "$format" \
        --arg status "$status" \
        --arg sha "$sha" \
        --arg streak "$streak" \
        --arg tier "$tier" \
        --arg urls_count "$urls_count" \
        '{
            section: $section,
            last_update: ($ts | tonumber? // null),
            total: ($total | tonumber? // 0),
            filtered: ($filtered | tonumber? // 0),
            fast: ($fast | tonumber? // 0),
            slow: ($slow | tonumber? // 0),
            format: $format,
            status: $status,
            sha256: $sha,
            unchanged_streak: ($streak | tonumber? // 0),
            tier: $tier,
            urls_count: ($urls_count | tonumber? // 0)
        }'
}

# JSON list of all parsed profiles + whether each passed the filter.
# Each record now also carries the last-known latency (ms) and pool
# classification (fast / slow / unknown).
subscription_list_json() {
    local section="$1"
    local parsed includes excludes ping_min ping_max latency_file fast_thresh
    parsed="$(subscription_cache_path_parsed "$section")"

    [ -r "$parsed" ] || { echo "[]"; return 0; }

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"
    config_get ping_min   "$section" "subscription_ping_min"  "0"
    config_get ping_max   "$section" "subscription_ping_max"  "0"
    config_get fast_thresh "$section" "subscription_fast_threshold_ms" "100"
    latency_file="$(subscription_cache_path_latency "$section")"

    case "$fast_thresh" in
        ''|*[!0-9]*) fast_thresh=100 ;;
    esac

    # Build a temp file of matched lines for O(1) lookup via fgrep.
    local tmp matched_file
    tmp="$(mktemp)"
    matched_file="$(mktemp)"

    subscription_apply_filter "$parsed" "$includes" "$excludes" \
        "$latency_file" "$ping_min" "$ping_max" > "$matched_file"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local tag kind rest matched=0 host port host_port="" lat="" pool="unknown"
        kind="${line%% *}"
        rest="${line#"$kind "}"
        tag="$(subscription_line_get_tag "$line")"

        if grep -qxF "$line" "$matched_file"; then
            matched=1
        fi

        lat="$(subscription_lookup_latency "$latency_file" "$tag")"
        case "$lat" in
            ''|*[!0-9]*) pool="unknown" ;;
            *)
                if [ "$lat" -lt "$fast_thresh" ]; then
                    pool="fast"
                else
                    pool="slow"
                fi
                ;;
        esac

        case "$kind" in
            url)
                host="$(url_get_host "$rest" 2>/dev/null)"
                port="$(url_get_port "$rest" 2>/dev/null)"
                if [ -n "$host" ]; then
                    if [ -n "$port" ]; then
                        host_port="$host:$port"
                    else
                        host_port="$host"
                    fi
                fi
                jq -n \
                    --arg tag "$tag" \
                    --arg kind "url" \
                    --arg endpoint "$host_port" \
                    --arg matched "$matched" \
                    --arg latency "$lat" \
                    --arg pool "$pool" \
                    '{tag:$tag, kind:$kind, endpoint:$endpoint,
                      matched:($matched=="1"),
                      latency_ms:($latency | tonumber? // null),
                      pool:$pool}'
                ;;
            json)
                jq -n \
                    --arg tag "$tag" \
                    --arg kind "json" \
                    --arg matched "$matched" \
                    --arg latency "$lat" \
                    --arg pool "$pool" \
                    --argjson outbound "$rest" \
                    '{tag:$tag, kind:$kind, type:($outbound.type // ""),
                      endpoint: (
                        if ($outbound.server // "") != "" then
                          ($outbound.server + (if ($outbound.server_port // 0) != 0 then ":" + ($outbound.server_port|tostring) else "" end))
                        else "" end
                      ),
                      matched:($matched=="1"),
                      latency_ms:($latency | tonumber? // null),
                      pool:$pool}'
                ;;
        esac
    done < "$parsed" | jq -s '.'

    rm -f "$tmp" "$matched_file"
}

# vim: ft=sh ts=4 sw=4 et
