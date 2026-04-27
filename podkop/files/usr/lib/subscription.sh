#!/bin/ash
# Podkop subscription support library.
#
# A "subscription" is a remote URL that returns either:
#   1) A sing-box JSON document with an `outbounds` array (used by Marzban,
#      Remna and similar panels). Triggered by `User-Agent: SFA/<ver>`.
#   2) A base64-encoded list of proxy URIs (vless://, ss://, trojan://,
#      hysteria2://, socks5:// ...). The de-facto fallback delivered by
#      panels that don't recognise the user agent.
#   3) A plain newline-separated list of the same proxy URIs (rare but
#      legal — handled transparently).
#
# This library is sourced by /usr/bin/podkop and exposes:
#
#   subscription_user_agent_for <ua_setting> <format>
#   subscription_fetch <url> <ua> <allow_insecure> > raw_body
#   subscription_detect_format <raw_body>           => "sing-box"|"base64"|"plain"
#   subscription_parse <body> <format>              => parsed cache lines
#   subscription_filter_match <tag> <filter_string> => 0/1
#   subscription_apply_filter <parsed_file> <filters_csv> <excludes_csv>
#       => filtered cache lines
#   subscription_update_section <section>           => refresh on-disk cache
#   subscription_load_filtered <section>            => stdout: parsed lines
#   subscription_status_json <section>              => JSON status
#   subscription_list_json <section>                => JSON profile list
#
# Cache layout under SUBSCRIPTION_CACHE_DIR (persistent — kept on /etc):
#   <section>.raw      raw body as fetched
#   <section>.parsed   normalised, one entry per line:
#                        - URL profile:  "url <link>"
#                        - sing-box JSON profile: "json <inline-json>"
#   <section>.meta     "<unix-ts>\t<count>\t<format>\t<status>"
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

    # -fsSL: fail on HTTP errors, silent, follow redirects.
    # 30s connect, 60s total — subscription endpoints are usually slow.
    # shellcheck disable=SC2086
    curl -fsSL $extra \
        --connect-timeout 30 \
        --max-time 60 \
        -A "$ua" \
        "$url"
}

# --- Format detection --------------------------------------------------------

# Detect the format of an already-fetched body.
# Echoes one of: "sing-box" | "base64" | "plain".
#
# The check is intentionally order-sensitive:
#   * if the body parses as JSON with an outbounds[] array — sing-box;
#   * else if it base64-decodes into something that contains a known
#     proxy scheme — base64;
#   * else if the raw body itself contains a known proxy scheme — plain;
#   * else default to base64 (most providers fall back to it).
subscription_detect_format() {
    local body="$1"

    if [ -z "$body" ]; then
        echo "base64"
        return
    fi

    # Trim leading whitespace for the JSON probe.
    local first
    first="$(printf '%s' "$body" | head -c1)"
    if [ "$first" = "{" ]; then
        if printf '%s' "$body" \
            | jq -e 'type == "object" and (.outbounds | type) == "array"' \
                >/dev/null 2>&1; then
            echo "sing-box"
            return
        fi
    fi

    local decoded
    decoded="$(printf '%s' "$body" | tr -d '\r\n\t ' | base64 -d 2>/dev/null)"
    if [ -n "$decoded" ] \
        && printf '%s' "$decoded" \
            | grep -Eq '^(vless|vmess|ss|trojan|hy2|hysteria2|socks4a?|socks5)://'; then
        echo "base64"
        return
    fi

    if printf '%s' "$body" \
        | grep -Eq '^(vless|vmess|ss|trojan|hy2|hysteria2|socks4a?|socks5)://'; then
        echo "plain"
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
    # proxy on their own.
    printf '%s' "$body" | jq -c '
        .outbounds // [] | .[]
        | select(
            (.type // "") as $t
            | $t != "" and $t != "direct" and $t != "block" and $t != "dns"
              and $t != "selector" and $t != "urltest" and $t != "ssh"
        )
        | "json " + (tostring)
    ' 2>/dev/null | sed 's/^"\(.*\)"$/\1/'
}

# Master parser. Echoes parsed cache lines to stdout.
#
# Args:
#   $1 body
#   $2 format  ("sing-box"|"base64"|"plain")
subscription_parse() {
    local body="$1"
    local format="$2"
    local decoded

    case "$format" in
        sing-box)
            _subscription_parse_singbox_body "$body"
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

# Apply include + exclude filters to a parsed cache file.
#
# Filters arrive as a single string with ASCII unit separator (\x1f) between
# entries — this lets callers safely embed UCI list values that may contain
# `|`, spaces, emoji, etc.
#
# An entry that contains a `|` is OR'd internally. Any include entry must
# match (OR across entries as well). If `includes` is empty, all entries
# are included. If a tag matches any exclude entry, it is dropped.
subscription_apply_filter() {
    local parsed_file="$1"
    local includes="$2"
    local excludes="$3"

    # IFS to the unit separator so `for` iterates over filter entries.
    local OLD_IFS="$IFS"
    local line tag include_ok kw

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

        printf '%s\n' "$line"
    done < "$parsed_file"
}

# --- Cache I/O ---------------------------------------------------------------

subscription_cache_path_raw()    { echo "$SUBSCRIPTION_CACHE_DIR/$1.raw"; }
subscription_cache_path_parsed() { echo "$SUBSCRIPTION_CACHE_DIR/$1.parsed"; }
subscription_cache_path_meta()   { echo "$SUBSCRIPTION_CACHE_DIR/$1.meta"; }

subscription_cache_init() {
    [ -d "$SUBSCRIPTION_CACHE_DIR" ] || mkdir -p "$SUBSCRIPTION_CACHE_DIR"
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

# Read settings → fetch → parse → atomic-rename to cache. Updates meta.
#
# Args:
#   $1 section name (UCI)
#
# Side effects: writes to $SUBSCRIPTION_CACHE_DIR/.
# Returns: 0 on success, non-zero otherwise (the meta file always reflects
#          the last attempt).
subscription_update_section() {
    local section="$1"
    local url ua_setting format allow_insecure
    local actual_format body parsed_tmp ts count status

    [ -z "$section" ] && return 2

    config_get url            "$section" "subscription_url"
    config_get ua_setting     "$section" "subscription_user_agent" "auto"
    config_get format         "$section" "subscription_format" "auto"
    config_get allow_insecure "$section" "subscription_allow_insecure" "0"

    if [ -z "$url" ]; then
        return 2
    fi

    subscription_cache_init

    local ua
    ua="$(subscription_user_agent_for "$ua_setting" "$format")"

    log "subscription[$section]: fetching $url (UA=$ua)" "info"

    body="$(subscription_fetch "$url" "$ua" "$allow_insecure" 2>/dev/null)"
    if [ -z "$body" ]; then
        status="fetch_failed"
        ts="$(date +%s)"
        printf '%s\t%s\t%s\t%s\n' "$ts" "0" "${format}" "$status" \
            > "$(subscription_cache_path_meta "$section")"
        log "subscription[$section]: fetch failed" "error"
        return 1
    fi

    if [ "$format" = "auto" ] || [ -z "$format" ]; then
        actual_format="$(subscription_detect_format "$body")"
    else
        actual_format="$format"
    fi

    parsed_tmp="$(subscription_cache_path_parsed "$section").tmp"
    if ! subscription_parse "$body" "$actual_format" > "$parsed_tmp"; then
        rm -f "$parsed_tmp"
        status="parse_failed"
        ts="$(date +%s)"
        printf '%s\t%s\t%s\t%s\n' "$ts" "0" "$actual_format" "$status" \
            > "$(subscription_cache_path_meta "$section")"
        log "subscription[$section]: parse failed" "error"
        return 1
    fi

    count="$(wc -l < "$parsed_tmp" | tr -d ' ')"
    if [ -z "$count" ] || [ "$count" -eq 0 ]; then
        rm -f "$parsed_tmp"
        status="empty"
        ts="$(date +%s)"
        printf '%s\t%s\t%s\t%s\n' "$ts" "0" "$actual_format" "$status" \
            > "$(subscription_cache_path_meta "$section")"
        log "subscription[$section]: parsed 0 profiles" "error"
        return 1
    fi

    # Save raw + atomic rename parsed.
    printf '%s' "$body" > "$(subscription_cache_path_raw "$section")"
    mv "$parsed_tmp" "$(subscription_cache_path_parsed "$section")"

    ts="$(date +%s)"
    printf '%s\t%s\t%s\t%s\n' "$ts" "$count" "$actual_format" "ok" \
        > "$(subscription_cache_path_meta "$section")"

    log "subscription[$section]: ok ($count profiles, format=$actual_format)" "info"
    return 0
}

# Print all parsed-and-filtered cache lines for a section to stdout.
# Returns non-zero if no cache exists.
subscription_load_filtered() {
    local section="$1"
    local parsed includes excludes
    parsed="$(subscription_cache_path_parsed "$section")"

    [ -r "$parsed" ] || return 1

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"

    subscription_apply_filter "$parsed" "$includes" "$excludes"
}

# JSON status for /usr/bin/podkop subscription_status.
subscription_status_json() {
    local section="$1"
    local meta_file ts count format status filtered total
    meta_file="$(subscription_cache_path_meta "$section")"

    if [ -r "$meta_file" ]; then
        IFS="$(printf '\t')" read -r ts count format status < "$meta_file"
    else
        ts=""; count="0"; format=""; status="never"
    fi

    total="$count"
    filtered="$(subscription_load_filtered "$section" 2>/dev/null | wc -l | tr -d ' ')"
    [ -z "$filtered" ] && filtered="0"

    jq -n \
        --arg section "$section" \
        --arg ts "$ts" \
        --arg total "$total" \
        --arg filtered "$filtered" \
        --arg format "$format" \
        --arg status "$status" \
        '{
            section: $section,
            last_update: ($ts | tonumber? // null),
            total: ($total | tonumber? // 0),
            filtered: ($filtered | tonumber? // 0),
            format: $format,
            status: $status
        }'
}

# JSON list of all parsed profiles + whether each passed the filter.
subscription_list_json() {
    local section="$1"
    local parsed includes excludes
    parsed="$(subscription_cache_path_parsed "$section")"

    [ -r "$parsed" ] || { echo "[]"; return 0; }

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"

    # Build a temp file of "matched\tline" pairs, then convert to JSON.
    local tmp matched_file
    tmp="$(mktemp)"
    matched_file="$(mktemp)"

    subscription_apply_filter "$parsed" "$includes" "$excludes" > "$matched_file"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local tag kind rest matched=0 host port host_port=""
        kind="${line%% *}"
        rest="${line#"$kind "}"
        tag="$(subscription_line_get_tag "$line")"

        if grep -qxF "$line" "$matched_file"; then
            matched=1
        fi

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
                    '{tag:$tag, kind:$kind, endpoint:$endpoint, matched:($matched=="1")}'
                ;;
            json)
                jq -n \
                    --arg tag "$tag" \
                    --arg kind "json" \
                    --arg matched "$matched" \
                    --argjson outbound "$rest" \
                    '{tag:$tag, kind:$kind, type:($outbound.type // ""),
                      endpoint: (
                        if ($outbound.server // "") != "" then
                          ($outbound.server + (if ($outbound.server_port // 0) != 0 then ":" + ($outbound.server_port|tostring) else "" end))
                        else "" end
                      ),
                      matched:($matched=="1")}'
                ;;
        esac
    done < "$parsed" | jq -s '.'

    rm -f "$tmp" "$matched_file"
}

# vim: ft=sh ts=4 sw=4 et
