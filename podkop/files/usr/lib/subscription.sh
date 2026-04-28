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
#   <section>.meta     tab-separated columns. The format is forward-compatible:
#                        col 1: <unix-ts>           last successful update
#                        col 2: <count>             profiles in current cache
#                        col 3: <format>            sing-box|base64|plain
#                        col 4: <status>            ok|fetch_failed|parse_failed|...
#                        col 5: <sha256>            of the raw body (optional)
#                        col 6: <fallback_in_use>   "1" when the cache shown is
#                                                   from a previous successful
#                                                   update because the latest one
#                                                   failed; "0" otherwise.
#                        col 7: <last_attempt_ts>   timestamp of last update *attempt*
#                                                   (success or failure).
#   <section>.parsed.prev   atomic backup kept after every successful update.
#   <section>.stuck         tab-separated lines describing servers temporarily
#                           dropped from rotation (adaptive rotation).
#                            "<tag>\t<stuck_since_ts>\t<fail_count>\n"
#
# All functions are POSIX/ash compatible and avoid `bash`-isms.

SUBSCRIPTION_CACHE_DIR="${SUBSCRIPTION_CACHE_DIR:-/etc/podkop/subscriptions}"

# Volatile per-section progress files written by subscription_update_section.
# The LuCI page polls these to render a real-stage progress bar instead of
# a dumb spinner. Path is /tmp/* on purpose: progress is ephemeral and we
# don't want to pollute /etc snapshots.
SUBSCRIPTION_PROGRESS_DIR="${SUBSCRIPTION_PROGRESS_DIR:-/tmp/podkop-progress}"

_subscription_progress_path() {
    echo "$SUBSCRIPTION_PROGRESS_DIR/$1.progress"
}

# Append a single tab-separated record `<ts>\t<stage>\t<detail>` to the
# section's progress file. Cheap (one printf, no jq) so it's safe to call
# many times during an update.
_subscription_progress_write() {
    local section="$1" stage="$2" detail="$3"
    [ -z "$section" ] && return 0
    [ -z "$stage" ]   && return 0
    mkdir -p "$SUBSCRIPTION_PROGRESS_DIR" 2>/dev/null
    local ts
    ts="$(date +%s)"
    printf '%s\t%s\t%s\n' "$ts" "$stage" "$detail" \
        >> "$(_subscription_progress_path "$section")" 2>/dev/null || true
}

# Reset the per-section progress file. Called at the start of every update
# so the LuCI poller never sees stale stages from a previous run.
_subscription_progress_reset() {
    local section="$1"
    [ -z "$section" ] && return 0
    mkdir -p "$SUBSCRIPTION_PROGRESS_DIR" 2>/dev/null
    : > "$(_subscription_progress_path "$section")" 2>/dev/null || true
}

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

subscription_cache_path_raw()         { echo "$SUBSCRIPTION_CACHE_DIR/$1.raw"; }
subscription_cache_path_parsed()      { echo "$SUBSCRIPTION_CACHE_DIR/$1.parsed"; }
subscription_cache_path_parsed_prev() { echo "$SUBSCRIPTION_CACHE_DIR/$1.parsed.prev"; }
subscription_cache_path_meta()        { echo "$SUBSCRIPTION_CACHE_DIR/$1.meta"; }
subscription_cache_path_stuck()       { echo "$SUBSCRIPTION_CACHE_DIR/$1.stuck"; }

# Compute sha256 of stdin (best-effort: prefer sha256sum, fall back to openssl).
_subscription_sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum 2>/dev/null | awk '{print $1; exit}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 2>/dev/null | awk '{print $NF; exit}'
    else
        echo ""
    fi
}

# Read meta file and echo a single field by 1-based index. Missing column => "".
_subscription_meta_field() {
    local meta_file="$1"
    local idx="$2"
    [ -r "$meta_file" ] || { echo ""; return 0; }
    awk -F'\t' -v i="$idx" 'NR==1 { if (NF>=i) print $i; exit }' "$meta_file"
}

# Write a meta line with all columns. Atomic via temp file.
_subscription_write_meta() {
    local section="$1"
    local ts="$2"
    local count="$3"
    local format="$4"
    local status="$5"
    local sha="$6"
    local fallback_in_use="$7"
    local last_attempt_ts="$8"
    local meta_file tmp
    meta_file="$(subscription_cache_path_meta "$section")"
    tmp="$meta_file.tmp"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$count" "$format" "$status" "$sha" "$fallback_in_use" "$last_attempt_ts" \
        > "$tmp" \
        && mv "$tmp" "$meta_file"
}

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

# Build the URL chain for a section: primary (subscription_url) followed by
# any subscription_url_fallback list entries (in declared order).
subscription_collect_urls() {
    local section="$1"
    local primary

    config_get primary "$section" "subscription_url"

    if [ -n "$primary" ]; then
        printf '%s\n' "$primary"
    fi

    _collect_url() { printf '%s\n' "$1"; }
    config_list_foreach "$section" "subscription_url_fallback" _collect_url
}

# Read settings → fetch (with URL fallback chain) → parse → atomic-rename
# to cache. Updates meta with sha256 / fallback flag. Keeps the previous
# successful parsed cache as <section>.parsed.prev so the section stays
# operational if a future update fails.
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
    local actual_format body parsed_tmp ts count
    local urls url tried_urls used_url=""
    local prev_sha new_sha
    local meta_path

    [ -z "$section" ] && return 2

    _subscription_progress_reset "$section"
    _subscription_progress_write "$section" "start" "$section"

    config_get ua_setting     "$section" "subscription_user_agent" "auto"
    config_get format         "$section" "subscription_format" "auto"
    config_get allow_insecure "$section" "subscription_allow_insecure" "0"

    urls="$(subscription_collect_urls "$section")"
    if [ -z "$urls" ]; then
        _subscription_progress_write "$section" "error" "no subscription_url configured"
        return 2
    fi

    subscription_cache_init
    meta_path="$(subscription_cache_path_meta "$section")"

    local ua
    ua="$(subscription_user_agent_for "$ua_setting" "$format")"

    # --- Step 1: fetch (try every URL in order) ----------------------------
    body=""
    tried_urls=""
    _subscription_progress_write "$section" "fetching" ""
    local IFS_OLD="$IFS"
    IFS="
"
    for url in $urls; do
        IFS="$IFS_OLD"
        if [ -z "$url" ]; then
            IFS="
"
            continue
        fi
        log "subscription[$section]: fetching $url (UA=$ua)" "info"
        _subscription_progress_write "$section" "fetching" "$url"
        body="$(subscription_fetch "$url" "$ua" "$allow_insecure" 2>/dev/null)"
        if [ -n "$body" ]; then
            used_url="$url"
            _subscription_progress_write "$section" "fetched" "${#body} bytes"
            break
        fi
        log "subscription[$section]: fetch from $url failed, trying fallback" "warn"
        _subscription_progress_write "$section" "fetch_retry" "$url"
        tried_urls="$tried_urls $url"
        IFS="
"
    done
    IFS="$IFS_OLD"

    ts="$(date +%s)"
    prev_sha="$(_subscription_meta_field "$meta_path" 5)"

    if [ -z "$body" ]; then
        # All URLs failed. Preserve the old parsed cache and mark the meta
        # so subscription_load_filtered keeps serving stale-but-working data.
        local fallback="0" prev_count prev_ts
        if [ -r "$(subscription_cache_path_parsed "$section")" ]; then
            fallback="1"
        fi
        prev_count="$(_subscription_meta_field "$meta_path" 2)"
        prev_ts="$(_subscription_meta_field "$meta_path" 1)"
        [ -z "$prev_count" ] && prev_count="0"
        _subscription_write_meta "$section" "$prev_ts" "$prev_count" "$format" \
            "fetch_failed" "$prev_sha" "$fallback" "$ts"
        _subscription_progress_write "$section" "error" "fetch failed for all URLs"
        log "subscription[$section]: fetch failed for all URLs" "error"
        return 1
    fi

    # --- Step 2: detect format -------------------------------------------
    _subscription_progress_write "$section" "detecting" ""
    if [ "$format" = "auto" ] || [ -z "$format" ]; then
        actual_format="$(subscription_detect_format "$body")"
    else
        actual_format="$format"
    fi

    new_sha="$(printf '%s' "$body" | _subscription_sha256_stdin)"
    _subscription_progress_write "$section" "format" "$actual_format"

    # --- Step 3: short-circuit if body identical -------------------------
    if [ -n "$new_sha" ] && [ "$new_sha" = "$prev_sha" ] && \
        [ -r "$(subscription_cache_path_parsed "$section")" ]; then
        count="$(_subscription_meta_field "$meta_path" 2)"
        [ -z "$count" ] && count="0"
        _subscription_write_meta "$section" "$ts" "$count" "$actual_format" \
            "ok" "$new_sha" "0" "$ts"
        _subscription_progress_write "$section" "unchanged" "$count profiles"
        _subscription_progress_write "$section" "done" "$count"
        log "subscription[$section]: ok unchanged ($count profiles)" "info"
        return 0
    fi

    # --- Step 4: parse ---------------------------------------------------
    _subscription_progress_write "$section" "parsing" ""
    parsed_tmp="$(subscription_cache_path_parsed "$section").tmp"
    if ! subscription_parse "$body" "$actual_format" > "$parsed_tmp"; then
        rm -f "$parsed_tmp"
        local fallback="0" prev_count prev_ts
        if [ -r "$(subscription_cache_path_parsed "$section")" ]; then
            fallback="1"
        fi
        prev_count="$(_subscription_meta_field "$meta_path" 2)"
        prev_ts="$(_subscription_meta_field "$meta_path" 1)"
        [ -z "$prev_count" ] && prev_count="0"
        _subscription_write_meta "$section" "$prev_ts" "$prev_count" \
            "$actual_format" "parse_failed" "$prev_sha" "$fallback" "$ts"
        _subscription_progress_write "$section" "error" "parse failed"
        log "subscription[$section]: parse failed (kept previous cache)" "error"
        return 1
    fi

    count="$(wc -l < "$parsed_tmp" | tr -d ' ')"
    if [ -z "$count" ] || [ "$count" -eq 0 ]; then
        rm -f "$parsed_tmp"
        local fallback="0" prev_count prev_ts
        if [ -r "$(subscription_cache_path_parsed "$section")" ]; then
            fallback="1"
        fi
        prev_count="$(_subscription_meta_field "$meta_path" 2)"
        prev_ts="$(_subscription_meta_field "$meta_path" 1)"
        [ -z "$prev_count" ] && prev_count="0"
        _subscription_write_meta "$section" "$prev_ts" "$prev_count" \
            "$actual_format" "empty" "$prev_sha" "$fallback" "$ts"
        _subscription_progress_write "$section" "error" "parsed 0 profiles"
        log "subscription[$section]: parsed 0 profiles (kept previous cache)" "error"
        return 1
    fi

    _subscription_progress_write "$section" "parsed" "$count"

    # --- Step 5: rotate cache atomically --------------------------------
    # Backup current parsed → .prev BEFORE overwriting.
    if [ -r "$(subscription_cache_path_parsed "$section")" ]; then
        cp "$(subscription_cache_path_parsed "$section")" \
           "$(subscription_cache_path_parsed_prev "$section")" 2>/dev/null || true
    fi
    printf '%s' "$body" > "$(subscription_cache_path_raw "$section")"
    mv "$parsed_tmp" "$(subscription_cache_path_parsed "$section")"

    _subscription_write_meta "$section" "$ts" "$count" "$actual_format" \
        "ok" "$new_sha" "0" "$ts"

    _subscription_progress_write "$section" "done" "$count"
    if [ -n "$tried_urls" ]; then
        log "subscription[$section]: ok via fallback URL ($count profiles, format=$actual_format)" "info"
    else
        log "subscription[$section]: ok ($count profiles, format=$actual_format)" "info"
    fi
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
    local meta_file ts count format status sha fallback last_attempt filtered total stuck_count

    meta_file="$(subscription_cache_path_meta "$section")"

    if [ -r "$meta_file" ]; then
        IFS="$(printf '\t')" read -r ts count format status sha fallback last_attempt \
            < "$meta_file"
    else
        ts=""; count="0"; format=""; status="never"
        sha=""; fallback="0"; last_attempt=""
    fi
    [ -z "$count" ]    && count="0"
    [ -z "$status" ]   && status="never"
    [ -z "$fallback" ] && fallback="0"

    total="$count"
    filtered="$(subscription_load_filtered "$section" 2>/dev/null | wc -l | tr -d ' ')"
    [ -z "$filtered" ] && filtered="0"

    if [ -r "$(subscription_cache_path_stuck "$section")" ]; then
        stuck_count="$(wc -l < "$(subscription_cache_path_stuck "$section")" \
            | tr -d ' ')"
    else
        stuck_count="0"
    fi
    [ -z "$stuck_count" ] && stuck_count="0"

    jq -n \
        --arg section       "$section" \
        --arg ts            "$ts" \
        --arg total         "$total" \
        --arg filtered      "$filtered" \
        --arg format        "$format" \
        --arg status        "$status" \
        --arg sha           "$sha" \
        --arg fallback      "$fallback" \
        --arg last_attempt  "$last_attempt" \
        --arg stuck         "$stuck_count" \
        '{
            section: $section,
            last_update:    ($ts | tonumber? // null),
            last_attempt:   ($last_attempt | tonumber? // null),
            total:          ($total | tonumber? // 0),
            filtered:       ($filtered | tonumber? // 0),
            stuck:          ($stuck | tonumber? // 0),
            format:         $format,
            status:         $status,
            sha256:         $sha,
            fallback_in_use: ($fallback == "1")
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

# --- Adaptive rotation: stuck-server tracking --------------------------------
#
# Format of <section>.stuck (tab-separated, one tag per line):
#   <tag>\t<stuck_since_ts>\t<consecutive_failures>
#
# A tag is considered "stuck" once `consecutive_failures` reaches
# SUBSCRIPTION_STUCK_THRESHOLD. Tags are auto-recovered when a probe
# succeeds, or after SUBSCRIPTION_STUCK_RECOVERY_AFTER seconds elapsed
# without ever clearing (so a permanently-dead tag eventually gets
# re-tried in case the upstream came back online).

SUBSCRIPTION_STUCK_THRESHOLD="${SUBSCRIPTION_STUCK_THRESHOLD:-3}"
SUBSCRIPTION_STUCK_RECOVERY_AFTER="${SUBSCRIPTION_STUCK_RECOVERY_AFTER:-1800}"

# Read the stuck file into stdin → stdout. Removes records that exceeded
# the recovery window (so they re-enter rotation automatically).
_subscription_stuck_prune() {
    local file="$1"
    local now="$2"

    [ -r "$file" ] || return 0

    awk -F'\t' -v now="$now" -v ttl="$SUBSCRIPTION_STUCK_RECOVERY_AFTER" '
        ($2 + ttl) > now { print }
    ' "$file"
}

# Mark a tag as having had a probe failure.
_subscription_stuck_mark_fail() {
    local section="$1"
    local tag="$2"
    local now="$3"
    local file tmp prior_count prior_since new_count
    file="$(subscription_cache_path_stuck "$section")"
    tmp="$file.tmp"

    : > "$tmp"
    if [ -r "$file" ]; then
        awk -F'\t' -v t="$tag" '$1 != t { print }' "$file" >> "$tmp"
        prior_count="$(awk -F'\t' -v t="$tag" '$1 == t { print $3; exit }' "$file")"
        prior_since="$(awk -F'\t' -v t="$tag" '$1 == t { print $2; exit }' "$file")"
    fi
    [ -z "$prior_count" ] && prior_count="0"
    [ -z "$prior_since" ] && prior_since="$now"
    new_count=$((prior_count + 1))
    printf '%s\t%s\t%s\n' "$tag" "$prior_since" "$new_count" >> "$tmp"

    mv "$tmp" "$file"
}

# Remove a tag from the stuck file (after a successful probe).
_subscription_stuck_clear() {
    local section="$1"
    local tag="$2"
    local file tmp
    file="$(subscription_cache_path_stuck "$section")"
    [ -r "$file" ] || return 0

    tmp="$file.tmp"
    awk -F'\t' -v t="$tag" '$1 != t { print }' "$file" > "$tmp"
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp" "$file"
    else
        mv "$tmp" "$file"
    fi
}

# Return 0 if the tag is currently considered stuck (above threshold).
subscription_tag_is_stuck() {
    local section="$1"
    local tag="$2"
    local file fail_count
    file="$(subscription_cache_path_stuck "$section")"
    [ -r "$file" ] || return 1

    fail_count="$(awk -F'\t' -v t="$tag" '$1 == t { print $3; exit }' "$file")"
    [ -z "$fail_count" ] && return 1
    [ "$fail_count" -ge "$SUBSCRIPTION_STUCK_THRESHOLD" ] && return 0
    return 1
}

# JSON list of currently-stuck tags for a section.
subscription_stuck_json() {
    local section="$1"
    local file
    file="$(subscription_cache_path_stuck "$section")"

    if [ ! -r "$file" ]; then
        echo "[]"
        return 0
    fi

    # Auto-prune expired entries before reporting.
    local now pruned tmp
    now="$(date +%s)"
    tmp="$file.tmp"
    pruned="$(_subscription_stuck_prune "$file" "$now")"
    if [ -z "$pruned" ]; then
        rm -f "$file"
        echo "[]"
        return 0
    fi
    printf '%s\n' "$pruned" > "$tmp" && mv "$tmp" "$file"

    awk -F'\t' '
        BEGIN { print "[" }
        NR > 1 { print "," }
        {
            gsub(/\\/,  "\\\\", $1)
            gsub(/"/,   "\\\"", $1)
            printf "{\"tag\":\"%s\",\"stuck_since\":%s,\"fails\":%s}",
                   $1, $2, $3
        }
        END { print "]" }
    ' "$file"
}

# Probe a single tag through the local Clash API. Returns 0 if the
# delay endpoint produced a positive latency, non-zero otherwise.
# CLASH_API_BASE may be overridden via env (default :9090).
_subscription_clash_delay() {
    local tag="$1"
    local url="$2"
    local timeout_ms="${3:-3000}"
    local base="${CLASH_API_BASE:-http://127.0.0.1:9090}"
    local response delay

    response="$(curl -fsS --max-time 8 \
        "$base/proxies/$tag/delay?timeout=$timeout_ms&url=$url" 2>/dev/null)"
    [ -z "$response" ] && return 1

    delay="$(printf '%s' "$response" | jq -r '.delay // empty' 2>/dev/null)"
    [ -z "$delay" ] && return 1
    [ "$delay" -gt 0 ] 2>/dev/null || return 1
    return 0
}

# Probe each filtered server through Clash API and update the stuck file.
# Skips silently if Clash API is unavailable (e.g. sing-box not running).
#
# Args:
#   $1 section
subscription_health_check() {
    local section="$1"
    local parsed includes excludes line tag i probe_url
    parsed="$(subscription_cache_path_parsed "$section")"
    [ -r "$parsed" ] || return 1

    local file now
    file="$(subscription_cache_path_stuck "$section")"
    now="$(date +%s)"

    # Prune expired entries first.
    if [ -r "$file" ]; then
        local pruned
        pruned="$(_subscription_stuck_prune "$file" "$now")"
        if [ -z "$pruned" ]; then
            rm -f "$file"
        else
            printf '%s\n' "$pruned" > "$file.tmp" && mv "$file.tmp" "$file"
        fi
    fi

    config_get probe_url "$section" "urltest_testing_url" \
        "https://www.gstatic.com/generate_204"

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"

    i=1
    local tmpfile
    tmpfile="$(mktemp)"
    subscription_apply_filter "$parsed" "$includes" "$excludes" > "$tmpfile"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        tag="$section-$i"
        i=$((i + 1))

        if _subscription_clash_delay "$tag" "$probe_url" 3000; then
            _subscription_stuck_clear "$section" "$tag"
        else
            _subscription_stuck_mark_fail "$section" "$tag" "$now"
            log "subscription[$section]: tag $tag probe failed" "debug"
        fi
    done < "$tmpfile"
    rm -f "$tmpfile"

    return 0
}

# --- Tier 2: progress / validate / test_url / latency -----------------------

# Pretty-print the per-section progress file as JSON. Used by the LuCI
# "Update subscription now" button to render a real-stage progress bar.
# Returns `{"section": "...", "stages": []}` if no progress file exists.
subscription_progress_json() {
    local section="$1"
    local file
    file="$(_subscription_progress_path "$section")"

    if [ ! -r "$file" ]; then
        jq -n --arg s "$section" '{section: $s, stages: []}'
        return 0
    fi

    jq -R -s --arg s "$section" '
        split("\n")
        | map(select(. != ""))
        | map(split("\t"))
        | map({
            ts:     (.[0] | tonumber? // 0),
            stage:  (.[1] // ""),
            detail: (.[2] // "")
          })
        | { section: $s, stages: . }
    ' < "$file"
}

# Quick "kick the tires" probe of an arbitrary URL. Used by the
# "Test connection" button next to subscription_url so the user can sanity
# check a URL before saving the form. No state is touched on disk.
#
# Args:
#   $1 url
#   $2 user_agent  (optional, defaults to "podkop")
#   $3 allow_insecure ("1" to skip TLS verification, optional)
subscription_test_url_json() {
    local url="$1"
    local ua="$2"
    local allow_insecure="$3"
    [ -z "$ua" ] && ua="podkop"

    if [ -z "$url" ]; then
        echo '{"ok":false,"error":"empty url"}'
        return 0
    fi

    local extra=""
    [ "$allow_insecure" = "1" ] && extra="-k"

    # Single curl HEAD with timing + remote IP capture.
    # %{time_connect} = TCP, %{time_appconnect} = TLS handshake,
    # %{time_total}   = end-to-end.
    local out rc
    # shellcheck disable=SC2086
    out="$(curl -sS $extra --connect-timeout 5 --max-time 8 -o /dev/null \
        -w 'http_code=%{http_code}\nsize=%{size_download}\nct=%{content_type}\nrip=%{remote_ip}\ntc=%{time_connect}\ntac=%{time_appconnect}\ntt=%{time_total}\n' \
        -I -A "$ua" "$url" 2>/dev/null)"
    rc=$?

    local http_code size ct rip tc tac tt
    http_code="$(printf '%s\n' "$out" | sed -n 's/^http_code=//p')"
    size="$(printf '%s\n' "$out" | sed -n 's/^size=//p')"
    ct="$(printf '%s\n' "$out" | sed -n 's/^ct=//p')"
    rip="$(printf '%s\n' "$out" | sed -n 's/^rip=//p')"
    tc="$(printf '%s\n' "$out" | sed -n 's/^tc=//p')"
    tac="$(printf '%s\n' "$out" | sed -n 's/^tac=//p')"
    tt="$(printf '%s\n' "$out" | sed -n 's/^tt=//p')"

    local latency_ms tls_ms tcp_ms
    tcp_ms="$(awk -v v="$tc"  'BEGIN{ if (v>0) print int(v*1000); else print 0 }')"
    tls_ms="$(awk -v v="$tac" 'BEGIN{ if (v>0) print int(v*1000); else print 0 }')"
    latency_ms="$(awk -v v="$tt"  'BEGIN{ if (v>0) print int(v*1000); else print 0 }')"

    # Sample first 8KB to detect format. Treat empty body as unknown.
    # `|| true` so a 4xx from the format probe never aborts the caller
    # (subscription_test_url_json must always emit a JSON object).
    local sample format_guess="unknown"
    # shellcheck disable=SC2086
    sample="$(curl -fsS $extra --connect-timeout 5 --max-time 8 \
        -A "$ua" \
        --range 0-8192 \
        "$url" 2>/dev/null || true)"
    if [ -n "$sample" ]; then
        format_guess="$(subscription_detect_format "$sample")"
    fi

    local ok="false" error=""
    case "$http_code" in
        2*) ok="true" ;;
        '') error="curl exit $rc" ;;
        *)  error="HTTP $http_code" ;;
    esac

    jq -n \
        --arg url    "$url" \
        --arg ok     "$ok" \
        --arg http_code "$http_code" \
        --arg size      "$size" \
        --arg ct        "$ct" \
        --arg rip       "$rip" \
        --arg tcp_ms    "$tcp_ms" \
        --arg tls_ms    "$tls_ms" \
        --arg latency   "$latency_ms" \
        --arg format    "$format_guess" \
        --arg error     "$error" \
        '{
            url:           $url,
            ok:            ($ok == "true"),
            http_code:     ($http_code | tonumber? // 0),
            size:          ($size | tonumber? // 0),
            content_type:  $ct,
            remote_ip:     $rip,
            tcp_ms:        ($tcp_ms | tonumber? // 0),
            tls_ms:        ($tls_ms | tonumber? // 0),
            latency_ms:    ($latency | tonumber? // 0),
            format_guess:  $format,
            error:         (if $error != "" then $error else null end)
          }'
}

# Pre-flight validation. Runs DNS → TCP → TLS → HTTP → format → parse for
# the configured subscription URL of <section>. Stops as soon as a stage
# fails so the user sees exactly where things broke.
subscription_validate_json() {
    local section="$1"
    local url ua_setting format allow_insecure ua
    [ -z "$section" ] && { echo '{"ok":false,"error":"section required"}'; return 1; }

    config_get url            "$section" "subscription_url"
    config_get ua_setting     "$section" "subscription_user_agent" "auto"
    config_get format         "$section" "subscription_format" "auto"
    config_get allow_insecure "$section" "subscription_allow_insecure" "0"
    ua="$(subscription_user_agent_for "$ua_setting" "$format")"

    if [ -z "$url" ]; then
        jq -n --arg s "$section" \
            '{section:$s, ok:false, checks:[{stage:"config", ok:false, message:"subscription_url not set"}]}'
        return 0
    fi

    local host port scheme
    scheme="$(printf '%s' "$url" | awk -F'://' '{print $1}')"
    host="$(printf '%s' "$url"   | awk -F'://' '{print $2}' | awk -F'[/?#:]' '{print $1}')"
    port="$(printf '%s' "$url"   | awk -F'://' '{print $2}' | awk -F'[/?#]' '{print $1}' | awk -F':' 'NF>1{print $NF}')"
    [ -z "$port" ] && case "$scheme" in
        https) port="443" ;;
        http)  port="80"  ;;
        *)     port="443" ;;
    esac

    # Build up the checks array with one jq invocation per stage. Cheap
    # since this is invoked manually by the user, not on hot paths.
    local checks_json='[]'
    local overall="true"
    _vc_add() {
        local stage="$1" ok_flag="$2" message="$3"
        checks_json="$(printf '%s' "$checks_json" \
            | jq --arg s "$stage" --arg o "$ok_flag" --arg m "$message" \
                '. + [{stage:$s, ok:($o=="true"), message:$m}]')"
        [ "$ok_flag" = "false" ] && overall="false"
        # NB: never let the trailing `[ ]` propagate non-zero — callers
        # commonly run with `set -e`.
        return 0
    }
    _vc_emit() {
        jq -n --arg s "$section" --argjson c "$checks_json" --arg o "$overall" \
            '{section:$s, ok:($o=="true"), checks:$c}'
    }

    # Stage 1 — DNS
    # If the host part already looks like a literal IPv4/IPv6 address, skip
    # the resolver (BusyBox `nslookup` returns nothing for raw IPs and
    # `getent` is rarely installed on OpenWrt routers).
    local ip
    case "$host" in
        # Trivially-IPv4 (4 dotted octets — exact match isn't needed, the
        # /[0-9.]+/ test is enough to short-circuit valid raw addresses).
        *[!0-9.]*) ;;
        *.*.*.*)   ip="$host" ;;
    esac
    case "$host" in
        *:*) ip="$host" ;;  # IPv6 literal
    esac
    if [ -z "$ip" ] && command -v getent >/dev/null 2>&1; then
        ip="$(getent hosts "$host" 2>/dev/null | awk 'NR==1{print $1}')"
    fi
    if [ -z "$ip" ] && command -v nslookup >/dev/null 2>&1; then
        ip="$(nslookup "$host" 2>/dev/null \
            | awk '
                /^Name:/ { in_a=1; next }
                in_a && /^Address[^:]*:/ {
                    sub(/^[^:]*:[ \t]*/, "")
                    sub(/#.*/, "")
                    print
                    exit
                }')"
    fi
    if [ -n "$ip" ]; then
        if [ "$ip" = "$host" ]; then
            _vc_add "dns" "true" "Literal IP — skipped"
        else
            _vc_add "dns" "true"  "$host → $ip"
        fi
    else
        _vc_add "dns" "false" "Cannot resolve $host"
        _vc_emit
        return 0
    fi

    # Stage 2+3+4 — TCP / TLS / HTTP via single curl HEAD
    local extra=""
    [ "$allow_insecure" = "1" ] && extra="-k"
    local out rc tc tac http_code
    # shellcheck disable=SC2086
    out="$(curl -sS $extra --connect-timeout 5 --max-time 8 -o /dev/null \
        -w 'tc=%{time_connect}\ntac=%{time_appconnect}\ncode=%{http_code}\n' \
        -I -A "$ua" "$url" 2>/dev/null)"
    rc=$?
    tc="$(printf '%s\n' "$out"  | sed -n 's/^tc=//p')"
    tac="$(printf '%s\n' "$out" | sed -n 's/^tac=//p')"
    http_code="$(printf '%s\n' "$out" | sed -n 's/^code=//p')"

    if [ "$rc" -eq 0 ] && [ "$(awk -v v="$tc" 'BEGIN{print (v>0)}')" = "1" ]; then
        local ms; ms="$(awk -v v="$tc" 'BEGIN{print int(v*1000)}')"
        _vc_add "tcp" "true" "Connected in ${ms} ms"
    else
        _vc_add "tcp" "false" "TCP connect failed (curl exit $rc)"
        _vc_emit
        return 0
    fi

    case "$scheme" in
        https)
            if [ "$rc" -eq 0 ] && [ "$(awk -v v="$tac" 'BEGIN{print (v>0)}')" = "1" ]; then
                local ms; ms="$(awk -v v="$tac" 'BEGIN{print int(v*1000)}')"
                local note="${ms} ms"
                [ "$allow_insecure" = "1" ] && note="${ms} ms (insecure mode)"
                _vc_add "tls" "true" "$note"
            else
                local note="TLS handshake failed"
                [ "$allow_insecure" != "1" ] && note="$note (try Allow Insecure?)"
                _vc_add "tls" "false" "$note"
                _vc_emit
                return 0
            fi
            ;;
    esac

    case "$http_code" in
        2*) _vc_add "http" "true"  "HTTP $http_code" ;;
        '') _vc_add "http" "false" "No HTTP response (curl exit $rc)" ;;
        *)  _vc_add "http" "false" "HTTP $http_code" ;;
    esac
    if [ "$overall" = "false" ]; then
        _vc_emit
        return 0
    fi

    # Stage 5+6 — fetch full body, detect format, parse
    local body actual_format count parsed_tmp
    # shellcheck disable=SC2086
    body="$(curl -fsS $extra --connect-timeout 5 --max-time 12 -A "$ua" "$url" 2>/dev/null)"
    if [ -z "$body" ]; then
        _vc_add "format" "false" "Empty response body"
        _vc_emit
        return 0
    fi
    if [ "$format" = "auto" ] || [ -z "$format" ]; then
        actual_format="$(subscription_detect_format "$body")"
    else
        actual_format="$format"
    fi
    _vc_add "format" "true" "Detected: $actual_format"

    parsed_tmp="$(mktemp 2>/dev/null || echo "/tmp/podkop-parse-$$.tmp")"
    if subscription_parse "$body" "$actual_format" > "$parsed_tmp" 2>/dev/null; then
        count="$(wc -l < "$parsed_tmp" | tr -d ' ')"
        [ -z "$count" ] && count="0"
        if [ "$count" -gt 0 ]; then
            _vc_add "parse" "true"  "$count profiles parsed"
        else
            _vc_add "parse" "false" "Body parsed but 0 profiles found"
        fi
    else
        _vc_add "parse" "false" "Parse step failed"
    fi
    rm -f "$parsed_tmp"

    _vc_emit
}

# Latency for each filtered profile, queried via the local Clash API.
# By default reads cached history (no probing) — fast, cheap, ~1 RTT each.
# Pass force=1 (second arg) to actively re-probe through Clash, which
# spends ~3 s per stuck server.
subscription_latency_json() {
    local section="$1"
    local force="${2:-0}"
    local parsed includes excludes line tag i probe_url
    parsed="$(subscription_cache_path_parsed "$section")"

    [ -r "$parsed" ] || { echo "[]"; return 0; }

    config_get probe_url "$section" "urltest_testing_url" \
        "https://www.gstatic.com/generate_204"

    includes="$(subscription_collect_list "$section" "subscription_filters")"
    excludes="$(subscription_collect_list "$section" "subscription_exclude")"

    local tmpfile
    tmpfile="$(mktemp)"
    subscription_apply_filter "$parsed" "$includes" "$excludes" > "$tmpfile"

    local base="${CLASH_API_BASE:-http://127.0.0.1:9090}"
    local result_file
    result_file="$(mktemp)"
    : > "$result_file"

    i=1
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        tag="$section-$i"
        i=$((i + 1))

        local raw_tag
        raw_tag="$(subscription_line_get_tag "$line")"

        local delay=""
        if [ "$force" = "1" ]; then
            local response
            response="$(curl -fsS --max-time 8 \
                "$base/proxies/$tag/delay?timeout=3000&url=$probe_url" \
                2>/dev/null)"
            delay="$(printf '%s' "$response" \
                | jq -r '.delay // empty' 2>/dev/null)"
        else
            local response
            response="$(curl -fsS --max-time 3 \
                "$base/proxies/$tag" 2>/dev/null)"
            delay="$(printf '%s' "$response" \
                | jq -r '.history // [] | map(.delay) | last // empty' \
                    2>/dev/null)"
        fi
        # Treat empty/null/0 as "no data".
        case "$delay" in
            ''|null|0) delay="" ;;
        esac

        # Tab-separated raw record; jq converts to JSON below.
        printf '%s\t%s\t%s\n' "$tag" "$raw_tag" "$delay" >> "$result_file"
    done < "$tmpfile"
    rm -f "$tmpfile"

    jq -R -s '
        split("\n")
        | map(select(. != ""))
        | map(split("\t"))
        | map({
            tag:     .[0],
            raw_tag: .[1],
            latency: (if (.[2] // "") == "" then null else (.[2] | tonumber? // null) end)
          })
    ' < "$result_file"
    rm -f "$result_file"
}

# vim: ft=sh ts=4 sw=4 et
