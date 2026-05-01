"use strict";
"require form";
"require baseclass";
"require fs";
"require ui";
"require uci";
"require tools.widgets as widgets";
"require view.podkop.main as main";

function createSectionContent(section) {
  let o = section.option(
    form.ListValue,
    "connection_type",
    _("Connection Type"),
    _("Select between VPN and Proxy connection methods for traffic routing"),
  );
  o.value("proxy", "Proxy");
  o.value("vpn", "VPN");
  o.value("block", "Block");
  o.value("exclusion", "Exclusion");

  o = section.option(
    form.ListValue,
    "proxy_config_type",
    _("Configuration Type"),
    _("Select how to configure the proxy"),
  );
  o.value("url", _("Connection URL"));
  o.value("selector", _("Selector"));
  o.value("urltest", _("URLTest"));
  o.value("subscription", _("Subscription"));
  o.value("outbound", _("Outbound Config"));
  o.default = "url";
  o.depends("connection_type", "proxy");

  o = section.option(
    form.TextValue,
    "proxy_string",
    _("Proxy Configuration URL"),
    _("vless://, ss://, trojan://, socks4/5://, hy2/hysteria2:// links"),
  );
  o.depends("proxy_config_type", "url");
  o.rows = 5;
  // Enable soft wrapping for multi-line proxy URLs (e.g., for URLTest proxy links)
  o.wrap = "soft";
  // Render as a textarea to allow multiple proxy URLs/configs
  o.textarea = true;
  o.rmempty = false;
  o.sectionDescriptions = new Map();
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "outbound_json",
    _("Outbound Configuration"),
    _("Enter complete outbound configuration in JSON format"),
  );
  o.depends("proxy_config_type", "outbound");
  o.rows = 10;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateOutboundJson(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "selector_proxy_links",
    _("Selector Proxy Links"),
    _("vless://, ss://, trojan://, socks4/5://, hy2/hysteria2:// links"),
  );
  o.depends("proxy_config_type", "selector");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "urltest_proxy_links",
    _("URLTest Proxy Links"),
    _("vless://, ss://, trojan://, socks4/5://, hy2/hysteria2:// links"),
  );
  o.depends("proxy_config_type", "urltest");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.ListValue,
    "urltest_check_interval",
    _("URLTest Check Interval"),
    _("The interval between connectivity tests"),
  );
  o.value("30s", _("Every 30 seconds"));
  o.value("1m", _("Every 1 minute"));
  o.value("3m", _("Every 3 minutes"));
  o.value("5m", _("Every 5 minutes"));
  o.default = "3m";
  o.depends("proxy_config_type", "urltest");
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.Value,
    "urltest_tolerance",
    _("URLTest Tolerance"),
    _(
      "The maximum difference in response times (ms) allowed when comparing servers",
    ),
  );
  o.default = "50";
  o.rmempty = false;
  o.depends("proxy_config_type", "urltest");
  o.depends("proxy_config_type", "subscription");
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }

    const parsed = parseFloat(value);

    if (
      /^[0-9]+$/.test(value) &&
      !isNaN(parsed) &&
      isFinite(parsed) &&
      parsed >= 50 &&
      parsed <= 1000
    ) {
      return true;
    }

    return _("Must be a number in the range of 50 - 1000");
  };

  o = section.option(
    form.Value,
    "urltest_testing_url",
    _("URLTest Testing URL"),
    _("The URL used to test server connectivity"),
  );
  o.value(
    "https://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204 (Google)",
  );
  o.value(
    "https://cp.cloudflare.com/generate_204",
    "https://cp.cloudflare.com/generate_204 (Cloudflare)",
  );
  o.value("https://captive.apple.com", "https://captive.apple.com (Apple)");
  o.value(
    "https://connectivity-check.ubuntu.com",
    "https://connectivity-check.ubuntu.com (Ubuntu)",
  );
  o.default = "https://www.gstatic.com/generate_204";
  o.rmempty = false;
  o.depends("proxy_config_type", "urltest");
  o.depends("proxy_config_type", "subscription");

  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  // ---------- Subscription ----------------------------------------------

  // New (v2): multi-URL subscription pool, edited as a textarea (one URL per
  // line). We previously used form.DynamicList here, but that widget only
  // commits a typed value when the user explicitly clicks "+" or presses
  // Enter — pasting a URL and hitting Save was silently losing it. A textarea
  // is the safest UX: every keystroke is part of the value. We map between the
  // textarea contents and a UCI `list subscription_urls` so the backend reads
  // it the same way as before. The init script migrates old `option
  // subscription_url` configs on first boot after upgrade.
  o = section.option(
    form.TextValue,
    "subscription_urls",
    _("Subscription URLs"),
    _(
      "One or more HTTP(S) URLs to fetch — one per line. Supported formats: " +
        "sing-box JSON, Clash YAML, v2ray JSON, base64-encoded link lists, or " +
        "plain link lists. All sources are merged and deduplicated by " +
        "tag+endpoint. Use http:// only for trusted local panels — a warning " +
        "will be shown.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.placeholder = "https://panel.example.com/sub/abc";
  o.rows = 4;
  o.wrap = "off";
  // Render textarea as plain text (don't mask) — URLs are not secrets in the
  // OpenWrt context (rooted UCI is already readable). Masking caused users to
  // paste-and-forget when the value was hidden.

  // Marshal between textarea (single string with newlines) and UCI list.
  o.cfgvalue = function (section_id) {
    let v = uci.get("podkop", section_id, "subscription_urls");
    if (v == null) {
      // Fallback: legacy single-URL field. Show it inside the textarea so the
      // user can see and edit their existing URL even before migration runs.
      const legacy = uci.get("podkop", section_id, "subscription_url");
      return legacy != null ? String(legacy) : "";
    }
    if (Array.isArray(v)) return v.join("\n");
    return String(v);
  };
  o.write = function (section_id, value) {
    const lines = String(value || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    uci.set("podkop", section_id, "subscription_urls", lines);
    // Drop the legacy single-URL field once the user has populated the new
    // list — keeps the config clean and avoids ambiguity for the backend.
    uci.unset("podkop", section_id, "subscription_url");
  };
  o.remove = function (section_id) {
    uci.unset("podkop", section_id, "subscription_urls");
    uci.unset("podkop", section_id, "subscription_url");
  };
  o.validate = function (section_id, value) {
    const lines = String(value || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    for (let i = 0; i < lines.length; i++) {
      const v = main.validateUrl(lines[i]);
      if (!v.valid) return v.message + " — " + lines[i];
    }
    return true;
  };

  o = section.option(
    form.ListValue,
    "subscription_format",
    _("Subscription Format"),
    _(
      "How to interpret the subscription body. 'auto' detects sing-box JSON, " +
        "Clash YAML, v2ray JSON, base64 or plain link list automatically. " +
        "Only override if auto-detection picks the wrong format.",
    ),
  );
  o.value("auto", _("Auto-detect (recommended)"));
  o.value("sing-box", _("sing-box JSON outbounds"));
  o.value("clash", _("Clash / clash.meta YAML"));
  o.value("v2ray", _("v2ray JSON"));
  o.value("base64", _("Base64 list of links"));
  o.value("plain", _("Plain list of links"));
  o.default = "auto";
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.Value,
    "subscription_user_agent",
    _("User-Agent"),
    _(
      "Some panels return different formats depending on the User-Agent. 'auto' picks SFA/1.11.9 for sing-box format, 'podkop' otherwise. Override with any string if your panel needs a specific UA.",
    ),
  );
  o.value("auto", _("Auto"));
  o.value("SFA/1.11.9", "SFA/1.11.9 (sing-box)");
  o.value("podkop", "podkop");
  o.value("clash.meta", "clash.meta");
  o.default = "auto";
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.ListValue,
    "subscription_mode",
    _("Selection Mode"),
    _(
      "URLTest: sing-box pings every server periodically and routes via the fastest one (recommended). Selector: defaults to the first matched server; switch via Clash dashboard.",
    ),
  );
  o.value("urltest", _("URLTest (auto-best by latency)"));
  o.value("selector", _("Selector (manual)"));
  o.default = "urltest";
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.DynamicList,
    "subscription_filters",
    _("Tag Filters (include)"),
    _(
      "Substring filters applied to the proxy tag/name. Use '|' inside one row for OR (e.g. 'NL|DE|FI' or '🇩🇪|🇳🇱'). Multiple rows are also OR'd. Leave empty to include every profile.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.placeholder = "NL|DE|FI";

  o = section.option(
    form.DynamicList,
    "subscription_exclude",
    _("Tag Filters (exclude)"),
    _(
      "Drop any profile whose tag matches any of these substrings. Same OR-with-'|' syntax as above.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.placeholder = "expired|trial";

  o = section.option(
    form.ListValue,
    "subscription_update_interval",
    _("Auto-update Interval"),
    _(
      "How often the subscription is refreshed in the background. On every successful refresh sing-box is reloaded. " +
        "'Auto (smart)' adapts: 7 unchanged updates in a row → bump tier coarser " +
        "(10m → 1h → 6h → 1d); any change → tighten one tier. Cuts panel load when nothing changes.",
    ),
  );
  o.value("auto", _("Auto (smart adaptive)"));
  o.value("10m", _("Every 10 minutes"));
  o.value("1h", _("Every hour"));
  o.value("6h", _("Every 6 hours"));
  o.value("1d", _("Once a day (recommended)"));
  o.value("off", _("Disabled (manual only)"));
  o.default = "1d";
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.Flag,
    "subscription_allow_insecure",
    _("Allow Insecure TLS"),
    _(
      "Accept self-signed / expired TLS certificates when fetching the subscription. Only enable if you trust the endpoint.",
    ),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("proxy_config_type", "subscription");

  // ---------- Latency-based filtering & pool-split (v2) -----------------

  o = section.option(
    form.Value,
    "subscription_ping_min",
    _("Min Latency (ms)"),
    _(
      "Drop profiles faster than this latency. Useful to exclude in-country " +
        "servers when you specifically want servers abroad. 0 = no lower bound. " +
        "Latency values are populated by the background latency collector.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.placeholder = "0";
  o.datatype = "uinteger";
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.Value,
    "subscription_ping_max",
    _("Max Latency (ms)"),
    _(
      "Drop profiles slower than this latency. 0 = no upper bound. " +
        "Profiles without a measurement yet are kept (so a brand new subscription " +
        "still has working entries while measurements accumulate).",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.placeholder = "0";
  o.datatype = "uinteger";
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.Flag,
    "subscription_pool_split",
    _("Split into fast / slow pools"),
    _(
      "Build TWO urltest groups: <section>-fast (latency < threshold) and " +
        "<section>-slow (the rest). Selector defaults to fast; a watchdog " +
        "auto-switches to slow when every fast profile is dead and back to " +
        "fast on recovery. Recommended for big subscriptions where some " +
        "regions are flaky.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.Value,
    "subscription_fast_threshold_ms",
    _("Fast pool threshold (ms)"),
    _(
      "Profiles with latency < threshold go into the fast pool, the rest into " +
        "the slow pool. Default 100 ms.",
    ),
  );
  o.depends("subscription_pool_split", "1");
  o.placeholder = "100";
  o.datatype = "uinteger";
  o.default = "100";

  // ---------- DNS-over-proxy (v2) ---------------------------------------

  o = section.option(
    form.Flag,
    "subscription_dns_over_proxy",
    _("DNS over proxy (per-section)"),
    _(
      "Resolve the listed domains through the proxy by default, falling back " +
        "to the local resolver if the proxy DNS times out. Useful to avoid " +
        "leaking sensitive resolutions to your ISP. Opt-in.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "subscription_dns_over_proxy_domains",
    _("DNS-over-proxy domains"),
    _(
      "Domains to resolve through the proxy (one per row). Subdomains are " +
        "matched automatically. Example: chatgpt.com, openai.com, *.youtube.com.",
    ),
  );
  o.depends("subscription_dns_over_proxy", "1");
  o.placeholder = "chatgpt.com";

  o = section.option(
    form.Value,
    "subscription_dns_over_proxy_timeout_ms",
    _("DNS-over-proxy timeout (ms)"),
    _(
      "Fall back to the local resolver if the proxy DNS does not answer within this many milliseconds.",
    ),
  );
  o.depends("subscription_dns_over_proxy", "1");
  o.placeholder = "2000";
  o.datatype = "uinteger";
  o.default = "2000";

  // Manual update + profiles browser.
  o = section.option(
    form.Button,
    "_subscription_update_button",
    _("Update subscription now"),
    _("Refresh the subscription cache and reload sing-box."),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "apply";
  o.onclick = function (ev, section_id) {
    const btn = ev.currentTarget;
    const restoreBtn = function () {
      btn.disabled = false;
      btn.innerHTML = _("Update subscription now");
    };
    btn.disabled = true;
    btn.innerHTML = _("Saving…");
    // First persist any pending edits the user has made (especially the
    // Subscription URLs textarea), then commit UCI, then call the CLI. Without
    // this, clicking Update before Save & Apply runs against an empty config.
    return this.map
      .save(null, true)
      .then(function () {
        return fs.exec("/sbin/uci", ["commit", "podkop"]);
      })
      .then(function () {
        btn.innerHTML = _("Updating…");
        return fs.exec("/usr/bin/podkop", [
          "subscription_update",
          section_id,
        ]);
      })
      .then(function (res) {
        if (res && res.code === 0) {
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _("Subscription '%s' updated successfully.").format(section_id),
            ),
            "info",
          );
        } else if (res && res.code === 2) {
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _(
                "Subscription '%s': no URLs configured. Add at least one URL to the field above and click Save & Apply.",
              ).format(section_id),
            ),
            "warning",
          );
        } else {
          const code = res && res.code != null ? res.code : -1;
          const stderr = (res && res.stderr) || "";
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _(
                "Subscription '%s' update failed (exit=%d). See system log. %s",
              ).format(section_id, code, stderr),
            ),
            "danger",
          );
        }
      })
      .catch(function (err) {
        ui.addNotification(
          null,
          E("p", {}, _("Error: %s").format(err.message || err)),
          "danger",
        );
      })
      .finally(restoreBtn);
  };

  o = section.option(
    form.Button,
    "_subscription_show_button",
    _("Show parsed profiles"),
    _(
      "Open a list of all profiles parsed from the subscription, with a checkmark next to the ones that pass the current filter.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    return Promise.all([
      fs.exec("/usr/bin/podkop", ["subscription_status", section_id]),
      fs.exec("/usr/bin/podkop", ["subscription_list", section_id]),
    ])
      .then(function (results) {
        const status = JSON.parse(results[0].stdout || "{}");
        const list = JSON.parse(results[1].stdout || "[]");

        const lastUpdate = status.last_update
          ? new Date(status.last_update * 1000).toLocaleString()
          : _("never");

        const rows = list.map(function (it) {
          let poolBadge = "-";
          if (it.pool === "fast") {
            poolBadge = E(
              "span",
              { style: "color:#2c7;font-weight:bold" },
              "fast",
            );
          } else if (it.pool === "slow") {
            poolBadge = E(
              "span",
              { style: "color:#d70;font-weight:bold" },
              "slow",
            );
          }
          const latText =
            it.latency_ms === null || it.latency_ms === undefined
              ? "-"
              : it.latency_ms < 0
                ? "timeout"
                : String(it.latency_ms) + " ms";
          return E("tr", { class: "tr" }, [
            E(
              "td",
              { class: "td", style: "text-align:center" },
              it.matched ? "✓" : "",
            ),
            E(
              "td",
              { class: "td", style: "font-family:monospace" },
              it.tag || "-",
            ),
            E(
              "td",
              { class: "td" },
              it.kind === "json" ? it.type || "json" : "url",
            ),
            E(
              "td",
              { class: "td", style: "font-family:monospace" },
              it.endpoint || "-",
            ),
            E(
              "td",
              { class: "td", style: "text-align:right;font-family:monospace" },
              latText,
            ),
            E("td", { class: "td", style: "text-align:center" }, poolBadge),
          ]);
        });

        const table = E(
          "table",
          { class: "table" },
          [
            E("tr", { class: "tr table-titles" }, [
              E("th", { class: "th" }, _("Match")),
              E("th", { class: "th" }, _("Tag")),
              E("th", { class: "th" }, _("Type")),
              E("th", { class: "th" }, _("Endpoint")),
              E("th", { class: "th" }, _("Latency")),
              E("th", { class: "th" }, _("Pool")),
            ]),
          ].concat(rows),
        );

        const tierLine = status.tier
          ? " · " +
            _("Tier: %s (streak %s)").format(
              status.tier,
              String(status.unchanged_streak || 0),
            )
          : "";
        const sourcesLine = status.urls_count
          ? " · " + _("Sources: %s").format(String(status.urls_count))
          : "";

        ui.showModal(_("Subscription profiles — %s").format(section_id), [
          E("p", {}, [
            E("strong", {}, _("Status:") + " "),
            status.status || "-",
            " · ",
            E("strong", {}, _("Format:") + " "),
            status.format || "-",
            " · ",
            E("strong", {}, _("Last update:") + " "),
            lastUpdate,
            " · ",
            E("strong", {}, _("Filtered:") + " "),
            String(status.filtered || 0),
            " / ",
            String(status.total || 0),
            tierLine,
            sourcesLine,
          ]),
          status.fast || status.slow
            ? E("p", {}, [
                E("strong", { style: "color:#2c7" }, _("Fast pool:") + " "),
                String(status.fast || 0),
                " · ",
                E("strong", { style: "color:#d70" }, _("Slow pool:") + " "),
                String(status.slow || 0),
              ])
            : "",
          rows.length === 0
            ? E(
                "p",
                { class: "alert-message warning" },
                _(
                  "No profiles parsed yet. Click 'Update subscription now' first.",
                ),
              )
            : table,
          E("div", { class: "right" }, [
            E(
              "button",
              {
                class: "btn",
                click: ui.hideModal,
              },
              _("Close"),
            ),
          ]),
        ]);
      })
      .catch(function (err) {
        ui.addNotification(
          null,
          E(
            "p",
            {},
            _("Failed to load profiles: %s").format(err.message || err),
          ),
          "danger",
        );
      });
  };

  o = section.option(
    form.Button,
    "_subscription_refresh_latency_button",
    _("Refresh latency cache"),
    _(
      "Re-poll the Clash API for current latency of every profile and re-apply " +
        "the ping-range filter / pool split.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    const btn = ev.currentTarget;
    btn.disabled = true;
    btn.innerHTML = _("Refreshing…");
    return fs
      .exec("/usr/bin/podkop", ["subscription_collect_latency", section_id])
      .then(function (res) {
        if (res.code === 0) {
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _("Latency cache refreshed for '%s'.").format(section_id),
            ),
            "info",
          );
        } else {
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _(
                "Latency refresh failed (exit=%d). Is sing-box running and Clash API enabled?",
              ).format(res.code || -1),
            ),
            "warning",
          );
        }
      })
      .catch(function (err) {
        ui.addNotification(
          null,
          E("p", {}, _("Error: %s").format(err.message || err)),
          "danger",
        );
      })
      .finally(function () {
        btn.disabled = false;
        btn.innerHTML = _("Refresh latency cache");
      });
  };

  // ---------- /Subscription ---------------------------------------------

  o = section.option(
    form.Flag,
    "enable_udp_over_tcp",
    _("UDP over TCP"),
    _("Applicable for SOCKS and Shadowsocks proxy"),
  );
  o.default = "0";
  o.depends("connection_type", "proxy");
  o.rmempty = false;

  o = section.option(
    widgets.DeviceSelect,
    "interface",
    _("Network Interface"),
    _("Select network interface for VPN connection"),
  );
  o.depends("connection_type", "vpn");
  o.noaliases = true;
  o.nobridges = false;
  o.noinactive = false;
  o.filter = function (section_id, value) {
    // Blocked interface names that should never be selectable
    const blockedInterfaces = [
      "br-lan",
      "eth0",
      "eth1",
      "wan",
      "phy0-ap0",
      "phy1-ap0",
      "pppoe-wan",
      "lan",
    ];

    // Reject immediately if the value matches any blocked interface
    if (blockedInterfaces.includes(value)) {
      return false;
    }

    // Try to find the device object with the given name
    const device = this.devices.find((dev) => dev.getName() === value);

    // If no device is found, allow the value
    if (!device) {
      return true;
    }

    // Get the device type (e.g., "wifi", "ethernet", etc.)
    const type = device.getType();

    // Reject wireless-related devices
    const isWireless =
      type === "wifi" || type === "wireless" || type.includes("wlan");

    return !isWireless;
  };

  o = section.option(
    form.Flag,
    "domain_resolver_enabled",
    _("Domain Resolver"),
    _("Enable built-in DNS resolver for domains handled by this section"),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("connection_type", "vpn");

  o = section.option(
    form.ListValue,
    "domain_resolver_dns_type",
    _("DNS Protocol Type"),
    _("Select the DNS protocol type for the domain resolver"),
  );
  o.value("doh", _("DNS over HTTPS (DoH)"));
  o.value("dot", _("DNS over TLS (DoT)"));
  o.value("udp", _("UDP (Unprotected DNS)"));
  o.default = "udp";
  o.rmempty = false;
  o.depends("domain_resolver_enabled", "1");

  o = section.option(
    form.Value,
    "domain_resolver_dns_server",
    _("DNS Server"),
    _("Select or enter DNS server address"),
  );
  Object.entries(main.DNS_SERVER_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.default = "8.8.8.8";
  o.rmempty = false;
  o.depends("domain_resolver_enabled", "1");
  o.validate = function (section_id, value) {
    const validation = main.validateDNS(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "community_lists",
    _("Community Lists"),
    _("Select a predefined list for routing") +
      ' <a href="https://github.com/itdoginfo/allow-domains" target="_blank">github.com/itdoginfo/allow-domains</a>',
  );
  o.placeholder = "Service list";
  Object.entries(main.DOMAIN_LIST_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.rmempty = true;
  let lastValues = [];
  let isProcessing = false;

  o.onchange = function (ev, section_id, value) {
    if (isProcessing) return;
    isProcessing = true;

    try {
      const values = Array.isArray(value) ? value : [value];
      let newValues = [...values];
      let notifications = [];

      const selectedRegionalOptions = main.REGIONAL_OPTIONS.filter((opt) =>
        newValues.includes(opt),
      );

      if (selectedRegionalOptions.length > 1) {
        const lastSelected =
          selectedRegionalOptions[selectedRegionalOptions.length - 1];
        const removedRegions = selectedRegionalOptions.slice(0, -1);
        newValues = newValues.filter(
          (v) => v === lastSelected || !main.REGIONAL_OPTIONS.includes(v),
        );
        notifications.push(
          E("p", {}, [
            E("strong", {}, _("Regional options cannot be used together")),
            E("br"),
            _(
              "Warning: %s cannot be used together with %s. Previous selections have been removed.",
            ).format(removedRegions.join(", "), lastSelected),
          ]),
        );
      }

      if (newValues.includes("russia_inside")) {
        const removedServices = newValues.filter(
          (v) => !main.ALLOWED_WITH_RUSSIA_INSIDE.includes(v),
        );
        if (removedServices.length > 0) {
          newValues = newValues.filter((v) =>
            main.ALLOWED_WITH_RUSSIA_INSIDE.includes(v),
          );
          notifications.push(
            E("p", { class: "alert-message warning" }, [
              E("strong", {}, _("Russia inside restrictions")),
              E("br"),
              _(
                "Warning: Russia inside can only be used with %s. %s already in Russia inside and have been removed from selection.",
              ).format(
                main.ALLOWED_WITH_RUSSIA_INSIDE.map(
                  (key) => main.DOMAIN_LIST_OPTIONS[key],
                )
                  .filter((label) => label !== "Russia inside")
                  .join(", "),
                removedServices.join(", "),
              ),
            ]),
          );
        }
      }

      if (JSON.stringify(newValues.sort()) !== JSON.stringify(values.sort())) {
        this.getUIElement(section_id).setValue(newValues);
      }

      notifications.forEach((notification) =>
        ui.addNotification(null, notification),
      );
      lastValues = newValues;
    } catch (e) {
      console.error("Error in onchange handler:", e);
    } finally {
      isProcessing = false;
    }
  };

  o = section.option(
    form.ListValue,
    "user_domain_list_type",
    _("User Domain List Type"),
    _("Select the list type for adding custom domains"),
  );
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "user_domains",
    _("User Domains"),
    _(
      "Enter domain names without protocols, e.g. example.com or sub.example.com",
    ),
  );
  o.placeholder = "Domains list";
  o.depends("user_domain_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateDomain(value, true);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "user_domains_text",
    _("User Domains List"),
    _(
      "Enter domain names separated by commas, spaces, or newlines. You can add comments using //",
    ),
  );
  o.placeholder =
    "example.com, sub.example.com\n// Social networks\ndomain.com test.com // personal domains";
  o.depends("user_domain_list_type", "text");
  o.rows = 8;
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const domains = main.parseValueList(value);

    if (!domains.length) {
      return _(
        "At least one valid domain must be specified. Comments-only content is not allowed.",
      );
    }

    const { valid, results } = main.bulkValidate(domains, (row) =>
      main.validateDomain(row, true),
    );

    if (!valid) {
      const errors = results
        .filter((validation) => !validation.valid) // Leave only failed validations
        .map((validation) => `${validation.value}: ${validation.message}`); // Collect validation errors

      return [_("Validation errors:"), ...errors].join("\n");
    }

    return true;
  };

  o = section.option(
    form.ListValue,
    "user_subnet_list_type",
    _("User Subnet List Type"),
    _("Select the list type for adding custom subnets"),
  );
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "user_subnets",
    _("User Subnets"),
    _(
      "Enter subnets in CIDR notation (e.g. 103.21.244.0/22) or single IP addresses",
    ),
  );
  o.placeholder = "IP or subnet";
  o.depends("user_subnet_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateSubnet(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "user_subnets_text",
    _("User Subnets List"),
    _(
      "Enter subnets in CIDR notation or single IP addresses, separated by commas, spaces, or newlines. You can add comments using //",
    ),
  );
  o.placeholder =
    "103.21.244.0/22\n// Google DNS\n8.8.8.8\n1.1.1.1/32, 9.9.9.9 // Cloudflare and Quad9";
  o.depends("user_subnet_list_type", "text");
  o.rows = 10;
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const subnets = main.parseValueList(value);

    if (!subnets.length) {
      return _(
        "At least one valid subnet or IP must be specified. Comments-only content is not allowed.",
      );
    }

    const { valid, results } = main.bulkValidate(subnets, main.validateSubnet);

    if (!valid) {
      const errors = results
        .filter((validation) => !validation.valid) // Leave only failed validations
        .map((validation) => `${validation.value}: ${validation.message}`); // Collect validation errors

      return [_("Validation errors:"), ...errors].join("\n");
    }

    return true;
  };

  o = section.option(
    form.DynamicList,
    "local_domain_lists",
    _("Local Domain Lists"),
    _("Specify the path to the list file located on the router filesystem"),
  );
  o.placeholder = "/path/file.lst";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validatePath(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "local_subnet_lists",
    _("Local Subnet Lists"),
    _("Specify the path to the list file located on the router filesystem"),
  );
  o.placeholder = "/path/file.lst";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validatePath(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "remote_domain_lists",
    _("Remote Domain Lists"),
    _("Specify remote URLs to download and use domain lists"),
  );
  o.placeholder = "https://example.com/domains.srs";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "remote_subnet_lists",
    _("Remote Subnet Lists"),
    _("Specify remote URLs to download and use subnet lists"),
  );
  o.placeholder = "https://example.com/subnets.srs";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "fully_routed_ips",
    _("Fully Routed IPs"),
    _(
      "Specify local IP addresses or subnets whose traffic will always be routed through the configured route",
    ),
  );
  o.placeholder = "192.168.1.2 or 192.168.1.0/24";
  o.rmempty = true;
  o.depends("connection_type", "proxy");
  o.depends("connection_type", "vpn");
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateSubnet(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.Flag,
    "mixed_proxy_enabled",
    _("Enable Mixed Proxy"),
    _(
      "Enable the mixed proxy, allowing this section to route traffic through both HTTP and SOCKS proxies",
    ),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("connection_type", "proxy");
  o.depends("connection_type", "vpn");

  o = section.option(
    form.Value,
    "mixed_proxy_port",
    _("Mixed Proxy Port"),
    _(
      "Specify the port number on which the mixed proxy will run for this section. Make sure the selected port is not used by another service",
    ),
  );
  o.rmempty = false;
  o.depends("mixed_proxy_enabled", "1");
}

const EntryPoint = {
  createSectionContent,
};

return baseclass.extend(EntryPoint);
