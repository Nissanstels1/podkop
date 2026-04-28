"use strict";
"require form";
"require baseclass";
"require fs";
"require ui";
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

  o = section.option(
    form.Value,
    "subscription_url",
    _("Subscription URL"),
    _(
      "HTTP(S) URL of a Marzban/Remna sing-box JSON subscription, or a base64-encoded list of proxy URIs (vless://, ss://, etc.).",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.rmempty = false;
  o.password = true;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return _("Subscription URL is required");
    }
    const v = main.validateUrl(value);
    return v.valid ? true : v.message;
  };

  // "Test connection" button — sanity-checks the URL currently typed into
  // the form WITHOUT saving. Calls /usr/bin/podkop subscription_test_url
  // which performs an HTTP HEAD with timing + format guess.
  o = section.option(
    form.Button,
    "_subscription_test_url_button",
    _("Test connection"),
    _(
      "Probe the URL above (without saving) — DNS, TCP, TLS handshake, HTTP code, body format. Useful to sanity-check a fresh subscription before clicking 'Save & Apply'.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    const url = (this.section.formvalue(section_id, "subscription_url") || "")
      .trim();
    const allowInsecure =
      this.section.formvalue(section_id, "subscription_allow_insecure") === "1"
        ? "1"
        : "0";

    if (!url) {
      ui.addNotification(
        null,
        E("p", {}, _("Set a subscription URL above first.")),
        "warning",
      );
      return;
    }

    const btn = ev.currentTarget;
    btn.disabled = true;
    const oldText = btn.innerHTML;
    btn.innerHTML = _("Testing…");

    return fs
      .exec("/usr/bin/podkop", [
        "subscription_test_url",
        url,
        allowInsecure,
        "podkop",
      ])
      .then(function (res) {
        let info;
        try {
          info = JSON.parse(res.stdout || "{}");
        } catch (e) {
          throw new Error(_("Cannot parse podkop response: %s").format(e));
        }

        const lines = [];
        if (info.ok) {
          lines.push(
            E(
              "p",
              {},
              _("HTTP %d · %d bytes · %d ms · format: %s").format(
                info.http_code || 0,
                info.size || 0,
                info.latency_ms || 0,
                info.format_guess || "?",
              ),
            ),
          );
        } else {
          lines.push(
            E(
              "p",
              {},
              _("Failed: %s (HTTP %d)").format(
                info.error || _("unknown error"),
                info.http_code || 0,
              ),
            ),
          );
        }
        if (info.remote_ip) {
          lines.push(
            E("p", {}, _("Resolved to: %s").format(info.remote_ip)),
          );
        }
        if (info.tls_ms && info.tls_ms > 0) {
          lines.push(
            E(
              "p",
              {},
              _("TLS handshake: %d ms").format(info.tls_ms),
            ),
          );
        }

        ui.addNotification(
          null,
          E("div", {}, lines),
          info.ok ? "info" : "danger",
        );
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
        btn.innerHTML = oldText;
      });
  };

  o = section.option(
    form.DynamicList,
    "subscription_url_fallback",
    _("Fallback Subscription URLs"),
    _(
      "Optional. Tried in order if the primary URL is unreachable or returns a non-2xx status. Useful when your panel has a mirror.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.password = true;
  o.placeholder = "https://mirror.example.com/abcdef";
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) return true;
    const v = main.validateUrl(value);
    return v.valid ? true : v.message;
  };

  o = section.option(
    form.ListValue,
    "subscription_format",
    _("Subscription Format"),
    _(
      "How to interpret the subscription body. 'auto' detects sing-box JSON vs base64 vs plain link list automatically.",
    ),
  );
  o.value("auto", _("Auto-detect"));
  o.value("sing-box", _("sing-box JSON outbounds"));
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
      "How often the subscription is refreshed in the background. On every successful refresh sing-box is reloaded.",
    ),
  );
  o.value("10m", _("Every 10 minutes"));
  o.value("1h", _("Every hour"));
  o.value("6h", _("Every 6 hours"));
  o.value("1d", _("Once a day"));
  o.value("off", _("Disabled (manual only)"));
  o.default = "1h";
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

  o = section.option(
    form.Flag,
    "subscription_drop_stuck",
    _("Adaptive rotation"),
    _(
      "When enabled, profiles whose Clash-API delay probes have failed three times in a row are excluded from the URLTest pool. They are auto-restored after 30 minutes or as soon as a probe succeeds again. Helps when a server pings fine but does not actually proxy traffic.",
    ),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("proxy_config_type", "subscription");

  o = section.option(
    form.Flag,
    "enable_kill_switch",
    _("Kill-switch"),
    _(
      "When enabled, traffic that the firewall has marked for proxying is dropped instead of leaking through the default route while sing-box is unreachable. Affects all sections (global). Recommended for privacy-sensitive setups.",
    ),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("proxy_config_type", "subscription");

  // Manual update + profiles browser.
  o = section.option(
    form.Button,
    "_subscription_update_button",
    _("Update subscription now"),
    _(
      "Refresh the subscription cache. The fetch+parse step is fast (~5s); reloading sing-box happens in the background so the LuCI request never times out.",
    ),
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
    btn.innerHTML = _("Starting…");

    // Translate raw stage IDs from /usr/bin/podkop subscription_progress
    // into human-friendly labels. We deliberately keep the labels short so
    // the button text doesn't wrap on narrow displays.
    const STAGE_LABELS = {
      start: _("Starting…"),
      fetching: _("Fetching…"),
      fetch_retry: _("Trying fallback URL…"),
      fetched: _("Fetched"),
      detecting: _("Detecting format…"),
      format: _("Format detected"),
      parsing: _("Parsing…"),
      parsed: _("Parsed"),
      unchanged: _("Unchanged"),
      done: _("Done"),
      error: _("Error"),
    };

    // Poll subscription_progress every 350ms while the update runs.
    // We render the most-recent stage as the button label so the user
    // sees real progress without a separate progress bar.
    let pollTimer = null;
    const startPoll = function () {
      const tick = function () {
        fs.exec("/usr/bin/podkop", [
          "subscription_progress",
          section_id,
        ])
          .then(function (res) {
            let info;
            try {
              info = JSON.parse(res.stdout || "{}");
            } catch (e) {
              return;
            }
            const stages = (info && info.stages) || [];
            if (stages.length === 0) return;
            const last = stages[stages.length - 1];
            const label = STAGE_LABELS[last.stage] || last.stage;
            const detail = last.detail ? " · " + last.detail : "";
            btn.innerHTML = label + detail;
          })
          .catch(function () {
            // Progress is best-effort; ignore poll failures.
          });
      };
      tick();
      pollTimer = window.setInterval(tick, 350);
    };
    const stopPoll = function () {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    startPoll();

    // Step 1: synchronous fetch + parse + cache rotation. Returns quickly.
    return fs
      .exec("/usr/bin/podkop", [
        "subscription_update",
        section_id,
        "--no-reload",
      ])
      .then(function (res) {
        stopPoll();
        if (res.code !== 0) {
          ui.addNotification(
            null,
            E(
              "p",
              {},
              _(
                "Subscription '%s' update failed (exit=%d). See system log.",
              ).format(section_id, res.code || -1),
            ),
            "danger",
          );
          return;
        }

        ui.addNotification(
          null,
          E(
            "p",
            {},
            _(
              "Subscription '%s' updated successfully. Reloading sing-box in the background…",
            ).format(section_id),
          ),
          "info",
        );

        // Step 2: trigger reload asynchronously (fire-and-forget). The shell
        // background-detaches sing-box reload so this fs.exec returns in
        // milliseconds even if reload itself takes 30-60s.
        return fs
          .exec("/bin/sh", [
            "-c",
            "nohup /usr/bin/podkop subscription_apply >/dev/null 2>&1 &",
          ])
          .catch(function () {
            // Last-resort: synchronous apply (still bounded since sing-box
            // reload typically completes well within fs.exec's timeout).
            return fs.exec("/usr/bin/podkop", ["subscription_apply"]);
          });
      })
      .catch(function (err) {
        stopPoll();
        ui.addNotification(
          null,
          E("p", {}, _("Error: %s").format(err.message || err)),
          "danger",
        );
      })
      .finally(function () {
        stopPoll();
        restoreBtn();
      });
  };

  // "Validate subscription" — runs a multi-stage pre-flight check and
  // displays a checklist modal so the user sees exactly which stage broke.
  o = section.option(
    form.Button,
    "_subscription_validate_button",
    _("Validate subscription"),
    _(
      "Run a pre-flight check on the saved subscription URL: DNS → TCP → TLS → HTTP → format → parse. Use this to debug why the subscription is failing without waiting for the next auto-update.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    const btn = ev.currentTarget;
    btn.disabled = true;
    const oldText = btn.innerHTML;
    btn.innerHTML = _("Validating…");

    return fs
      .exec("/usr/bin/podkop", ["subscription_validate", section_id])
      .then(function (res) {
        let info;
        try {
          info = JSON.parse(res.stdout || "{}");
        } catch (e) {
          throw new Error(_("Cannot parse podkop response"));
        }

        const checks = (info && info.checks) || [];
        const rows = checks.map(function (c) {
          const icon = c.ok
            ? E(
                "span",
                { style: "color:#5cb85c;font-weight:bold" },
                "✓",
              )
            : E(
                "span",
                { style: "color:#d9534f;font-weight:bold" },
                "✗",
              );
          return E("tr", { class: "tr" }, [
            E(
              "td",
              {
                class: "td",
                style: "text-align:center;width:30px;",
              },
              icon,
            ),
            E(
              "td",
              {
                class: "td",
                style:
                  "font-family:monospace;width:90px;text-transform:uppercase;",
              },
              c.stage,
            ),
            E("td", { class: "td" }, c.message || ""),
          ]);
        });

        const summary = info.ok
          ? E(
              "p",
              { class: "alert-message success" },
              _("All checks passed — subscription is reachable and parseable."),
            )
          : E(
              "p",
              { class: "alert-message warning" },
              _(
                "Validation failed at stage '%s'. Check the row marked ✗ below for details.",
              ).format(
                (checks.find(function (c) {
                  return !c.ok;
                }) || {}).stage || "?",
              ),
            );

        ui.showModal(
          _("Subscription validation — %s").format(section_id),
          [
            summary,
            E("table", { class: "table" }, [
              E("tr", { class: "tr table-titles" }, [
                E("th", { class: "th" }, ""),
                E("th", { class: "th" }, _("Stage")),
                E("th", { class: "th" }, _("Detail")),
              ]),
            ].concat(rows)),
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
          ],
        );
      })
      .catch(function (err) {
        ui.addNotification(
          null,
          E("p", {}, _("Validation error: %s").format(err.message || err)),
          "danger",
        );
      })
      .finally(function () {
        btn.disabled = false;
        btn.innerHTML = oldText;
      });
  };

  o = section.option(
    form.Button,
    "_subscription_show_button",
    _("Show parsed profiles"),
    _(
      "Open a list of all profiles parsed from the subscription, with a checkmark next to the ones that pass the current filter. Live latency, editable filters and per-server re-probing live in this modal.",
    ),
  );
  o.depends("proxy_config_type", "subscription");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    // Self-reference so we can use `o.section.formvalue(...)` inside the
    // modal even though `this` rebinds when click handlers fire.
    const sectionRef = this.section;

    // Mirror of the shell-side filter logic. Tag matches if any
    // `|`-separated token of any include entry is a substring of the tag.
    // Empty include list -> always include.
    const matchInclude = function (tag, entries) {
      if (!entries || entries.length === 0) return true;
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        if (!entry) continue;
        const tokens = String(entry).split("|");
        for (let j = 0; j < tokens.length; j++) {
          const tok = tokens[j];
          if (tok && String(tag).indexOf(tok) >= 0) return true;
        }
      }
      return false;
    };
    const matchExclude = function (tag, entries) {
      if (!entries || entries.length === 0) return false;
      return matchInclude(tag, entries);
    };

    // Pull *current* (possibly unsaved) filter values from the form so the
    // modal reflects what the user is editing right now, not just what is
    // saved on disk.
    const currentIncludes = function () {
      const v = sectionRef.formvalue(section_id, "subscription_filters");
      return Array.isArray(v) ? v.filter(Boolean) : v ? [v] : [];
    };
    const currentExcludes = function () {
      const v = sectionRef.formvalue(section_id, "subscription_exclude");
      return Array.isArray(v) ? v.filter(Boolean) : v ? [v] : [];
    };

    const latencyClass = function (ms) {
      if (ms == null) return "color:#888";
      if (ms < 100) return "color:#5cb85c;font-weight:bold";
      if (ms < 300) return "color:#f0ad4e;font-weight:bold";
      return "color:#d9534f;font-weight:bold";
    };
    const latencyText = function (ms) {
      if (ms == null) return "—";
      return String(ms) + " ms";
    };

    return Promise.all([
      fs.exec("/usr/bin/podkop", ["subscription_status", section_id]),
      fs.exec("/usr/bin/podkop", ["subscription_list", section_id]),
      fs.exec("/usr/bin/podkop", ["subscription_latency", section_id, "0"]),
    ])
      .then(function (results) {
        const status = JSON.parse(results[0].stdout || "{}");
        const list = JSON.parse(results[1].stdout || "[]");
        let latency;
        try {
          latency = JSON.parse(results[2].stdout || "[]");
        } catch (e) {
          latency = [];
        }
        // Map raw_tag -> latency for quick join.
        const latencyByTag = {};
        for (let i = 0; i < latency.length; i++) {
          latencyByTag[latency[i].raw_tag] = latency[i].latency;
        }

        const lastUpdate = status.last_update
          ? new Date(status.last_update * 1000).toLocaleString()
          : _("never");

        const headerChildren = [
          E("strong", {}, _("Status:") + " "),
          status.status || "-",
          " · ",
          E("strong", {}, _("Format:") + " "),
          status.format || "-",
          " · ",
          E("strong", {}, _("Last update:") + " "),
          lastUpdate,
        ];
        const matchedSpan = E("span", {}, "");
        headerChildren.push(
          " · ",
          E("strong", {}, _("Filtered:") + " "),
          matchedSpan,
        );
        if (status.fallback_in_use) {
          headerChildren.push(
            " · ",
            E(
              "span",
              {
                class: "label",
                style:
                  "background:#d9534f;color:#fff;padding:2px 6px;border-radius:3px;",
              },
              _("Cache fallback"),
            ),
          );
        }
        if (status.stuck && status.stuck > 0) {
          headerChildren.push(
            " · ",
            E(
              "span",
              {
                class: "label",
                style:
                  "background:#f0ad4e;color:#fff;padding:2px 6px;border-radius:3px;",
              },
              _("Stuck servers: %d").format(status.stuck),
            ),
          );
        }

        // ---- Live filter editor ------------------------------------
        // Two text fields prefilled from the form. Edits are debounced
        // and re-evaluate `matched` client-side without hitting the
        // backend. Saving the form is a separate concern.
        const includesInput = E("input", {
          type: "text",
          placeholder: "NL|DE|FI",
          style: "font-family:monospace;width:100%;box-sizing:border-box;",
          value: currentIncludes().join(","),
        });
        const excludesInput = E("input", {
          type: "text",
          placeholder: "expired|trial",
          style: "font-family:monospace;width:100%;box-sizing:border-box;",
          value: currentExcludes().join(","),
        });

        const tableBody = E("tbody", {}, []);

        const renderRows = function () {
          const incEntries = (includesInput.value || "")
            .split(",")
            .map(function (s) {
              return s.trim();
            })
            .filter(Boolean);
          const excEntries = (excludesInput.value || "")
            .split(",")
            .map(function (s) {
              return s.trim();
            })
            .filter(Boolean);

          let matchedCount = 0;
          const rows = list.map(function (it) {
            const isMatch =
              matchInclude(it.tag || "", incEntries) &&
              !matchExclude(it.tag || "", excEntries);
            if (isMatch) matchedCount++;
            const ms = latencyByTag.hasOwnProperty(it.tag)
              ? latencyByTag[it.tag]
              : null;
            return E(
              "tr",
              {
                class: "tr",
                style: isMatch ? "" : "opacity:0.55",
              },
              [
                E(
                  "td",
                  { class: "td", style: "text-align:center;width:32px;" },
                  isMatch ? "✓" : "",
                ),
                E(
                  "td",
                  { class: "td", style: "font-family:monospace;" },
                  it.tag || "-",
                ),
                E(
                  "td",
                  { class: "td", style: "width:80px;" },
                  it.kind === "json" ? it.type || "json" : "url",
                ),
                E(
                  "td",
                  { class: "td", style: "font-family:monospace;" },
                  it.endpoint || "-",
                ),
                E(
                  "td",
                  {
                    class: "td",
                    style:
                      "text-align:right;font-family:monospace;width:90px;" +
                      latencyClass(ms),
                  },
                  latencyText(ms),
                ),
              ],
            );
          });

          // Repaint matchedCount in header.
          while (matchedSpan.firstChild) {
            matchedSpan.removeChild(matchedSpan.firstChild);
          }
          matchedSpan.appendChild(
            document.createTextNode(
              String(matchedCount) + " / " + String(list.length),
            ),
          );

          // Repaint table body.
          while (tableBody.firstChild) {
            tableBody.removeChild(tableBody.firstChild);
          }
          rows.forEach(function (r) {
            tableBody.appendChild(r);
          });
        };

        // Debounce keystrokes so we don't redraw on every char.
        let debounceTimer = null;
        const onFilterEdit = function () {
          if (debounceTimer !== null) window.clearTimeout(debounceTimer);
          debounceTimer = window.setTimeout(renderRows, 120);
        };
        includesInput.addEventListener("input", onFilterEdit);
        excludesInput.addEventListener("input", onFilterEdit);

        const filterPanel = E(
          "div",
          {
            style:
              "display:grid;grid-template-columns:140px 1fr;gap:6px 12px;align-items:center;margin:8px 0;",
          },
          [
            E(
              "label",
              { style: "font-weight:bold;" },
              _("Include filter (csv)"),
            ),
            includesInput,
            E(
              "label",
              { style: "font-weight:bold;" },
              _("Exclude filter (csv)"),
            ),
            excludesInput,
            E("div", {}, ""),
            E(
              "div",
              { class: "cbi-value-description" },
              _(
                "Edits are applied live in this modal only. Save & Apply to persist them. Use ',' between entries; '|' inside one entry means OR.",
              ),
            ),
          ],
        );

        // ---- Latency re-probe button -------------------------------
        const reprobeBtn = E(
          "button",
          {
            class: "btn",
            style: "margin-right:6px;",
          },
          _("Re-probe latency"),
        );
        reprobeBtn.addEventListener("click", function () {
          reprobeBtn.disabled = true;
          const oldText = reprobeBtn.innerHTML;
          reprobeBtn.innerHTML = _("Probing…");
          fs.exec("/usr/bin/podkop", [
            "subscription_latency",
            section_id,
            "1",
          ])
            .then(function (res) {
              let fresh;
              try {
                fresh = JSON.parse(res.stdout || "[]");
              } catch (e) {
                fresh = [];
              }
              for (let i = 0; i < fresh.length; i++) {
                latencyByTag[fresh[i].raw_tag] = fresh[i].latency;
              }
              renderRows();
            })
            .catch(function () {
              ui.addNotification(
                null,
                E("p", {}, _("Re-probe failed; is sing-box running?")),
                "warning",
              );
            })
            .finally(function () {
              reprobeBtn.disabled = false;
              reprobeBtn.innerHTML = oldText;
            });
        });

        const tableEl = E("table", { class: "table" }, [
          E("thead", {}, [
            E("tr", { class: "tr table-titles" }, [
              E("th", { class: "th" }, _("Match")),
              E("th", { class: "th" }, _("Tag")),
              E("th", { class: "th" }, _("Type")),
              E("th", { class: "th" }, _("Endpoint")),
              E(
                "th",
                { class: "th", style: "text-align:right;" },
                _("Latency"),
              ),
            ]),
          ]),
          tableBody,
        ]);

        renderRows();

        ui.showModal(_("Subscription profiles — %s").format(section_id), [
          E("p", {}, headerChildren),
          filterPanel,
          list.length === 0
            ? E(
                "p",
                { class: "alert-message warning" },
                _(
                  "No profiles parsed yet. Click 'Update subscription now' first.",
                ),
              )
            : tableEl,
          E("div", { class: "right" }, [
            reprobeBtn,
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
