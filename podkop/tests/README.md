# Subscription tests

Standalone tests for `usr/lib/subscription.sh`. They mock UCI helpers and
spin up a tiny HTTP server (`python3 -m http.server`) — no OpenWrt box
required.

```sh
# Unit-level (parser, filter, format detection, UA selection)
sh podkop/tests/test_subscription.sh

# End-to-end (HTTP fetch -> parse -> cache -> filtered load -> JSON status)
sh podkop/tests/test_subscription_e2e.sh
```

Both scripts exit non-zero if anything fails and print a PASS/FAIL summary.

`REPO_ROOT` env var can override the repo location (defaults to
`/home/ubuntu/repos/podkop`).
