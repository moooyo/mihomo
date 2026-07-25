# Runtime overlay: live verification

These exercise the runtime overlay against a *running* mihomo, which the Go
tests deliberately cannot: the socket permissions, the peer-verified transports,
the controller guards, restart recovery and the durable store all only exist in
a real process.

Both bugs that shipped past the unit tests were found here, and both had the
same shape — a validator reading live global state at a point in startup where
nothing had populated it yet. Neither is reachable from a unit test that
constructs the manager directly.

## Running

```sh
# on the target host
mihomo -d ./test/overlay -f ./test/overlay/config.yaml &
bash ./test/overlay/live-test-1.sh
bash ./test/overlay/live-test-2.sh
```

`live-test-2.sh` restarts mihomo itself and expects the binary at
`/tmp/mihomo-overlay`; adjust the two `nohup` lines for another path.

## The bypass matrix

Every `neg-*.yaml` is `config.yaml` with exactly one bypass carrier
reintroduced. Each must be **rejected** by `mihomo -t`:

| File | Carrier |
| --- | --- |
| `neg-mode.yaml` | `mode: global` — returns before any rule is evaluated |
| `neg-listener.yaml` | listener-level `proxy:` — sets `SpecialProxy` |
| `neg-tunnel.yaml` | top-level `tunnels:` with a proxy target |
| `neg-rematch.yaml` | a reachable `rematch` outbound |
| `neg-passrule.yaml` | a rule targeting `PASS-RULE` |
| `neg-allowrule.yaml` | a non-deny rule before the egress anchor |
| `neg-noterm.yaml` | the `IN-NAME` terminator not adjacent to the anchor |
| `neg-dupanchor.yaml` | a duplicated egress anchor |
| `neg-nested.yaml` | an anchor nested inside a logic rule |

```sh
for f in test/overlay/neg-*.yaml; do
  printf '%-24s ' "$(basename "$f")"
  if mihomo -t -d test/overlay -f "$f" 2>&1 | grep -q 'test is successful'; then
    echo 'ACCEPTED  <-- BYPASS NOT CLOSED'
  else
    echo 'rejected'
  fi
done
```

Section 13.1 of the architecture review makes this a **merge gate**: upstream
adds routing primitives faster than the guard list can be re-derived by
inspection — three new bypass carriers landed in a single week in June 2026 —
so this matrix runs on every rebase, before the fork is published.
