# Runtime Overlay (Option B) — Implementation Plan

Companion to [`external-traffic-processor-architecture-review.md`](external-traffic-processor-architecture-review.md).
That document decides *what* to build and why. This one records *how*, against
the actual code at the revisions below, and what is deliberately out of the
first increment.

## Revisions and branches

| Repository | Base | Feature branch | Worktree |
| --- | --- | --- | --- |
| `moooyo/mihomo` | `b9faf971` (`Alpha`) | `feat/runtime-overlay` | `D:/Code/worktrees/mihomo-runtime-overlay` |
| `moooyo/5gpn` | `949d3d2` (`origin/main`) | `feat/runtime-overlay` | `D:/Code/worktrees/5gpn-runtime-overlay` |
| `Zephyruso/zashboard` | `c54f9c5` (`main`) | `feat/runtime-overlay` | `D:/Code/worktrees/zashboard-runtime-overlay` |

5gpn release policy for this work: the feature branch is never pushed to `main`.
Beta releases are permitted through the existing `beta` channel
(`X.Y.Z-beta.N` tags, which `.github/workflows/release.yml` requires to be
reachable from `beta`); no stable tag may be cut from this work.

## Answers to the open decisions this implementation assumes

Section 16 of the review lists eighteen questions. Implementation cannot proceed
without a position on the ones that shape code, so this plan takes one. Each is
an assumption, recorded so it can be overturned rather than silently inherited.

| # | Question | Position taken here |
| --- | --- | --- |
| 1 | Shared sidecar trusted? | Trusted as a process boundary. Per-plugin workers are out of scope. |
| 2 | Rule-layer anchors or core pre-routing stage? | Anchors, as 6.2.2 recommends, plus the bypass closure guards that make them enforceable. The matcher representation is kept independent of where it is evaluated. |
| 3 | Active-state corruption: startup failure or deny guard? | Startup failure for the affected client data plane. The overlay refuses rather than serving an unguarded path. |
| 4 | Who owns extending the closure? | The closure is one function, `config.OverlayClosureDigest`, so extending it is a single-site change. There is no test that fails when a new `RawConfig` field goes unclassified — that would be worth adding and is not in this increment. |
| 7 | Selective or full cache invalidation? | Epoch-keyed, so invalidation is O(1) and selective by construction; no `ClearCache`. |
| 8 | Graceful vs hard revoke | The coordinator declares `transition_mode` per generation. Permission removal, host removal and master-off must use `revoke`. |
| 9 | Drain deadlines | TCP 30s, UDP 30s, H1 30s, H2 60s, H3 60s, WebSocket 300s. Encoded in `overlay.DefaultDrainDeadlines`. |
| 12 | Pinned-IP eligibility | Deferred in full — see "Deferred" below. `public-only` is carried on the capability and validated at commit, but no transport-level pinning ships in this increment. |
| 14 | Windows production? | Development only. The control and generation sockets refuse to start on Windows rather than falling back to a weaker transport. |

## What the code actually looks like (recon summary)

The design document is accurate about intent but the tree has diverged from the
upstream shapes it cites. The load-bearing corrections:

- `C.Rule` has no `ShouldResolveIP`/`ShouldFindProcess`/`SetSubRule`. Lazy
  resolution is a `C.RuleMatchHelper` struct of nilable closures passed to
  `Match` (`constant/rule.go:126-159`).
- `Match` returns `(bool, string)` and nothing else. There is no channel for a
  capability handle or a structured deny reason; anything richer must ride on
  `*C.Metadata`.
- A matched rule whose adapter name is absent from the proxies map is silently
  **skipped**, not rejected (`tunnel/tunnel.go:665-668`). An anchor that returns
  a stale proxy name therefore fails *open*.
- No rule matching at all returns `DIRECT`, not `REJECT` (`tunnel/tunnel.go:709`).
- There is no revision, generation, epoch or config digest anywhere in
  `config/`, `hub/`, `tunnel/` or `constant/`. All of it is greenfield.
- `executor.mux` is unexported and taken only by `ApplyConfig`. Every other
  mutation path — `patchConfigs`, `disableRules`, provider updates, geo updates —
  runs outside it.
- `tunnel.mode` is a plain unsynchronised package var written from an HTTP
  handler. The "overlay requires rule mode" invariant is racy until that is
  fixed, not merely unchecked.
- `config.ParseRawConfig` mutates global runtime state *during parse* via
  `temporaryUpdateGeneral`, outside any lock. `mihomo -t` and a rejected
  `PUT /configs` transiently flip the live tunnel mode.
- The unix socket and named pipe controllers pass `secret=""` and the unix
  socket is `chmod 0666`. Both serve the entire API unauthenticated.
- `AllProxies` (feeding `include-all-proxies`) and `proxyList` (feeding the
  reserved provider and the auto-created GLOBAL selector) are two different
  slices. Excluding a processor target from one leaves it in the other.
- SOCKS5 UDP is entirely unauthenticated: the `UDP ASSOCIATE` branch discards
  both the authenticated user and the target address, and the UDP listener
  never reads its `AuthServer`.

## Phase 0 — overlay core (`component/overlay`)

Self-contained, no dependencies on `tunnel`/`config`/`hub`.

| File | Contents |
| --- | --- |
| `types.go` | `Document`, `ClientRule`, `EgressCapability`, `ProcessorTarget`, `ResolverProfile`, `Quotas`, `DrainDeadlines`, structural validation |
| `errors.go` | Sentinel errors and their stable wire `Code`s, with a `Retryable()` split so the coordinator can tell "retry this operation" from "build a new generation" |
| `digest.go` | Length-prefixed, tagged canonical serializer; overall/projection/resolver-set/capability-set digests; dependency-closure digest |
| `compile.go` | `Document` → matchers; `MatchInput`; first-match client evaluation; capability lookup |
| `snapshot.go` | Immutable `Snapshot`, `ProcessorState`, fail-closed `MatchClient`, `ResolveEgress`, `ActiveView`, `atomic.Pointer` holder |
| `store.go` | Durable store: atomic rename + file fsync + directory fsync, per-record integrity digest, refuse-newer-schema, `Purge` |
| `lease.go` | Readiness lease, fencing tokens, boot epoch |
| `manager.go` | `Stage`/`Abort`/`Commit` with CAS, `Recover` + quarantine, readback, drain sweeper, host `Hooks` |

Two decisions worth stating because they are easy to get wrong:

- **The digest is length-prefixed and type-tagged, not a concatenation.** A rule
  value containing the separator would otherwise collide with a different rule
  list, and the digest is the only thing three processes use to agree they hold
  the same policy.
- **`MatchClient` returns reject, not "no match", when a capture is selected but
  the processor is unserviceable.** "No match" falls through to the operator's
  rules, which is the exact bypass the overlay exists to prevent.

## Phase 1 — anchors and tunnel integration

1. `constant/rule.go`: append `RuntimeOverlayClient` and `RuntimeOverlayEgress`
   to the `RuleType` iota block (append-only; values are never serialised
   numerically) and to `String()`.
2. `rules/common/runtime_overlay.go`: the anchor rule. Immutable `owner` +
   `stage`; resolves the live snapshot through a late-bound package accessor at
   match time, mirroring `rules/provider`'s `var tunnel P.Tunnel` pattern so the
   rule never pins a generation across commits.
3. `rules/parser.go`: `case "RUNTIME-OVERLAY"`. `ParseRulePayload` puts the owner
   in `payload` and the stage in `target`, so the constructor validates the stage
   token and rejects any trailing params (`ParseParams` silently ignores unknown
   ones).
4. `rules/logic/logic.go` and `rules/provider/classical_strategy.go`: add
   `RUNTIME-OVERLAY` to both denylists. The second matters more than it looks —
   `classicalStrategy.Insert` only logs on parse failure, so without the entry a
   remote rule-set could inject an anchor outside config validation entirely.
5. `config/config.go:1102-1108`: exempt `RUNTIME-OVERLAY` from the
   proxy-existence check the way `SUB-RULE` is exempted. Without this the anchor
   fails config load with `proxy [egress] not found`.
6. Fail-closed adapter resolution: the anchor consults the live proxies map
   before returning a capture target, and returns `REJECT` rather than a name
   that would be silently skipped at `tunnel/tunnel.go:665`.

## Phase 2 — bypass closure

A single validator, `config.validateRuntimeOverlay`, run at the end of
`ParseRawConfig` — the only point where rules, listeners, tunnels, hosts,
sniffer and mode are all populated. `parseRules` runs at `:699` but tunnels are
parsed at `:731`, so this cannot be a check inside `parseRules`.

It asserts:

- exactly one anchor per stage, neither nested in `AND`/`OR`/`NOT` nor in a
  sub-rule list;
- the egress anchor is immediately followed by the `IN-NAME,<egress-listener>,REJECT`
  terminator;
- every rule before the egress anchor is a deny, or carries an inbound qualifier
  that excludes processor-originated traffic. This is what stops a compromised
  sidecar from reaching the gateway's own management plane through the panel
  guard's `DIRECT` rules;
- the client anchor precedes every ordinary operator rule and the terminal
  `MATCH`;
- `mode: rule`;
- no in-scope listener carries `proxy:` or `rule:`;
- no `tunnels:` entry carries a `proxy:` target — including the compact string
  form, whose optional fourth comma field silently becomes `Proxy`;
- no reachable `rematch` outbound or `PASS-RULE` target.

Processor-target exclusion is a `runtime-overlay-processor: true` key read
directly off the raw proxy mapping in `parseProxies`. That name is then withheld
from **both** `AllProxies` (killing the `include-all-proxies` splice) and
`proxyList` (killing the reserved provider and the auto-created GLOBAL
selector), while remaining in the `proxies` map so rules can still target it.
`validateDialerProxies` is extended to reject a `dialer-proxy` edge in either
direction.

The core revision is `overlay.DependencyClosureDigest` computed over `RawConfig`
values, never over parsed objects — parsed adapters carry fresh UUIDs per parse
and sniffer configs carry compiled matchers, so neither hashes stably.

## Phase 3 — sockets, executor, controller guards

- `hub/executor`: export the apply lock so a commit can exclude a reload. The
  hierarchy is `executor.mux` → `tunnel.configMux`; taking them in the other
  order deadlocks against `ApplyConfig`.
- Overlay recovery is installed at `executor.go:118`, after rule providers load
  and before `tunnel.OnRunning()` opens the data plane. Binding listeners at
  `:107` is not the exposure point — the `Inner` status gate already drops
  non-internal traffic.
- `temporaryUpdateGeneral` is fenced so a *parse* cannot flip the live tunnel out
  of rule mode while an overlay is active.
- `tunnel.mode` becomes atomic.
- Two new listeners, each with its own `*http.Server`, its own chi mux, no CORS,
  `Cache-Control: no-store`, and `SO_PEERCRED` verification per connection — not
  once at startup. They deliberately do not reuse `router()`, which mounts
  `/configs`, `/restart` and `/upgrade`.
  - control socket (coordinator, read-write): capabilities, stage, commit,
    abort, readback, purge;
  - generation socket (processor, read-only): the active view, `GET` only.
- `PATCH /rules/disable` validates the entire payload before mutating anything
  and refuses anchors, the egress terminator and protected guards.
- `patchConfigs` becomes two-phase: validate the whole decoded schema against the
  active overlay, return 409 with zero side effects, and only then run the
  existing body. Today its first mutation fires eight statements before `mode` is
  even examined.

## Phase 4 — runtime hardening

- Generation identity on trackers plus `statistic.Manager.CloseMatching`, giving
  revocation an enumerate-and-close primitive for both TCP and UDP. `xsync.Map`
  `Range` is explicitly not a consistent snapshot, so the match path must *also*
  reject the revoked generation; the sweep alone is not sufficient.
- Authenticated SOCKS5 UDP: the `UDP ASSOCIATE` branch registers an association
  keyed by the client's UDP source, carrying the authenticated user and a
  lifetime bounded by the TCP control connection. The UDP listener rejects
  unassociated sources and stamps `InUser`.
- Resolver cache epoch: folded into the cache key **and** the singleflight key,
  and captured by the detached stale-refetch goroutine, which otherwise lands
  pre-swap answers in the post-swap cache up to five seconds later.
- `public-only` scope validation at the egress phase.

## Deferred, and why

These are in the review's scope but not in this increment. They are listed so
the gap is explicit rather than discovered later.

- **Transport-level pinned-IP dialing for every adapter.** `Metadata.RemoteAddress()`
  returns `Host` whenever it is set, so DIRECT, HTTP, SOCKS5-out and VMess all
  forward the domain and ignore a populated `DstIP`. A real pin needs a new
  metadata field honoured by each adapter's destination formatting, in the
  highest-churn directory in the tree (230 commits since 2025-01-01). This
  increment validates the resolved scopes and pins DIRECT; every other adapter is
  rejected for `public-only` rather than silently trusted.
- **Option C** in its entirety.
- **Shadow-compile semantic comparison** between the legacy renderer and the
  overlay. The legacy driver is retained and the migration is documented, but the
  automated differential is not built.
- **Geo database updates as a revision-bearing event.** `POST /configs/geo` and
  the background updater change what `GEOIP`/`GEOSITE` rules match with no lock
  and no revision bump. Overlay client rules deliberately do not support geo
  selectors, so the overlay's own matching is unaffected; the operator rules
  below the client anchor are not covered.

## Verification

The 14.1 items that map onto automated tests in this increment:

- canonical projection digest stability and quota rejection;
- anchor presence, adjacency, precedence; missing/duplicate/reordered rejection;
- anchor rejected inside `AND`/`OR`/`NOT` and inside a classical rule-set;
- allow-rule-before-egress-anchor rejection;
- processor target absent from GLOBAL, `include-all-proxies`, reserved provider;
- rule-mode rejection, listener `proxy`/`rule` rejection, `tunnels:` rejection;
- `PATCH /rules/disable` cannot disable an anchor, and a mixed payload applies
  nothing;
- CAS conflict, idempotent repeat commit, lost-response readback;
- store integrity failure and refuse-newer-schema;
- crash between persist and swap → restart rolls forward;
- quarantine on restart; lease expiry fails captures closed;
- drain deadline expiry revokes; hard revoke closes established sessions;
- resolver epoch advances on profile change and no pre-commit answer survives;
- authenticated UDP association and revocation.

## Work breakdown

| # | Item | Repo |
| --- | --- | --- |
| 1 | overlay core package | mihomo |
| 2 | anchor rule type, parser, denylists | mihomo |
| 3 | closure validator, processor exclusion, core revision | mihomo |
| 4 | executor gate, recovery, apply lock, atomic mode | mihomo |
| 5 | control + generation sockets, peer verification | mihomo |
| 6 | controller guards (`rules/disable`, `patchConfigs`) | mihomo |
| 7 | tracker generation identity + revocation | mihomo |
| 8 | authenticated SOCKS5 UDP associations | mihomo |
| 9 | resolver cache epoch | mihomo |
| 10 | tests | mihomo |
| 11 | operation journal, generation/bundle IDs | 5gpn |
| 12 | overlay driver beside the legacy YAML driver | 5gpn |
| 13 | prepare/commit/readback/roll-forward recovery | 5gpn |
| 14 | panel guard requalification, DNS cacheable negatives | 5gpn |
| 15 | processor generation polling and transaction binding | 5gpn-intercept |
| 16 | notification XSS, WebSocket token | zashboard |
| 17 | capability discovery with four states | zashboard |
| 18 | overlay status panel | zashboard |

## Status at the end of this increment

Everything below is implemented, tested and verified against a running binary
unless the row says otherwise.

| # | Item | Repo | State |
| --- | --- | --- | --- |
| 1 | overlay core package | mihomo | done |
| 2 | anchor rule type, parser, denylists | mihomo | done |
| 3 | closure validator, processor exclusion, core revision | mihomo | done |
| 4 | executor gate, recovery, apply lock, atomic mode | mihomo | done |
| 5 | control + generation sockets, peer verification | mihomo | done |
| 6 | controller guards (`rules/disable`, `patchConfigs`) | mihomo | done |
| 7 | tracker generation identity + revocation | mihomo | done |
| 8 | authenticated SOCKS5 UDP associations | mihomo | done |
| 9 | resolver cache epoch | mihomo | done |
| 10 | tests (unit + live) | mihomo | done |
| 11 | operation journal, generation/bundle IDs | 5gpn | done |
| 12 | overlay driver beside the legacy YAML driver | 5gpn | done — legacy remains the default |
| 13 | prepare/commit/readback/roll-forward recovery | 5gpn | done |
| 14 | panel guard requalification | 5gpn | done |
| 15 | processor generation polling and transaction binding | 5gpn-intercept | done |
| 16 | notification XSS, WebSocket token | zashboard | done |
| 17 | capability discovery with four states | zashboard | done |
| 18 | overlay status panel | zashboard | done |

Not done, and deliberately so:

- **The legacy driver is still the default.** `overlay_driver.go` is wired and
  tested but `mutate()` still takes the YAML path. Switching is a persisted,
  operator-visible migration step, and the review requires shadow comparison
  first (12.1 step 4), which is not built.
- **Shadow semantic comparison** between the two drivers.
- **Transport-level pinned-IP dialing.** `Metadata.RemoteAddress()` returns
  `Host` whenever it is set, so DIRECT, HTTP, SOCKS5-out and VMess all forward
  the domain and ignore a populated `DstIP`. A real pin needs a new metadata
  field honoured by each adapter's destination formatting, in the tree's
  highest-churn directory. `public-only` is carried and validated but not yet
  enforced at the transport.
- **DNS quarantine cacheable negatives** (6.15) on the 5gpn resolver.
- **Option C** in its entirety.

### What live testing caught that unit tests did not

Two bugs shipped past a green unit suite, both the same shape: a validator
reading live global state at a point in startup where nothing had populated it.
Recovery recompiled the persisted generation against a processor list
`ApplyConfig` had not published yet, and the post-recovery dependency check read
an empty `tunnel.Proxies()`. Both were fatal at parse time, so **every restart
with a generation persisted exited** — the exact failure-matrix row that says a
restart must recover into quarantine. Neither is reachable from a unit test that
constructs the manager directly.

That is why `test/overlay` exists and why section 13.1 makes the bypass matrix a
merge gate rather than a one-time check.
