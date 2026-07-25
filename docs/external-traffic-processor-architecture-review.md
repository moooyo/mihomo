# External Traffic Processor Architecture Review

## Document status

This is a non-normative design handoff for independent cross-review. It does
not describe current behavior and must not be treated as an approved
implementation contract until the open decisions in this document are closed.

- Status: Proposed; internally reviewed; revised after adversarial cross-review;
  pending sign-off on the open decisions in Section 16
- Review date: 2026-07-25, Asia/Shanghai
- Cross-review date: 2026-07-25, Asia/Shanghai
- Primary system: 5gpn native interception extensions
- Upstream contribution: Not a design constraint for the selected private-fork
  architecture
- Current 5gpn source of truth:
  `moooyo/5gpn@7a6c418: docs/architecture.md`

The review used these exact revisions:

| Repository | Revision | Branch |
| --- | --- | --- |
| `moooyo/5gpn` | `7a6c418a97e9d89c47ba9259b24c802239a24935` | `codex/extension-upstream-parity` |
| `MetaCubeX/mihomo` | `b9faf97198066bf0f57edd3831b6f62b9dc24f05` | `Alpha` |
| `Zephyruso/zashboard` | `c54f9c584655f55b331ca3775485a3db4762466a` | `main` |

Reproducibility note:

- architecture claims and cited source behavior are anchored to committed
  contents at the revisions above;
- the inspected 5gpn worktree had nine pre-existing modified shell/test files,
  including presentation-oriented changes in certificate scripts; those diffs
  were not created by this review and were found not to change the processor
  architecture assessed here;
- the inspected `D:/Code/mihomo` worktree had one pre-existing untracked
  `AGENTS.md`; zashboard was clean;
- this handoff document is the only change in the current mihomo review
  worktree.

### Cross-review revision record

An independent adversarial cross-review of the first revision ran three rounds
of refute-by-default verification over the candidate defects it generated. The
majority were refuted against the cited sources; the survivors are incorporated
here. No survivor undermines the choice of Option B. Material changes:

| Area | Change |
| --- | --- |
| 3.1 | corrected a mis-aimed `common/net/sing.go` citation |
| 5.2 | added the rule-provider option and its rejection rationale |
| 6.2 | allow-rules before the egress anchor are now explicitly forbidden; the GLOBAL/`include-all` invariant is reclassified as a required core change |
| 6.2.1 | closure extended to top-level `tunnels:`, `hosts:`, and each in-scope listener's own `proxy` field; `rematch`/`PASS-RULE` added as bypass carriers |
| 6.2.2 | new: records the cross-review's answer to question 2 |
| 6.6 | state machine redrawn (`ARMED` removed, abort and direct-revoke edges added); resolver cache is now generation-bound |
| 6.12 | added the concrete revocation mechanism for established UDP sessions |
| 6.15 | replaced `SERVFAIL` with an authoritative cacheable negative |
| 7.2, 11 | the sidecar's read-only generation endpoint now has a specified transport, ACL, and peer identity |
| 12.1 | rollback steps reordered to resolve a deadlock against the anchor guard |
| 12.2 | downgrade now purges durable overlay state |
| 13 | added private-fork carrying cost; effort estimate revised upward |
| 7.3, 8 | added two pre-implementation blockers and three failure-matrix rows |
| 14.1, 15 | added verification and implementation items for every change above |
| 16 | annotated the questions the cross-review answered; added three more |

Refuted claims are not recorded as defects, but two were load-bearing enough to
note so they are not re-raised:

- the incremental-mutation atomicity gap is already governed by 6.2.1; current
  `hub/route/configs.go` behavior is the thing 6.2.1 requires changing, not a
  defect in the design;
- mihomo can enumerate and force-close established UDP NAT sessions today; see
  6.12.

## Review map

- [Executive decision](#executive-decision)
- [1. Requirement in full](#1-requirement-in-full)
- [2. Non-goals](#2-non-goals)
- [3. Current architecture](#3-current-architecture)
- [4. API terminology and zashboard](#4-api-terminology-and-zashboard)
- [5. Options reviewed](#5-options-reviewed)
- [6. Selected architecture: Option B](#6-selected-architecture-option-b)
- [7. Security and trust model](#7-security-and-trust-model)
- [8. Failure and recovery matrix](#8-failure-and-recovery-matrix)
- [9. Why Option C is not the initial target](#9-why-option-c-is-not-the-initial-target)
- [10. Conditional Option C](#10-conditional-option-c)
- [11. Management APIs](#11-management-apis)
- [12. Migration plan](#12-migration-plan)
- [13. Engineering scope and ROI](#13-engineering-scope-and-roi)
- [14. Verification requirements](#14-verification-requirements)
- [15. Required implementation work](#15-required-implementation-work)
- [16. Cross-review questions](#16-cross-review-questions)
- [17. Final verdict](#17-final-verdict)
- [18. Evidence index](#18-evidence-index)

## Executive decision

The missing primitive is not dynamic code loading inside mihomo. The product
needs a first-class way to select traffic, send it through an external traffic
processor, and force the processor's upstream traffic through a constrained
mihomo egress.

The deployed two-SOCKS path already transports the required TCP and UDP bytes.
The highest-risk gap is the control plane: 5gpn currently emulates an owned
runtime policy by parsing, editing, validating, publishing, hot-loading, and
rolling back the complete operator-owned mihomo YAML file.

The final recommendation is staged:

1. Keep the current YAML-plus-SOCKS implementation as a recoverable baseline.
2. Implement a typed, action-bearing, persistent, atomic runtime overlay in the
   private mihomo fork while retaining and hardening the proven SOCKS5 data
   paths. This is the selected production target.
3. Build a custom external-processor data protocol only if measured or security
   requirements prove that SOCKS5 is insufficient.

~~~text
A: legacy YAML + SOCKS
    -> B: atomic runtime overlay + hardened SOCKS   [selected]
    -> C: custom processor/broker protocol          [conditional]

A2: rule-provider hot reload                        [rejected, see 5.2]
~~~

| Decision item | Verdict |
| --- | --- |
| Typed runtime overlay, durable generation, CAS, and readback | Go |
| Continue using and harden SOCKS5 TCP/UDP | Go |
| zashboard management through the 5gpn BFF | Go |
| Direct zashboard mutation of mihomo generation state | No-Go |
| Immediate full custom UDS processor/broker protocol | No-Go |
| TCP-only custom protocol experiment after Phase B | Conditional Go |
| Custom UDP/H3 transport before differential and soak evidence | No-Go |

### Decision assumptions

The selected Option B depends on these explicit assumptions:

- the shared `5gpn-intercept` process is trusted as a process boundary; malicious
  JavaScript is in scope, but a complete sidecar compromise is not claimed to
  preserve plugin-to-plugin isolation;
- Linux is the production gateway target; Windows requirements for a future
  custom data transport remain an open decision;
- the current 5gpn feature set does not require source IP, inbound name, rule
  identity, or arbitrary processor-chain metadata inside script actions;
- the existing SOCKS transport has not been demonstrated to be a material CPU
  or latency bottleneck;
- one external processor is sufficient for the selected phase;
- the operator accepts a one-time static mihomo infrastructure boundary and
  two explicit runtime-overlay anchors;
- mihomo remains in rule mode while a runtime overlay is active, and no in-scope
  configuration surface can route around the rule engine: no listener-level
  `proxy`/`rule` override, no top-level `tunnels:` entry targeting a bypass, and
  no reachable `rematch` outbound or `PASS-RULE` target. Section 6.2.1 defines
  the closure; Section 6.2.2 records the cross-review's finding that this
  assumption is the least durable one in the list.

If an assumption becomes false, the decision must be reopened rather than
silently extending Option B beyond its reviewed scope.

## 1. Requirement in full

5gpn native interception extensions currently require:

- strict manifests and immutable source/script snapshots;
- explicit capture hosts and ordered plugin execution;
- request and response transformation over plain HTTP, TLS/H1, H2, and H3;
- bounded JavaScript execution, typed settings, optional storage, and approved
  network origins;
- optional global `DIRECT` and `REJECT` rules;
- operator-selected egress groups and capture DNS behavior;
- a private interception CA and exact certificate readiness;
- explicit review, enable, update, reorder, and uninstall workflows;
- bounded sensitive plugin logs;
- Console and Telegram management.

The independent data-plane requirement is:

~~~text
Select a bounded class of TCP/UDP traffic
  -> send it to an external processor
  -> let the processor terminate and transform application protocols
  -> force every processor-originated connection back through an authorized
     mihomo egress
  -> fail closed on a missing processor, permission, route, or dependency
~~~

Required observable properties:

1. Ordinary plugin operations do not rewrite the complete operator-owned
   mihomo config.
2. Every runtime change has an explicit generation and digest.
3. One mihomo in-memory atomic `RuntimeSnapshot` swap is the live
   linearization point for new processor flows, egress decisions, and sidecar
   transaction generation lookup.
4. A lost response is recoverable through authoritative readback.
5. A missing processor or group rejects rather than falling through to normal
   rules or `DIRECT`.
6. Process restart does not create a bypass window for client-cached gateway
   destinations.
7. New transactions on long-lived H1/H2/H3 connections observe revocation in
   bounded time.
8. The browser never holds the real mihomo controller secret for extension
   management.

## 2. Non-goals

The selected architecture does not require mihomo to:

- load Go plugins, JavaScript, WASM, or arbitrary binaries;
- fetch manifests, scripts, marketplaces, or remote executables;
- own the `5gpn.io/v1` schema;
- own the root interception CA or device trust workflow;
- implement the 5gpn marketplace, Telegram workflow, or consent UI;
- expose arbitrary file or command execution;
- claim the new API as part of generic Clash API;
- claim per-plugin isolation after a shared sidecar compromise.

## 3. Current architecture

~~~text
client DNS
  -> 5gpn-dns returns a real address or gateway address
  -> mihomo sniffs and matches traffic
  -> MODULE-INTERCEPT SOCKS5 outbound
  -> 5gpn-intercept terminates HTTP/TLS/QUIC and runs transforms
  -> intercept-egress SOCKS5/mixed inbound
  -> ordered IN-NAME/domain/port rules select an operator group
  -> origin
~~~

Current ownership:

- `5gpn-dns` owns desired state, validation, review, DNS, CA coordination, the
  complete mihomo YAML transaction, and the product API.
- `5gpn-intercept` is the trusted HTTP/TLS/QUIC front end and JavaScript
  runtime.
- mihomo owns L4 ingress, sniffing, matching, both SOCKS legs, and egress.
- zashboard is a generic Clash-compatible controller dashboard.
- the 5gpn Console owns complete extension management.

### 3.1 Mihomo's current boundary

The current TCP path is:

~~~text
sniff and pre-handle metadata
  -> resolve one rule to one ProxyAdapter
  -> DialContext with generic retry
  -> optional early-handshake write
  -> create one tracker with one fixed chain
  -> raw bidirectional relay
~~~

Evidence:

- `tunnel/tunnel.go:502-625`
- `constant/adapters.go:124-149`
- `tunnel/tunnel.go:582-605` and `common/net/sing.go:49-54` for the
  early-handshake write
- `tunnel/statistic/tracker.go:24-146`

HTTP `CONNECT` is returned to the raw tunnel rather than an HTTP transaction
hook:

- `listener/http/proxy.go:68-76`

TLS and QUIC sniffers extract routing metadata. They do not decrypt or mutate
application traffic:

- `component/sniffer/tls_sniffer.go:69-187`
- `component/sniffer/quic_sniffer.go:162-443`

### 3.2 What 5gpn currently emulates

`cmd/5gpn-dns/intercept_module_manager.go:907-1019` currently:

1. locks extension state;
2. validates a complete sidecar candidate;
3. locks the full mihomo config;
4. proves ownership of contiguous reserved rule blocks;
5. renders egress, fail-closed, policy, and capture rules;
6. validates complete YAML and runs `mihomo -t`;
7. publishes the sidecar config;
8. waits for the certificate host-set digest;
9. publishes and hot-loads the complete mihomo config;
10. performs compensating rollback if hot-load fails;
11. publishes the DNS overlay last.

The strongest coupling is in:

- `cmd/5gpn-dns/intercept_mihomo.go`
- `cmd/5gpn-dns/interception_routing_check.go`
- `cmd/5gpn-dns/intercept_module_manager.go:907-1173`
- `cmd/5gpn-dns/api_mihomo_config.go`

## 4. API terminology and zashboard

\"Clash API\" is a de facto REST/WebSocket compatibility family. It is not a
versioned standard and is not synonymous with the mihomo controller.

zashboard models:

- `clash`: Clash-compatible REST/WebSocket;
- `singbox`: native sing-box gRPC.

The `clash` path may connect to mihomo or another compatible core. Current
capabilities are inferred from backend type and version strings rather than
feature discovery:

- `src/types/index.d.ts:3-18`
- `src/assembly/backend.ts:13-34`
- `src/assembly/version.ts:25-41`
- `src/api/clash.ts`

The current zashboard Clash path is not a strict mihomo-only client. Most core
requests match current mihomo, but it also contains fork-specific requests:

| zashboard request | Current mihomo Alpha |
| --- | --- |
| `GET /group/weights` | Not implemented |
| `GET /group/{name}/weights` | Not implemented |
| `POST /cache/smart/flush` | Not implemented |
| `DELETE /connections/smart/{id}` | Not implemented |
| `PUT /rules/{uuid}` | Not implemented; current mihomo rules have no UUID |

This is direct evidence that backend type or a successful `GET /version` cannot
be treated as capability negotiation.

The 5gpn extension API is separate:

- `cmd/5gpn-dns/api.go:399-413`
- `GET/PUT /api/interception/settings`
- `/api/interception/modules/*`
- `/api/interception/marketplaces/*`
- independent ticketed plugin-log WebSocket.

Consequences:

1. The runtime-overlay API is a private mihomo extension, not generic Clash API.
2. zashboard uses explicit feature discovery, not a version regex.
3. Browser mutations go through the 5gpn BFF so review, certificate, sidecar,
   mihomo, and DNS ordering cannot be bypassed.

Feature discovery uses a versioned descriptor and four client states:

- `unknown`: discovery is still pending; do not render the feature;
- `supported`: the advertised schema version is understood;
- `unsupported`: capability endpoint or feature returns 404;
- `temporarily-unavailable`: timeout or 5xx; retain retry rather than caching
  permanent absence.

A 401 follows the existing authentication path. An unknown future schema is not
silently treated as supported. Switching zashboard backend cancels outstanding
discovery/list requests and uses the backend UUID plus a request generation so
an old response cannot populate the new backend.

## 5. Options reviewed

### 5.1 Option A: complete YAML mutation plus SOCKS

Advantages:

- implemented and extensively tested;
- proven TCP, UDP, QUIC v1/v2, and H3 behavior;
- no additional private core feature;
- understood rollback behavior.

Disadvantages:

- every routing change rewrites the operator file;
- ownership depends on exact ordering and serialization;
- hot apply has no committed generation or runtime digest;
- a lost `/configs` response leaves commit outcome uncertain;
- operator edits can invalidate the reserved boundary;
- the control plane carries a large compensating transaction.

Decision: migration and emergency rollback baseline only.

### 5.2 Option A2: rule-provider hot reload

5gpn already ships a file-vehicle rule provider (`whitelist`) and references it
from the operator rule list, so this option costs no new mihomo feature at all:

- `etc/mihomo/config.yaml.tmpl:47-48`, `:79`.

The shape would be: keep the operator YAML frozen, express the extension's
capture and policy rules as classical rule-set payloads, rewrite only the small
provider files, and refresh them through the existing endpoint
(`hub/route/provider.go:113-121`, `PUT /providers/rules/{name}`).

Advantages:

- no private core change and no new API;
- the operator's file is never rewritten by ordinary plugin operations, which is
  the single largest defect of Option A;
- classical behavior accepts the rule types this product needs — only `MATCH`,
  `RULE-SET`, and `SUB-RULE` are rejected
  (`rules/provider/classical_strategy.go:51-57`);
- a hot-reload path already exists and is already exercised in production.

Disqualifying disadvantages. All three are fail-open, and each independently
breaks required property 5:

1. a missing or unloaded provider makes its `RULE-SET` rule evaluate to "no
   match" rather than reject, so traffic continues to the next rule
   (`rules/provider/rule_set.go:23-36`);
2. a provider whose `Initial()` fails is logged and skipped, not fatal, and
   provider loading happens at `hub/executor/executor.go:117` — after client
   listeners are already bound at `:107`. That is exactly the restart bypass
   window property 6 forbids (`hub/executor/executor.go:318-353`, `:327-338`);
3. an unparsable line inside a classical payload is warned and dropped, leaving
   a silently short rule set (`rules/provider/classical_strategy.go:41-49`).

It also carries none of the primitives the requirement asks for: no generation,
no digest, no CAS, no readback, no atomic multi-file swap, and no drain or
revocation semantics. Making it fail-closed and transactional means changing the
same core files Option B changes, at which point it is Option B with a worse
data model.

Decision: rejected. Recorded here because it is the cheapest option that looks
viable, and the rejection rationale must not have to be rediscovered.

### 5.3 Option B: atomic runtime overlay plus hardened SOCKS

Advantages:

- removes complete YAML mutation from normal plugin operations;
- preserves proven TCP/UDP/H3 transport;
- centralizes ownership, dependency checks, and failure behavior in mihomo;
- supports CAS, idempotency, and readback;
- can run in shadow mode before cutover;
- keeps the private-fork surface concentrated.

Disadvantages:

- adds an explicit second rule source;
- requires config reload to coordinate with overlay dependencies;
- requires real persistent generation state;
- requires hardened SOCKS UDP association behavior;
- does not carry arbitrary flow metadata.

Decision: selected target.

### 5.4 Option C: custom processor and egress-broker protocol

Advantages:

- carries complete immutable flow metadata;
- supports per-flow status, cancellation, and quotas;
- permits Linux sidecar operation with only `AF_UNIX`;
- can replace generic listeners and rule-based egress.

Disadvantages:

- still requires all of Option B;
- adds a permanent private protocol and synchronized releases;
- requires half-close, framing, quotas, fuzzing, and crash recovery;
- current UDP/NAT APIs do not preserve per-datagram metadata;
- H2/H3 generation is not solved at the raw-flow layer;
- raw dial authorization cannot guarantee HTTP origin semantics;
- likely increases total code and test volume.

Decision: evidence-triggered later phase only.

## 6. Selected architecture: Option B

### 6.1 Static data boundary

Retain:

- the `MODULE-INTERCEPT` SOCKS5 outbound;
- the `intercept-egress` inbound;
- fixed loopback exposure and authentication;
- a terminal egress reject;
- sidecar ownership of H1/H2/H3 and scripts.

These are one-time operator-visible infrastructure. They are not rewritten by
ordinary extension operations.

### 6.2 Two runtime-overlay anchors

One prepend-only overlay is incorrect because current behavior has two stages.

~~~text
panel and anti-loop guards
RUNTIME-OVERLAY,5gpn,egress
IN-NAME,intercept-egress,REJECT
optional global UDP/443 system-guard slot
RUNTIME-OVERLAY,5gpn,client
operator rules and terminal MATCH
~~~

Both stages are published through one immutable `RuntimeSnapshot`, but they do
not have identical generation visibility:

- `client` reads only the single active generation: ordered extension
  `DIRECT`/`REJECT` rules, then capture rules targeting `MODULE-INTERCEPT`;
- `egress` resolves opaque capabilities against the active generation plus a
  bounded registry of explicitly draining generations, allowing already-started
  G0 transactions to complete after G1 becomes active.

A prepared generation has no usable data-plane egress capability. The live
snapshot swap simultaneously activates G1 client/egress state and moves G0 into
either the draining or revoked registry.

Required invariants:

- exactly one anchor per stage;
- the egress anchor is immediately adjacent to and immediately before the fixed
  `IN-NAME,intercept-egress,REJECT` terminator;
- only explicitly defined panel, protocol, and anti-loop system guards may
  precede the egress anchor; no broad operator rule may shadow it;
- every rule preceding the egress anchor is a deny rule, or is qualified so it
  cannot match processor-originated traffic. Current 5gpn violates this: the
  panel guard block ends in two `DIRECT` allow rules
  (`etc/mihomo/config.yaml.tmpl:78-79`) that precede the egress terminator at
  `:91`, so a compromised sidecar dialing the console or dashboard host reaches
  the gateway's loopback management plane without ever meeting the egress
  anchor. Each such rule must gain a negative `IN-NAME,intercept-egress`
  qualifier, or move below the terminator, before the overlay is enabled;
- the client anchor occupies the defined slot after the optional global
  UDP/443 system guard and before every ordinary operator rule and terminal
  `MATCH`;
- every full-config candidate validates both anchors and their precedence
  before apply;
- removing, duplicating, or reordering anchors while an overlay is persisted
  rejects config reload and rejects startup of client data-plane listeners;
- quarantine requires valid anchors. If the anchor structure is unavailable,
  the implementation must refuse the affected client data plane unless a
  separate, independently persisted pre-routing deny hook is implemented;
- only typed matchers and actions are accepted;
- rule quotas are fixed;
- processor targets never enter normal groups, GLOBAL, URL tests,
  `include-all-proxies`, or dialer-proxy chains. This one is not achievable by
  configuration and is a required fork change: every parsed proxy is appended to
  `AllProxies` unconditionally (`config/config.go:907`), spliced into any
  `include-all-proxies` group (`adapter/outboundgroup/parser.go:95-110`), and
  swept into the auto-created GLOBAL selector (`config/config.go:972-984`).
  Processor targets need an explicit exclusion flag at parse time, in the same
  place `PASS`/`PASS-RULE` are already excluded from the reserved provider
  (`config/config.go:961-967`).

### 6.2.1 Mode and listener-routing bypass constraints

The two anchors are evaluated only through normal rule resolution. Current
mihomo can bypass that path:

- `metadata.SpecialProxy` returns before mode or rule matching;
- Direct and Global modes return `DIRECT`/`GLOBAL` without evaluating rules;
- `metadata.SpecialRules` selects a sub-rule list that does not contain the
  default-list anchors;
- a `rematch` outbound sets `RematchName` or `SpecialRules` from inside an
  otherwise ordinary match result, so a sub-rule redirect no longer has to be
  present on the listener;
- top-level `tunnels:` is a second listener carrier outside `cfg.Listeners`,
  applied at `hub/executor/executor.go:110`, and every tunnel entry sets
  `SpecialProxy` unconditionally when `proxy:` is non-empty.

Evidence:

- `tunnel/tunnel.go:317-410`
- `hub/route/configs.go:320-388`
- `listener/inbound/base.go:92-119`
- `adapter/outbound/rematch.go:33-40`
- `config/config.go:211`, `:432`, `:731-739`
- `listener/tunnel/tcp.go:59-61`

The `tunnels:` carrier deserves emphasis because 5gpn is already one field away
from it. The rendered gateway listeners are `type: tunnel` with no `proxy:` key
(`install.sh:1734-1746`); adding `proxy: <anything>` to any one of them is a
one-line, config-valid, total bypass of both anchors. The closure must therefore
cover each in-scope listener's own `proxy` field and each `tunnels:` entry, not
merely the set of listener names.

Option B therefore selects the following compatibility policy:

- an active or prepared-to-commit overlay requires mihomo rule mode;
- incremental mutation to Direct or Global mode returns conflict while the
  overlay is active;
- full config reload validates mode before apply;
- every listener in the 5gpn client-ingress scope and the
  `intercept-egress` listener must have no listener-level `proxy` or `rule`
  override, and no top-level `tunnels:` entry may target a bypass;
- active overlay config reload rejects an in-scope listener or tunnel entry that
  could set `SpecialProxy` or `SpecialRules`, and rejects any reachable
  `rematch` outbound or `PASS-RULE` target that could re-enter matching outside
  the anchored list;
- the `RuntimeSnapshot` dependency closure explicitly includes mode, sniffing
  and sniffer configuration, in-scope listeners together with each listener's
  own `proxy`/`rule` fields, top-level `tunnels:`, top-level `hosts:`, protected
  system rules and their disabled state, groups/providers, resolver
  configuration, and both anchors. `hosts:` belongs in the closure because it
  rewrites `metadata.Host` and can pre-resolve `DstIP` before any rule is
  evaluated (`tunnel/tunnel.go:309-312`, `:331-334`), which is enough to move a
  capture host out of the client overlay's match set;
- every structural incremental mutation in that dependency closure
  participates in the same core revision and overlay guard;
- incremental handlers validate the complete request against the overlay before
  producing any side effect. A mixed payload containing both allowed fields and
  one forbidden mode/rule/listener change rejects atomically; no earlier field
  or rule index may remain mutated;
- `PATCH /rules/disable` cannot disable or replace an overlay anchor, the
  `intercept-egress` terminator, or any protected panel/anti-loop/system guard;
- disabling sniffing or changing force/skip behavior in a way that can suppress
  required hostname recovery is rejected while the overlay is active, unless
  the same atomic operation installs an equivalent fail-closed snapshot;
- selector choice and health changes do not automatically advance the
  structural core revision, but each egress dial still validates the selected
  leaf and recursion policy; provider updates that can alter topology require
  dependency revalidation;
- zashboard disables incompatible mode controls while active and explains that
  the operator must explicitly disable the interception generation first.

This restriction is part of the selected small-fork design, not a general
mihomo limitation. If Direct/Global modes or listener-specific routing must
remain available while interception is active, the anchor design is
insufficient. That requirement triggers a redesign in which system guards,
egress fail-closed handling, and client overlay matching become a core
pre-routing stage evaluated before `SpecialProxy`, `SpecialRules`, and mode
selection.

### 6.2.2 Cross-review position on the pre-routing stage

Section 16 question 2 asks whether the rule-layer anchors are acceptable or
whether the design must move to a core pre-routing stage. The cross-review's
answer is that the anchors are acceptable for the first release but should not
be treated as the permanent boundary, for two reasons.

First, the bypass surface is a moving target rather than a fixed list. The four
carriers enumerated in 6.2.1 were found by inspection of one revision, and three
of them are recent: `PASS-RULE` (`fd2112ec`, 2026-06-04), the `rematch` outbound
and `REMATCH-NAME` rule (`ea19cda0`, 2026-06-12), and per-listener
`routing-mark` plus inbound listen override (`d67572bb`, `0daa3ff7`, both
2026-06-12). Each new upstream routing feature is a new opportunity for a rule
that never reaches an anchor, and the guard list has to be re-derived on every
rebase. A pre-routing stage inverts that: new features are constrained by
default instead of by enumeration.

Second, forcing rule mode removes the operator's panic switches. With an overlay
active there is no single-step "route everything DIRECT" or "route everything
through GLOBAL" available, and the documented escape is a multi-step generation
disable through the control plane. That is acceptable only if the escape hatch
is itself specified, tested, and reachable when the coordinator is down; see
Section 8.

Concrete position:

- ship Option B with the anchors as designed;
- treat the pre-routing stage as a planned second increment, not a hypothetical,
  and keep the overlay compiler's matcher representation independent of where it
  is evaluated so the move does not require recompiling generations;
- add one mandatory rebase gate: every upstream merge re-runs the bypass test
  matrix in 14.1 before the fork is published.

### 6.3 Stable generation model

A generation is an opaque, non-reusable ID with immutable digests, not a
process-local counter.

~~~text
generation_id
parent_generation_id
document_revision
overall_digest
mihomo_projection_digest
sidecar_bundle_digest
certificate_host_set_digest
expected_core_config_revision
egress_capability_set
resolver_profile_set
transition_mode: graceful | revoke
~~~

The generation covers every behavior-changing field, including changes that do
not alter capture rules:

- scripts and settings;
- execution order;
- network permissions;
- mappings;
- egress bindings;
- resolver profile/capture DNS;
- H2/H3 behavior;
- master enablement.

Otherwise the sidecar or DNS selector becomes an untracked second commit point.

### 6.4 Prepare and commit

Do not implement blocking distributed two-phase commit. Use:

~~~text
immutable idempotent prepare
  -> durable commit intent
  -> mihomo CAS commit
  -> authoritative readback
  -> roll forward
~~~

Safe order:

1. Persist the 5gpn operation journal and immutable desired generation.
2. Build and validate an immutable sidecar bundle.
3. Prepare a versioned certificate artifact.
4. Prepare the unpublished mihomo projection and generation-specific egress
   capabilities.
5. Load the sidecar bundle as prepared, but do not give the sidecar an
   independent active-generation pointer or asynchronously published runtime
   file.
6. Confirm sidecar instance, prepared bundle, certificate, and readiness.
7. Commit one complete mihomo `RuntimeSnapshot` with CAS.
8. Read back active and persisted mihomo generation.
9. Persist the desired-state pointer.
10. Publish client DNS overlay last.
11. Drain or revoke the previous generation.

The static capture SOCKS leg does not carry a trustworthy generation identity.
The sidecar therefore must not activate G1 before mihomo commit or maintain a
separate current-generation file. It stores prepared bundles keyed by stable
generation ID and, at the start of every new HTTP transaction or raw non-HTTP
processor flow, queries a narrow read-only local endpoint backed directly by
the same mihomo atomic `RuntimeSnapshot` used by client matching and egress.
The sidecar cannot write that endpoint. An asynchronously mirrored file or
eventually consistent cache is insufficient.

The endpoint returns more than a generation ID. It returns the processor state,
active bundle/certificate digests, lease expiry, expected process instance, and
fencing identity. The sidecar verifies that the returned process instance and
fencing identity match itself. A stale, expired, quarantined, or mismatched view
fails closed.

The sidecar reads and captures this authoritative view at every protocol
decision boundary that can expose generation-specific behavior:

- processor/SOCKS session acceptance;
- TLS certificate and ALPN selection;
- UDP association acceptance;
- QUIC/H3 handshake setup;
- each new H1 request, H2 stream, or H3 request stream;
- every new upstream connection or pooled-transport acquisition.

Connection-level decisions retain the view captured when that decision begins.
Transaction-level decisions recheck the live view. If G1 removes H2/H3 support,
changes certificates, or hard-revokes a permission, existing G0 connections are
drained or closed according to transition policy rather than continuing to
create G0 work.

An in-flight transaction retains the bundle it already captured. A new request
on an existing H1/H2/H3 connection reads the new authoritative generation after
the mihomo pointer changes. Failure to read the pointer or load its exact
prepared bundle fails closed.

Generation-specific SOCKS credentials may serve as opaque egress capabilities
during migration. Server-side state maps them to one immutable generation and
fixed egress policy; they are usable only while the live `RuntimeSnapshot` marks
that generation active or draining. The sidecar never names an arbitrary group.

### 6.5 Persistent operation journal

~~~text
operation_id
expected_document_revision
base_generation_id
target_generation_id
target_document_digest
phase
last_error
~~~

Coordinator states:

~~~text
IDLE(G0)
  -> STAGED(op, G1)
  -> PREPARED
  -> COMMIT_INTENT
  -> EFFECTIVE(G1)
  -> DNS_APPLIED(G1)
  -> DONE
~~~

Rules:

- before `COMMIT_INTENT`, prepared artifacts may be aborted;
- after sending commit, an error or lost response enters recovery;
- readback G1 means roll forward;
- readback G0 means retry the same idempotent operation;
- readback another generation means conflict;
- rollback after effective commit is a new compensating generation.

### 6.6 Mihomo overlay state

~~~text
STAGED   --commit---------> ACTIVE
STAGED   --abort----------> REVOKED
ACTIVE   --graceful-------> DRAINING
ACTIVE   --revoke---------> REVOKED
DRAINING --deadline-------> REVOKED
REVOKED  --no dependents--> GC
~~~

State meanings:

- `STAGED`: the generation artifact is persisted and validated, but carries no
  usable client-match or egress capability. This is the only state that
  `/abort` accepts; abort deletes the artifact and leaves the active generation
  untouched.
- `ACTIVE`: exactly one generation at a time, installed by the live swap.
- `DRAINING`: reached only when the superseding commit declares
  `transition_mode: graceful`. Egress capabilities stay resolvable until the
  drain deadline; no new client matches are produced.
- `REVOKED`: capabilities are gone. Reached from `DRAINING` at the deadline, or
  directly from `ACTIVE` in the same live swap when the superseding commit
  declares `transition_mode: revoke`.
- `GC`: artifacts and certificates released once no dependent generation
  remains.

There is no `ARMED` state. An earlier revision listed one between `STAGED` and
`ACTIVE`; it had no defined entry condition, no defined capability semantics,
and no transition that any other section referenced.

Drain deadlines are per-protocol and bounded; Section 16 question 9 must fix the
exact values. `DRAINING` is not open-ended — the deadline forces `REVOKED` even
if transactions remain, and 6.10's forced-close path applies.

`Commit(G1, expectedActive=G0, expectedCore=R)` constructs one immutable
snapshot containing at least:

~~~text
generation and state
client overlay
active egress overlay and capability mappings
bounded draining-generation egress registry
resolver profiles
dependency/readiness projection
quotas and transition policy
~~~

The commit must:

1. serialize with other overlay commits and full config reload;
2. revalidate generation and core revision;
3. validate rule mode, in-scope listener routing, anchors, groups, resolvers,
   quotas, and recursion;
4. inspect a local sidecar readiness snapshot without blocking IPC under the
   executor lock;
5. persist the generation artifact and durable recovery decision while keeping
   prepared G1 capabilities unavailable;
6. fsync the containing directory;
7. atomically swap the single complete in-memory `RuntimeSnapshot`;
8. as part of that swap, activate G1 capabilities and move G0 to the bounded
   draining or revoked registry;
9. as part of that swap, advance a resolver cache epoch when the generation's
   `resolver_profile_set` differs from the previous generation's;
10. return active ID and digest.

The cache epoch is not optional bookkeeping. mihomo's resolver holds its own
answer cache (`dns/resolver.go:48`), and nothing in the commit path touches it:
`ClearCache` (`dns/resolver.go:393`) is reachable only through a full config
apply. Without an epoch, a generation that changes the trust/China resolver
profile keeps serving the previous profile's answers until their TTLs expire,
which silently breaks the "one atomic swap is the linearization point" property
for exactly the decisions 6.14 says must be generation-bound. Either the cache
key includes the epoch or the swap invalidates the affected entries; a full
`ClearCache` is acceptable but discards unrelated entries. 5gpn already solved
the same problem on its side with a cache epoch (`cmd/5gpn-dns/handler.go:884`),
and the two epochs must be advanced by the same commit.

The atomic in-memory swap is the live linearization point. Client matching, the
egress capability lookup, authoritative readback, and the sidecar's local
generation endpoint all load the same pointer. There is no separately
published sidecar view or client table.

The durable recovery decision precedes the live swap but is not itself the
online linearization point. If the process crashes between persistence and the
atomic swap, the running process never exposes a mixed G0/G1 state; restart
loads G1 before listeners and rolls forward. Readback distinguishes
`persisted_generation` from the live `active_generation` so the coordinator can
recover a failed commit call without blind rollback.

### 6.7 Authoritative readback

Readback includes:

~~~text
active_generation
active_digest
persisted_generation
core_config_revision
processor_state
dependency_errors
sidecar_instance_id
sidecar_bundle_digest
lease_state
prepared_generations
draining_generations
~~~

Repeated commit semantics:

- current G1 and requested G1: return the same success;
- current G0 and prepared G1: retry;
- current G2 while request expects G0: conflict.

### 6.8 Startup quarantine

Before opening client data-plane listeners, mihomo:

1. loads the last durable active generation;
2. validates both required anchors;
3. installs one quarantine `RuntimeSnapshot` in which ordinary non-capture
   routing remains available, known capture matches reject, and processor egress
   capabilities are disabled;
4. opens client listeners only after that quarantine snapshot is active;
5. waits for exact sidecar bundle/certificate readiness;
6. atomically swaps the same generation from quarantined to ready only after a
   fenced readiness lease is valid.

If anchors are missing, the active artifact is corrupt, or the capture set
cannot be reconstructed, mihomo cannot safely provide the ordinary path unless
an independently persisted minimal deny artifact exists. Recovery otherwise
refuses the affected client data plane. Sidecar unavailability alone does not
stop unrelated ordinary routing; it keeps the quarantine snapshot active.

### 6.9 Sidecar readiness lease

~~~text
processor_id
process_instance_id
generation_id
sidecar_bundle_digest
certificate_host_set_digest
OS peer identity
lease_id and fencing token
heartbeat expiry
~~~

The readiness lease attests that the exact bundle is prepared and can be chosen
if mihomo publishes its generation as active. It does not independently
activate the sidecar. Lease expiry changes readiness, not desired state. The
overlay remains active and matching traffic rejects.

A new mihomo boot epoch invalidates old leases, fencing tokens, UDP
associations, and connection/session handles. It does not erase immutable
generation artifacts or durable SOCKS capability mappings. Those mappings are
reconstructed in disabled/quarantine state and become usable only after a new
matching sidecar lease is established.

### 6.10 Long-lived HTTP semantics

A raw connection is not one HTTP transaction. The sidecar enforces generation
at the transaction layer:

- each started transaction captures one immutable generation;
- new transactions resolve the current generation from mihomo's authoritative
  read-only endpoint backed by mihomo's atomic `RuntimeSnapshot`;
- a missing view, digest mismatch, or missing prepared bundle fails closed;
- graceful retirement stops new old-generation work;
- H1 stops keep-alive reuse;
- H2 sends GOAWAY;
- H3 stops accepting new request streams;
- WebSocket and other long-lived flows have a maximum retirement age;
- disable, permission removal, host removal, and master-off hard revoke;
- old upstream pools never accept new work after retirement.

Current 5gpn already reads config per request and retires transport generations:

- `cmd/5gpn-intercept/proxy.go:283-360`
- `cmd/5gpn-intercept/proxy.go:391-466`

The new model must preserve timely revocation rather than pin permissions to a
long-lived TCP connection.

### 6.11 Egress groups

The sidecar submits an opaque capability, not a group name. The egress request
enters mihomo's dedicated runtime-overlay egress phase; it must never continue
into the client overlay or ordinary operator rules. An unmatched or invalid
processor egress request reaches the fixed egress reject terminator.

The capability is accepted only if the current `RuntimeSnapshot` lists it under
the active generation or an explicitly draining generation. Prepared
capabilities are rejected. A hard revoke removes old capabilities in the live
swap; a graceful transition retains them only until the bounded transaction
drain deadline.

At egress resolution mihomo:

- resolves the server-side binding;
- confirms the group still exists;
- rejects processor-reachable groups and chains;
- rejects recursion;
- applies any policy forbidding `DIRECT`;
- consumes the request in the dedicated egress phase;
- never falls back to `DIRECT`.

Removal of a referenced group through supported config or API paths is rejected
by default. Out-of-band removal marks the generation degraded while captures
remain fail-closed.

### 6.12 Hardened SOCKS5 UDP

Current mihomo UDP listener accepts datagrams independently of an authenticated
TCP association:

- `listener/socks/udp.go:42-98`

Required replacement behavior:

- authenticated `UDP ASSOCIATE` creates a private ephemeral UDP socket;
- association binds control connection, peer, and authenticated capability;
- control close destroys the socket;
- every datagram revalidates target policy;
- quotas limit associations, datagram size, bytes, rate, and lifetime;
- revocation closes affected associations;
- unauthenticated datagrams never reach processor egress.

The sidecar implementation is a useful reference:

- `cmd/5gpn-intercept/proxy.go:182-250`
- `cmd/5gpn-intercept/socks.go`

Revocation of already-established sessions does not need a new core mechanism.
`component/nat.Table` exposes no predicate-based iteration, but every UDP NAT
session is wrapped in a tracker registered with `statistic.DefaultManager`
(`tunnel/tunnel.go:479`), the manager supports `Range`
(`tunnel/statistic/manager.go:55-59`), and closing a tracked `PacketConn` runs
the deferred cleanup that removes the NAT entry
(`tunnel/connection.go:168-174`). Enumerate-and-drop-by-predicate over that
manager is the pattern `DELETE /connections` and
`adapter/provider/provider.go:167-177` already use. The overlay's revocation
predicate is the generation-bound capability recorded on the tracker's chain, so
the required work is carrying that identity onto the tracker, not building
enumeration.

### 6.13 DNS rebinding and pinned dialing

The current script network path permits an exact hostname, then delegates the
unresolved domain to SOCKS. Private-address guards use `no-resolve`, so a domain
can rebind after authorization.

Evidence:

- `cmd/5gpn-dns/intercept_module_types.go:854-895`
- `cmd/5gpn-intercept/module_network.go:268-298`
- `cmd/5gpn-dns/intercept_mihomo.go:180-187`
- `etc/mihomo/config.yaml.tmpl:81-91`
- `rules/common/ipcidr.go:38-47`

The authoritative egress boundary:

1. resolves through the generation's resolver profile;
2. validates every IPv4/IPv6 result;
3. rejects loopback, private, link-local, CGNAT, multicast, unspecified,
   mapped, and other forbidden scopes;
4. selects a validated numeric address;
5. dials that numeric address through the selected leaf adapter;
6. never delegates the original domain to a downstream remote resolver;
7. repeats checks for redirects, rewrites, retries, and new pooled connections.

The raw HTTP Host and TLS ClientHello retain application authority while the
transport targets the pinned IP. An adapter that cannot accept pinned IP is
ineligible for `public-only` and fails closed.

### 6.14 Resolver and certificate ownership

Keep client DNS overlay separate from processor origin resolution:

1. Client DNS chooses gateway, quarantine, or normal policy.
2. Processor egress uses a generation-bound trust/China resolver profile.

The latter cannot be an independent unversioned hostname map after commit.

A single mutable certificate path is also insufficient across overlapping
generations. Use immutable artifacts:

~~~text
certificates/
  <host-set-digest>/
    <leaf-fingerprint>/
      fullchain.pem
      privkey.pem
      metadata.json
    current -> <leaf-fingerprint>
~~~

Old artifacts remain until dependent generations are revoked. The root CA key
remains outside mihomo and sidecar runtime.

### 6.15 DNS publication

- Publish DNS after effective generation readback.
- Confirmed old capture hosts continue returning gateway.
- New uncommitted hosts return an authoritative cacheable negative — `NOERROR`
  with an empty answer section and a short fixed TTL — not `SERVFAIL`.
- Temporary processor failure does not restore normal DNS.
- Explicit disable removes processor behavior; cached gateway traffic then
  follows ordinary mihomo rules.
- UI documents gradual convergence caused by client DNS caches.

`SERVFAIL` is the wrong signal here because it is the one rcode with
transient-failure semantics. Resolvers and stub clients treat it as "this server
is broken, try another one," which is an invitation to fail over to a resolver
that has no gateway mapping at all — the exact bypass quarantine exists to
prevent. It is also not negatively cached: 5gpn's own resolver refuses to cache
any non-success rcode and caches `NODATA` at `TTLMin`
(`cmd/5gpn-dns/handler.go:1371-1379`), so a `SERVFAIL` quarantine answer would
be re-queried at full rate for as long as quarantine lasts. An authoritative
empty `NOERROR` is cacheable, is not a failover trigger, and converges on the
short TTL when the generation becomes ready. Use `NXDOMAIN` only for hosts that
are genuinely not in any generation's capture set.

## 7. Security and trust model

| Threat | Enforceable guarantee |
| --- | --- |
| Malicious JavaScript confined to plugin API | Runtime origins, quotas, settings, and process sandbox |
| JavaScript escape or complete sidecar compromise | Only mihomo L3/L4 destination, egress, and quota constraints remain trustworthy |

`extension_id`, `generation_id`, and `session_id` are identifiers, not secrets.
A compromised shared sidecar can impersonate another loaded plugin.

If one plugin escape must not affect another:

~~~text
mihomo
  <-> trusted intercept front end
  <-> bounded normalized HTTP transaction IPC
  <-> per-installation untrusted workers
~~~

### 7.1 Raw dial limitation

A raw TCP/UDP capability constrains endpoint and egress, but cannot prove an
HTTP origin after sidecar compromise. A compromised sidecar can change TLS SNI,
Host, or protocol on an allowed endpoint.

Therefore:

- captured primary upstream may use the raw path under a trusted-sidecar model;
- auxiliary plugin networking needs a trusted bounded HTTP fetch broker if
  origin semantics must survive sidecar compromise;
- documentation calls raw egress endpoint authorization, not origin
  authorization.

### 7.2 Controller and browser boundary

Generic controller defaults are unsuitable for extension mutation:

- auth is conditional on non-empty secret;
- default CORS allows `*` and private network access;
- controller Unix socket is `0666` and bypasses the secret;
- named pipe also bypasses the secret.

Evidence:

- `hub/route/server.go:105-143`
- `hub/route/server.go:251-326`
- `config/config.go:594-598`

Runtime-overlay mutation uses a separate machine-only endpoint with strict ACL
and peer identity. Browser management stays behind the 5gpn BFF, HttpOnly
session, Origin/CSRF validation, and one-use sensitive WebSocket tickets.

The read-only generation endpoint that 6.4 and 6.10 require the sidecar to poll
is a second, distinct endpoint, and it needs its own stated boundary rather than
inheriting one by omission:

- it is a separate `AF_UNIX` socket (Linux) from the mutation endpoint, so a
  read grant never implies a write grant;
- mode `0600`, owned by the mihomo runtime user, with the sidecar's user granted
  access explicitly — by group or by an ACL entry, not by widening the mode.
  `hub/route/server.go:279-287` is the anti-pattern to avoid: it listens and
  then `os.Chmod(addr, 0o666)`, which makes the controller socket reachable by
  every local user and bypasses the secret entirely;
- `SO_PEERCRED` verification of the connecting process against the expected
  sidecar identity, checked on every connection, not once at startup;
- responses are `no-store` and carry the boot epoch and fencing identity so a
  reply captured from a previous mihomo process cannot be replayed;
- the endpoint is read-only in the strict sense — no method on it may mutate
  overlay, lease, or generation state, including as a side effect.

This matters more than it looks. The table above claims that after a complete
sidecar compromise the mihomo-enforced L3/L4 and egress constraints remain
trustworthy. That claim holds only if the compromised sidecar cannot reach the
mutation endpoint. Placing both endpoints on one socket, or leaving the read
socket world-accessible, silently converts a sidecar compromise into a control
plane compromise.

### 7.3 Confirmed pre-implementation blockers

1. Fix DNS rebinding in the current script network path.
2. Fix zashboard notification DOM XSS:
   - `src/api/http.ts:39-45`
   - `src/helper/notification.ts:99-102`
   - controller secret storage in `src/store/setup.ts:47-60`.
3. Fix zashboard's placeholder WebSocket token conflict with server-injected
   Authorization.
4. Fix authenticated SOCKS UDP association ownership.
5. Add body, upstream, and transaction deadlines to the sidecar.
6. Decide whether the shared sidecar is trusted or per-plugin workers are
   required.
7. Requalify the panel guard `DIRECT` rules that currently precede the egress
   terminator (`etc/mihomo/config.yaml.tmpl:78-79`, `:91`), so a compromised
   sidecar cannot reach the gateway's loopback management plane.
8. Specify and implement the read-only generation socket's transport, mode, and
   peer verification before the sidecar depends on it (7.2).

## 8. Failure and recovery matrix

| Failure | Required result |
| --- | --- |
| Coordinator crashes before journal | No operation; G0 remains |
| Journal persists, prepare incomplete | Repeat idempotent prepare |
| Certificate prepared, later failure | G0 remains; artifact later GC'd |
| Sidecar prepared, coordinator crashes | G0 remains; rebuild/reuse bundle |
| Mihomo generation staged, coordinator crashes | Active remains G0 |
| Commit sent, response lost | Read active generation; never blind rollback |
| Mihomo persists G1 then crashes before live swap | Restart loads G1; roll forward |
| Coordinator crashes after G1 commit | Journal and readback recover G1 |
| Coordinator crashes before DNS publish | Verify G1, then publish DNS |
| Sidecar disappears while G1 active | G1 remains active/not-ready; captures reject |
| Sidecar restarts | Rebuild exact bundle; obtain new fenced lease |
| Mihomo restarts | Load G1 before listeners; quarantine until readiness |
| Referenced group removed through API | Reject config change |
| Group disappears out of band | Mark degraded; egress fails closed |
| Old H2/H3 connection remains | Stop new streams; bounded drain; force close |
| Active state corrupts | Refuse unguarded data plane or install deny guard |
| Client caches old real IP after enable | Cannot recall; converge by TTL |
| Client caches gateway after disable | Ordinary rules apply after disable |
| Operator needs an immediate global bypass while the coordinator is down | Documented single-step local escape that revokes the overlay without the coordinator, then falls back to ordinary rules; forced rule mode means the usual Direct/Global panic switch is unavailable (6.2.2) |
| Resolver profile changes but cached answers persist | Commit advances the resolver cache epoch in the same swap (6.6) |
| Downgrade leaves durable overlay artifacts | Purge before binary replacement; a later upgrade must not resurrect them (12.2) |

## 9. Why Option C is not the initial target

A normal `ProxyAdapter` is not a complete processor contract:

- it receives dial-projected metadata, not immutable original context;
- `Metadata.Pure()` may clear host;
- generic retry can invoke a processor up to ten times;
- `NeedHandshake` can replay buffered application bytes;
- ordinary proxies enter GLOBAL, groups, URL tests, and include-all lists;
- one outer tracker is created before broker egress exists;
- adapter cleanup relies partly on finalizers.

Evidence:

- `constant/metadata.go:278-287`
- `tunnel/tunnel.go:560-605`
- `tunnel/tunnel.go:723-758`
- `config/config.go:895-971`
- `adapter/outboundgroup/parser.go:95`
- `tunnel/statistic/tracker.go:24-146`
- `adapter/outbound/base.go:356-399`

UDP is a larger mismatch. Current NAT selects one proxy for a sender and later
passes only payload plus destination address through `PacketConn`:

- `tunnel/tunnel.go:420-499`
- `tunnel/connection.go:16-144`
- `component/nat/table.go`

Later datagrams lose original host, sniff host, generation, and route context.
A custom UDP processor therefore needs a dedicated packet-session API and
cannot be hidden safely behind current `WriteTo(payload, addr)` semantics.

## 10. Conditional Option C

Option C starts only after at least one trigger:

- sidecar must be restricted to `AF_UNIX` at OS level;
- processor requires metadata SOCKS cannot carry;
- mihomo must enforce per-session egress capabilities;
- benchmarks attribute more than approximately 5-10% CPU or more than 1 ms p95
  latency to SOCKS;
- multiple processors or structured intermediate decisions are required.

If triggered, start TCP-only:

- one UDS `SOCK_STREAM` per processed TCP flow;
- one separate UDS stream per actual egress TCP connection;
- separate processor and egress listeners;
- bounded fixed preface plus extensible TLV;
- synchronous OPEN/ACK before raw application bytes;
- no `NeedHandshake` integration;
- no replay after ACK;
- explicit terminal/retryable statuses;
- OS peer verification and defense-in-depth channel auth;
- native half-close;
- no shared multiplexed data connection in v1.

Sidecar-provided IDs, target, and group are not authorization facts. Mihomo
creates an opaque server-side flow record bound to boot epoch, processor,
generation, operation, fixed egress, expiry, and quotas.

Custom UDP/H3 remains a separate milestone and retains SOCKS as the differential
oracle until soak and fault testing pass.

## 11. Management APIs

Conceptual machine-only API:

~~~text
control socket (coordinator only, read-write):
  GET  /capabilities
  PUT  /runtime-overlays/5gpn/generations/{generation_id}
  POST /runtime-overlays/5gpn/generations/{generation_id}/commit
  POST /runtime-overlays/5gpn/generations/{generation_id}/abort
  GET  /runtime-overlays/5gpn

generation socket (sidecar only, read-only):
  GET  /runtime-overlays/5gpn/active
~~~

The two sockets are separate transports with separate ACLs; see 7.2. `/abort`
accepts only a `STAGED` generation and is rejected for anything already active,
draining, or revoked (6.6). `GET .../active` returns the authoritative view
described in 6.4 — processor state, active bundle and certificate digests, lease
expiry, expected process instance, and fencing identity.

`GET /capabilities` returns a stable controller API version and independently
versioned feature descriptors, for example an understood
`runtime-overlays: { version: 1 }` entry. The browser-facing BFF may expose a
narrower aggregate capability document, but it must preserve the distinction
between unsupported, temporarily unavailable, and unknown future schema.

Requirements:

- strict typed schema and size limits;
- CAS with core and active generation revisions;
- idempotency key and stable errors;
- no-store responses;
- no scripts, executables, arbitrary paths, or remote URLs;
- protected UDS/named-pipe ACL and peer verification;
- no generic controller local transport.

zashboard calls a same-origin 5gpn BFF. The BFF performs review, invokes all
components, aggregates effective state, retains the real mihomo secret, and
mints one-use WebSocket tickets.

## 12. Migration plan

Persist an explicit driver:

~~~text
legacy-yaml-socks
overlay-socks
overlay-broker
~~~

Startup never auto-detects and oscillates between drivers.

### 12.1 A to B

1. Add inactive overlay registry, persistence, capability, and readback.
2. Add both validated runtime anchors.
3. Add `overlay-socks` driver while retaining legacy.
4. Shadow-compile the same desired state into legacy rules and inactive
   generation; compare normalized semantics.
5. Prepare and read back the target generation.
6. Commit overlay generation.
7. Perform one controlled cleanup of dynamic legacy YAML blocks.
8. Verify sidecar, mihomo, groups, certificate, and DNS.
9. Retain legacy renderer and backup for at least one release.

Rollback:

1. materialize and validate legacy YAML, retaining both anchors as inert
   declarations;
2. commit a terminal empty generation with `transition_mode: revoke`, which
   clears the client overlay and hard-revokes every egress capability in one
   live swap;
3. read back and confirm no active generation and an empty draining registry;
4. publish and read back the legacy runtime;
5. clear the persisted overlay artifacts and recovery pointer;
6. switch persisted driver.

The ordering matters and the obvious order deadlocks. 6.2 requires config reload
to reject a candidate whose anchors are missing or reordered while an overlay is
persisted, so publishing anchor-free legacy YAML before the overlay is stood
down is rejected by the core's own guard. Keeping the anchors present but inert
in the rollback YAML (step 1) and revoking through the overlay's own commit path
(step 2) removes the circular dependency, and keeps the revocation atomic
instead of inferring it from a successful file publish.

Overlap precedence during the window is defined rather than incidental: while
any generation is active or draining, the overlay is authoritative and legacy
dynamic rule blocks must not be present in the published config. There is no
supported state in which both rule sources are live, because their relative
order would then depend on where the legacy renderer happened to place its
blocks relative to the anchors.

A timeout always requires generation readback.

### 12.2 B to optional C

1. Keep SOCKS and custom transports available.
2. Include transport mode in generation.
3. Start TCP-only.
4. Route new flows by generation while old flows drain.
5. Roll back by committing a SOCKS generation.
6. Keep custom UDP disabled until independent H3 and soak gates pass.
7. Retain SOCKS for at least one release after custom transport becomes default.

Downgrade to an older mihomo binary first materializes the active overlay back
to legacy YAML and proves the runtime before binary replacement. It must also
purge mihomo's durable overlay state, in this order:

1. run the 12.1 rollback in full, ending with the driver switched to
   `legacy-yaml-socks`;
2. verify no generation artifact, recovery pointer, or durable capability
   mapping remains on disk;
3. only then replace the binary.

Skipping step 2 leaves artifacts that the old binary does not understand and
does not clean up. The failure is not cosmetic: the durable SOCKS capability
mappings of 6.9 outlive a boot epoch by design, and a later upgrade back to the
fork would find them, reconstruct them in quarantine state, and resurrect a
generation the operator believes was rolled back. The downgrade contract asked
for in Section 16 question 15 must state which artifacts are purged, which are
archived, and what the fork does on startup when it finds state written by a
newer overlay schema version.

## 13. Engineering scope and ROI

Approximate current surfaces:

- YAML/routing ownership plus tests: about 1.8k lines;
- sidecar SOCKS plus tests: about 1.0k lines;
- manager plus tests: about 2.5k lines, only partly mihomo-specific.

Rough effort for a team familiar with all repositories:

- Option B: approximately 12-18 engineer-weeks including migration and tests;
- Option C after B: approximately 10-18 additional engineer-weeks.

The Option B figure was revised upward from an earlier 6-10 estimate. Section 15
lists 13 fork work items and 10 control-plane items, and 14.1 lists about 30
required test areas, several of which are race, fuzz, and multi-process
restart-ordering suites rather than unit tests. A durable generation store with
CAS, crash-consistent recovery, and readback is on its own a multi-week item;
the anchor and bypass guard work spans the config parser, the executor, and the
controller. Treating the estimate as 6-10 weeks makes the schedule the first
thing to fail.

### 13.1 Private-fork carrying cost

Option B is a permanent private fork of an actively developed upstream, and the
recurring cost of that fork is a first-order input to the decision. It was
missing from the first revision.

Upstream churn in the files Option B modifies, measured on
`MetaCubeX/mihomo@b9faf97` since 2025-01-01:

| Path | Commits | Option B's stake |
| --- | --- | --- |
| `adapter/outbound` | 230 | 6.13's per-adapter pinned-dial eligibility matrix |
| `listener/inbound` | 151 | in-scope listener guards |
| `config/config.go` | 51 | closure validation, GLOBAL/`include-all` exclusion |
| `hub/route` | 34 | management endpoints, incremental mutation guards |
| `rules` | 29 | anchor rule types and matcher representation |
| `tunnel/tunnel.go` | 21 | both anchors, egress phase, revocation |
| `hub/executor/executor.go` | 21 | commit serialization with config reload |
| `listener/socks` | 14 | authenticated UDP associations |

The repository took 811 commits in the trailing twelve months. `adapter/outbound`
alone at 230 commits is the highest-churn area in the table and is precisely
where 6.13 requires per-adapter behavioral knowledge, so the pinned-dial
eligibility matrix is not a one-time deliverable — it is a standing obligation
re-validated on every rebase.

Upstream also keeps adding features that create new bypass carriers, three of
them within a single week in June 2026 (see 6.2.2). Each one is a rebase where
the fork must decide whether a new routing primitive can reach around the
anchors.

The honest budget therefore has two lines, not one:

- build: the 12-18 engineer-weeks above;
- carry: recurring rebase, re-validation of the bypass matrix, and re-validation
  of the adapter eligibility matrix, for as long as the fork exists.

The carry line has no natural end and needs a named owner before implementation
starts. It is also the strongest argument for the 6.2.2 position: a pre-routing
stage is a smaller and more stable diff than a guard list that must be re-derived
against every upstream routing feature.

Option B may remove 500-800 production lines of YAML transaction code while
adding comparable or greater typed generation and recovery code. Its value is
correctness and a smaller failure domain, not line count.

Option C is expected to increase total code. Its value is transport identity,
metadata, and OS network isolation, not simplicity.

## 14. Verification requirements

### 14.1 Option B

- canonical projection digest and quotas;
- both anchor stages and exact precedence;
- missing/duplicate/reordered anchor rejection;
- active-overlay rejection of Direct/Global mode through full config and
  incremental `PATCH /configs`;
- active-overlay rejection or safe fail-closed handling of
  `PATCH /configs {sniffing:false}` and sniffer force/skip changes;
- in-scope listener `proxy`/`rule` override rejection and
  `SpecialProxy`/`SpecialRules` bypass tests;
- top-level `tunnels:` entry with a `proxy:` target is rejected while the
  overlay is active, and cannot reach egress if introduced out of band;
- a reachable `rematch` outbound or `PASS-RULE` target cannot redirect capture
  traffic out of the anchored rule list;
- `hosts:` mutation cannot move a capture host out of the client overlay's
  match set;
- no allow rule precedes the egress anchor without an `intercept-egress`
  exclusion; a sidecar-originated connection to the console and dashboard hosts
  reaches the egress terminator;
- processor targets are absent from GLOBAL, `include-all-proxies` groups, URL
  tests, and dialer-proxy chains;
- protected anchors, egress terminator, and system guards cannot be disabled
  through `PATCH /rules/disable`;
- all incremental routing mutations advance/check the same core revision;
- mixed `PATCH /configs` and `PATCH /rules/disable` payloads containing one
  forbidden change produce no partial mutation;
- CAS conflict and idempotent repeat commit;
- lost commit response followed by readback;
- persistent generation corruption and directory fsync;
- all process startup orders;
- sidecar lease expiry and fencing;
- lease expiry prevents new streams on an already-established H2/H3 connection;
- G1 H2 disablement and certificate rotation race with G0 handshakes;
- config reload racing commit;
- referenced group deletion and recursion;
- graceful update and hard revoke;
- H1 keep-alive, H2, WebSocket, QUIC v1/v2, and H3;
- authenticated UDP association and revocation;
- DNS rebinding and pinned dial;
- resolver cache epoch advances on a resolver-profile change, and no
  pre-commit answer is served after the swap;
- quarantine answers are cacheable negatives, not `SERVFAIL`, and converge on
  the fixed short TTL;
- the read-only generation socket rejects a non-sidecar local peer, rejects
  every mutating method, and cannot be used to reach the mutation socket;
- rollback executes in the 12.1 order without tripping the anchor guard, and
  legacy rules are never live while a generation is active or draining;
- downgrade leaves no durable overlay artifact, and a subsequent upgrade does
  not resurrect a revoked generation;
- certificate retention and GC;
- DNS always after effective generation;
- race and fuzz tests;
- the full bypass matrix above re-runs as a merge gate on every upstream rebase
  (13.1).

### 14.2 Option C additions

- golden wire vectors and parser fuzzing;
- OPEN/ACK at every partial read/write boundary;
- no bytes before ACK and no replay after ACK;
- bidirectional half-close and cancellation;
- unauthorized peer and stale boot epoch;
- FD, memory, and goroutine recovery;
- parent/child tracking without double counting;
- SOCKS/custom differential behavior;
- TCP-only release before custom UDP;
- H3 and repeated process restart;
- at least 72-hour soak before removing SOCKS fallback.

Suggested relative performance gates:

- TCP throughput at least 95% of SOCKS baseline, never below 90%;
- CPU/byte and allocations regress no more than 15%;
- connection-open p50/p99 regress no more than 20%;
- H3 throughput at least 90% of SOCKS UDP baseline;
- H3 p99 regression no more than 10% or 1 ms;
- no unexplained datagram loss;
- soak with 10k idle TCP, 2k UDP, and 1k active egress;
- no bypass, hang, or leak under repeated processor restart.

## 15. Required implementation work

### Mihomo private fork

- typed two-stage overlay compiler;
- durable generation store and recovery pointer;
- one atomic in-memory `RuntimeSnapshot` shared by matching, egress, readback,
  and the sidecar generation endpoint;
- CAS, idempotency, readback, and stable errors;
- serialization with core config reload;
- rule-mode enforcement and in-scope listener routing guards;
- closure guards for top-level `tunnels:` and `hosts:`, per-listener `proxy`,
  and reachable `rematch`/`PASS-RULE` targets;
- a parse-time exclusion flag keeping processor targets out of `AllProxies`,
  GLOBAL, and `include-all-proxies`;
- resolver cache epoch advanced by the overlay commit;
- dependency and recursion validation;
- sidecar readiness lease and quarantine;
- deterministic drain/revoke registry;
- generation egress capability mapping;
- generation identity carried on UDP trackers so revocation can enumerate and
  close established associations;
- private authenticated SOCKS UDP associations;
- pinned resolver/dial policy;
- machine-only management endpoint, plus a separate read-only generation socket
  with its own ACL and peer verification;
- structured status and metrics;
- a rebase gate that re-runs the bypass matrix against each upstream merge.

### 5gpn control plane

- persistent operation journal;
- immutable generation and bundle IDs;
- legacy and overlay drivers;
- shadow semantic comparison;
- prepare, commit, readback, and roll-forward recovery;
- versioned certificate artifacts;
- resolver profile projection;
- DNS pending/quarantine state;
- quarantine answers as cacheable negatives, and a DNS cache epoch advanced by
  the same commit that advances mihomo's;
- requalify the panel guard block so its `DIRECT` allow rules cannot be reached
  by processor-originated traffic;
- driver-aware upgrade, downgrade, and rollback, including durable overlay
  artifact purge before a binary downgrade;
- eventual removal of ordinary complete-YAML mutation.

### 5gpn-intercept

- stable bundle digest;
- bounded prepared bundle retention;
- transaction-level generation capture;
- H1/H2/H3 retirement and hard revoke;
- generation-keyed pools and credentials;
- readiness registration and fencing;
- body/upstream deadlines;
- optional later trusted front end plus per-installation workers.

### zashboard and BFF

- fix notification XSS and WebSocket placeholder token;
- explicit capability discovery;
- model unknown, supported, unsupported, and unavailable;
- use 5gpn BFF for all mutations;
- show desired, prepared, effective, degraded, and quarantined states;
- show generation, digest, dependency errors, drain, and DNS convergence;
- keep sensitive logs ticketed and text-only.

## 16. Cross-review questions

Independent reviewers should explicitly answer:

1. Is the shared sidecar trusted, or must one plugin escape be isolated?
2. Is forcing rule mode and forbidding in-scope listener routing overrides
   acceptable, or must the design move to a core pre-routing stage before
   `SpecialProxy`, `SpecialRules`, and mode selection? The cross-review's
   position is recorded in 6.2.2: acceptable for the first release, planned as a
   second increment. This question is answered but not closed; closing it is a
   decision, not a review finding.
3. Is active state corruption a startup failure or a durable deny-guard mode?
4. Which core config changes are allowed while an overlay is active? 6.2.1 now
   names the closure; the remaining question is who owns extending it when
   upstream adds a field.
5. What are group deletion and provider mutation semantics?
6. Do group changes close established upstream connections?
7. How is the trust/China resolver profile generation-bound? 6.6 now requires a
   cache epoch; the remaining question is whether the epoch invalidates
   selectively or clears the whole cache.
8. Which changes are graceful and which hard revoke?
9. What are maximum drain times for H1/H2/H3/WebSocket/UDP? 6.6 requires these
   to be finite and per-protocol; the values are still unset.
10. Which certificate artifacts remain valid during overlap?
11. Must auxiliary networking retain origin security after sidecar compromise?
12. Which adapters qualify for pinned-IP `public-only` dialing? 13.1 shows this
    is a standing obligation across 230 commits of `adapter/outbound` churn, not
    a one-time matrix.
13. What exact evidence triggers Option C?
14. Is Windows production required or development-only for a custom transport?
15. What downgrade contract is required after Option B? 12.2 states the minimum;
    the schema-version-mismatch behavior is still open.

Questions added by the cross-review:

16. Who owns the private fork's recurring carry cost in 13.1, and what is the
    maximum acceptable rebase lag behind upstream?
17. Is the 12-18 engineer-week Option B estimate accepted, and does the schedule
    account for the race, fuzz, and restart-ordering suites in 14.1?
18. What is the operator's single-step escape hatch when the coordinator is
    unreachable and rule mode is forced?

## 17. Final verdict

The system needs a first-class external-processing control plane, but it already
transports the required bytes. The immediate architectural problem is the
absence of a typed, owned, atomic, persistent, and observable runtime policy
generation inside mihomo.

Option B removes the dominant operational risk while preserving mature and
difficult protocol coverage. Option C remains a legitimate future
security/performance architecture, but it must be evidence-triggered and
introduced TCP-first behind a dual-stack migration.

The adversarial cross-review did not change this conclusion. It found no defect
that undermines the choice of Option B, and the cheapest-looking alternative —
rule-provider hot reload — is disqualified by three independent fail-open paths
(5.2). What it did change is the price: the estimate is now 12-18 engineer-weeks
plus an open-ended fork carry cost (13.1), and the rule-layer anchors are
recorded as a first increment rather than the permanent boundary (6.2.2).

Implementation should begin only after independent review closes the questions
in Section 16, the confirmed security blockers in 7.3 are assigned, and the fork
carry cost in 13.1 has a named owner.

## 18. Evidence index

### Mihomo

- TCP/UDP paths: `tunnel/tunnel.go`
- UDP sender: `tunnel/connection.go`
- proxy contract: `constant/adapters.go`
- metadata projection: `constant/metadata.go`
- tracker: `tunnel/statistic/tracker.go`
- config apply: `hub/executor/executor.go`
- controller config: `hub/route/configs.go`
- rule providers: `rules/provider/rule_set.go`,
  `rules/provider/classical_strategy.go`, `hub/route/provider.go`
- auth/local transports: `hub/route/server.go`
- routing bypass carriers: `adapter/outbound/rematch.go`,
  `listener/tunnel/tcp.go`, `adapter/outboundgroup/parser.go`
- connection enumeration: `tunnel/statistic/manager.go`,
  `adapter/provider/provider.go`
- resolver cache: `dns/resolver.go`
- SOCKS outbound: `adapter/outbound/socks5.go`
- SOCKS inbound: `listener/socks/tcp.go`, `listener/socks/udp.go`

### 5gpn

- current architecture: `docs/architecture.md`
- durable decisions: `MEMORY.md`
- rendered mihomo seed and listeners: `etc/mihomo/config.yaml.tmpl`,
  `install.sh`
- extension types/parser: `cmd/5gpn-dns/intercept_module_types.go`,
  `cmd/5gpn-dns/intercept_module_parser.go`
- manager/YAML projection: `cmd/5gpn-dns/intercept_module_manager.go`,
  `cmd/5gpn-dns/intercept_mihomo.go`
- sidecar config/proxy/SOCKS: `cmd/5gpn-intercept/config.go`,
  `cmd/5gpn-intercept/proxy.go`, `cmd/5gpn-intercept/socks.go`
- script networking: `cmd/5gpn-intercept/module_network.go`
- certificate publisher: `scripts/intercept-cert-renew.sh`
- DNS/resolver: `cmd/5gpn-dns/handler.go`,
  `cmd/5gpn-dns/egress_dns_selector.go`

### Zashboard

- backend/capabilities: `src/types/index.d.ts`,
  `src/assembly/backend.ts`, `src/assembly/version.ts`
- Clash client: `src/api/clash.ts`
- notifications: `src/api/http.ts`, `src/helper/notification.ts`

### External context

- https://github.com/MetaCubeX/mihomo/discussions/2850
- https://github.com/MetaCubeX/mihomo/issues/2237
- https://github.com/MetaCubeX/mihomo/issues/2143#issuecomment-3018362464
- https://github.com/MetaCubeX/mihomo/discussions/2400#discussioncomment-15109880
- https://github.com/Zephyruso/zashboard/issues/473
- https://github.com/Zephyruso/zashboard/issues/513#issuecomment-3389083194
