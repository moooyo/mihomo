# Disposable-only 5gpn runtime acceptance

This checklist intentionally mutates runtime documents and live configuration,
occupies every extension-worker slot, and injects startup, timeout, crash, and
OOM failures. Run it only on a disposable host with out-of-band access. Never
run it against a working gateway or a host carrying unrecoverable operator
state.

The acceptance result is the observed runtime behavior, not a claim that the
test can roll back every injected failure. Capture the before-state for
comparison, but rebuild the host after the run.

## Prerequisites and fixture contract

- Satisfy all evidence and immutability rules in [README.md](README.md).
- Use a current release installed with the production worker-isolation
  boundary: pure cgroup v2 plus the managed systemd unit on Linux, or nested Job
  Objects on Windows.
- Serve controlled DNS groups, subscription content, an H1/H2 origin, and
  synthetic extension manifests from an acceptance environment whose exact
  source commit or image digest is recorded.
- Give every served object a recorded SHA-256. Stop before changing the gateway
  if any byte differs.
- Use a disposable Telegram bot token and disposable administrator accounts.
  Never place the token in shell history, process arguments, screenshots, or
  the evidence archive.
- Use the authenticated controller directly. Console clicks are not evidence
  for this repository's runtime contracts.

The controlled DNS fixture should provide at least these deterministic cases:

| Name | China group | Trust group | Purpose |
| --- | --- | --- | --- |
| `cn.acceptance.invalid` | delayed A `1.0.1.1` | immediate A `192.0.2.10` | China must win by embedded-CN membership, not arrival time |
| `foreign.acceptance.invalid` | immediate A `192.0.2.20` | delayed A `192.0.2.21` | Trust must win when China is not in the embedded CN set |
| `nxdomain.acceptance.invalid` | NXDOMAIN with SOA | NXDOMAIN with SOA | Rcode and authority preservation |
| `servfail.acceptance.invalid` | SERVFAIL with authority | SERVFAIL with authority | Failure preservation |

The `.invalid` names require the fixture resolvers to answer authoritatively;
they must never escape to public DNS.

Before the first write, record file hashes, controller projections, document
revisions, the main PID, `NRestarts`, open file descriptors, and the complete
fixture ledger.

## 1. DNS arbitration, member order, and generation boundaries

- [ ] Install temporary exact/suffix/keyword rules with deliberate overlap by
  one revision-correct whole-document `PUT /5gpn/dns`. The first matching rule
  wins globally across block, direct, and proxy intents. Reordering the same two
  rules changes the winner; a stale revision returns 409 without changing the
  document or live generation.
- [ ] `block` returns NXDOMAIN without contacting either upstream group.
  `direct` returns the real arbitrated address. `proxy` returns the configured
  gateway address. Unmatched `auto`, `direct`, and `gateway` fallback modes
  remain observably distinct.
- [ ] For `cn.acceptance.invalid`, both groups start concurrently and the
  delayed China answer wins despite the trust answer arriving first. For
  `foreign.acceptance.invalid`, trust wins only after the completed China reply
  proves non-CN. Arrival order never decides arbitration.
- [ ] Members within one group are attempted sequentially in configured order.
  A healthy first member prevents later attempts; a silent first member gets a
  fair slice of the remaining deadline and the second member is attempted.
  Recovery restores first-member precedence.
- [ ] Cancel a caller while one member is active. The cancellation does not
  count as a breaker failure. Let an attempt slice expire while the parent
  context remains live; the next member is attempted and the failed member is
  scored.
- [ ] Client-supplied ECS is removed. The configured China ECS value is sent to
  China UDP, DoT, and DoH members and stripped from replies; trust receives no
  ECS.
- [ ] Prime a cache entry, start a delayed old-generation query, then publish a
  policy or upstream change. The cache is empty for the new generation, and the
  delayed old answer cannot refill it. Query-log metadata remains paired with
  the answer generation that produced it.
- [ ] A complete DNS write hot-swaps policy, tuning, and both upstream groups as
  one immutable snapshot while round-tripping the installation-owned gateway
  projection unchanged. A write that changes any
  installation-owned listener, certificate, private-key, origin-listener, or
  gateway field returns 400 and leaves revision, disk bytes, cache generation,
  and listeners unchanged.
- [ ] Repeated writes containing a China DoH member leave the process file
  descriptor count flat after the retirement grace period.
- [ ] Subscription network failure, unsafe redirect, special-use dial target,
  oversized response, empty/partial parse, and stale source/revision retain the
  previous complete cache byte-for-byte. An unchanged successful fetch does not
  rewrite the cache or flush DNS responses.

Restore the intended DNS document before testing interception so DNS outcomes
do not depend on a temporary rule left behind.

## 2. Mandatory worker isolation and capacity

### Linux cgroup-v2 acceptance

- [ ] Break one mandatory startup-isolation prerequisite in a controlled boot
  fixture. The process exits before DoT, controller, or application listeners
  open. There is no in-process validation or execution fallback.
- [ ] During a blocked worker operation, locate its
  `workers.<main-pid>.<nonce>/action.<nonce>` leaf. It contains exactly the
  child PID, has `memory.max=536870912`, `pids.max=32`, and
  `memory.oom.group=1`; the child was born directly into the leaf rather than
  started in the parent and migrated later.
- [ ] The aggregate cgroup remains bounded at 1 GiB and 64 PIDs. The main
  mihomo PID never enters the worker aggregate or an action leaf.
- [ ] After success, cancellation, timeout, protocol failure, crash, and OOM,
  the leaf is empty and removed. No worker or descendant survives its operation.

### Windows Job Object acceptance

- [ ] On a disposable Windows host, the worker starts suspended with a leaf Job
  Object first and the aggregate Job Object second in the inherited job list.
  The leaf limits one process and 512 MiB; the aggregate limits two processes
  and 1 GiB. Breakaway flags are absent and kill-on-job-close is set.
- [ ] Only the three duplicated standard handles are inherited, child-process
  creation is restricted, exactly one worker PID is present before resume, and
  the previous suspend count is exactly one.
- [ ] Closing or terminating the leaf kills the complete operation. Closing the
  aggregate during process shutdown kills every remaining worker.

### Cross-platform admission and failure behavior

- [ ] Hold one script action in extension A and one in extension B. A second
  concurrent live action from A and any third worker-requiring live action fail
  immediately through the interception transformation error path; requests do
  not queue behind a slot. A concurrent controller review or validation that
  needs a worker returns HTTP 503 with code `worker_capacity_busy`.
- [ ] While both slots are occupied, parent-side reject, mock, header edit, URL
  rewrite, and bounded body replacement actions still complete. JavaScript,
  GoJQ, and DOM work remain subject to worker admission.
- [ ] Force one worker timeout, crash, malformed private-protocol response, and
  OOM. Each fails only its current validation or action. DoT, controller, other
  forwarding, and the other worker slot remain healthy.
- [ ] Each action receives a fresh VM. A global written by one request is absent
  from the next request, and a permission removed in a new immutable snapshot
  is not retained by a pooled transport or worker.
- [ ] Filesystem, process, module-loader, raw socket, and ambient network APIs
  are absent. Script network and persistent storage calls succeed only when the
  manifest grants them, remain bounded, and are served by parent-owned
  operations.

## 3. Native interception runtime

- [ ] Verify every external fixture against the pinned table in
  [README.md](README.md). Review the exact manifest URL, record the returned
  manifest and immutable snapshot digests, then install by quoting that review
  and the current revision. A byte or digest change between review and install
  returns a conflict and does not install anything.
- [ ] A new extension is disabled, has explicit `DIRECT` egress, defaults
  capture DNS to `trust`, and cannot enable until required typed settings and
  the complete reviewed capability disclosure are satisfied.
- [ ] Attempt to set `http3: true`. The API returns 422, preserves the revision,
  and keeps the fixed UDP/443 reject active. The `/rules/disable` product
  surface refuses to disable that guard.
- [ ] Hot-apply an otherwise valid complete operator config with the guard
  missing or duplicated. Complete-config ownership permits the apply, but the
  client boundary becomes not ready and interception fails closed. Restore the
  guard before continuing; the product rule API never claims to own the full
  YAML.
- [ ] Enable the master and an extension whose host is not in the current leaf.
  DNS claims the host at the gateway, the runtime reports pending certificate
  identity, and new HTTP/TLS traffic is rejected before ordinary routing. It
  never falls through to direct forwarding while pending.
- [ ] Publish a certificate result with a stale target digest, stale attempt,
  mismatched file hashes, incomplete SAN set, CA leaf, or invalid validity.
  None becomes ready. A result matching the current target, attempt, exact file
  hashes, validity, and SAN set changes runtime readiness without advancing the
  interception document revision.
- [ ] Plain HTTP and TLS H1/H2 run the same ordered native actions. H3 over
  UDP/443 is rejected; a fallback-capable client retries over TCP; an H3-only
  client fails. Operator-configured UDP/QUIC on another port remains outside
  HTTP interception.
- [ ] Reorder two overlapping extensions. Request and response actions, capture
  DNS ownership, egress ownership, and typed routing rules change together only
  after the reviewed revision-protected write. A stale reorder changes nothing.
- [ ] A selected egress group that disappears remains named, marks the extension
  not ready, withdraws its ready capture overlay, and never falls back to
  `DIRECT` or the terminal group. Rebinding restores readiness through the
  ordinary transaction.
- [ ] Typed extension routing rules can select only `REJECT` or `DIRECT`, are
  bounded, and exist only while both the extension and master are enabled. They
  run in reviewed execution order before ordinary capture and cannot name a
  proxy group.
- [ ] A network-granted script can reach a safe canonical HTTP(S) destination
  only through mihomo's inner dialer. Unsafe hosts, IP literals, unsafe
  redirects, excessive calls, oversized responses, and deadline expiry fail
  closed. A cross-origin rewrite forwards the complete method, decoded body,
  and end-to-end headers while runtime-owned framing fields remain excluded.
- [ ] Bodyless and buffered paths respect admission and expanded-body bounds.
  gzip, zlib/raw deflate, and Brotli inputs decode within limits; malformed or
  oversized input and output fail only the current action.
- [ ] Overflow the 1000-entry engine log ring. Cursor reads report `dropped`.
  Restart the process and verify the new stream returns `reset: true` with a
  usable current tail. Script console text never appears in the persistent
  journal.
- [ ] Optional Apple WLOC compatibility observation uses only the pinned
  manifest and script bytes and records whether the current live Apple origin
  exercised TCP/H2 through the selected inner-dialer egress. Because the remote
  origin's protocol behavior is not pinned, this observation cannot determine
  the reproducible acceptance result; the controlled H1/H2 fixture above does.

Root CA secrecy, root helper sandboxing, certificate-request path-unit delivery,
and atomic filesystem publication are integration responsibilities of the 5gpn
repository. This checklist asserts only the mihomo runtime's request/result
fence and traffic behavior.

## 4. Telegram lifecycle and authority

- [ ] Save the current bot projection and revision, then configure the
  disposable token, at least two administrators, and alerts through one
  revision-correct `PUT /5gpn/bot`. The response and every later read expose
  only `token_set`, never the token.
- [ ] An invalid but non-empty token produces a redacted `unreachable` runtime
  state without stopping DNS, interception, or the controller. Replacing it
  with the valid token stops the old polling generation before starting one new
  generation; two loops never consume the same token concurrently.
- [ ] `/id` answers any caller with only their own user and chat IDs.
  `/status` answers configured administrators and agrees with the live
  controller projections. `/resolve <domain>` reports the name-only policy and
  capture decision: terminal rules agree with the controller policy fields,
  while an unmatched `auto` name is not compared with the controller's final
  address arbitration. Other commands from a non-admin are silent.
- [ ] Remove one administrator while long polling is active. The replacement
  generation uses the new complete admin set on the next update; an obsolete
  generation cannot answer after cancellation.
- [ ] `/install`, `/enable`, `/disable`, `/update`, `/reorder`, `/policy`,
  `/restart`, `/logs`, and certificate-like commands receive the ordinary
  unknown-command response for an administrator. All runtime document
  revisions remain unchanged.
- [ ] With alerts disabled, no unsolicited message is sent. With alerts
  enabled, an interception master switched off while extensions exist, an
  absent/mismatched/expiring interception certificate, and a sustained
  subscription failure each send once per distinct condition. A healthy state
  silently re-arms the condition; unchanged failures do not spam and no
  resolver or generic upstream-health alert is fabricated.
- [ ] Block and restore Telegram reachability. State moves through
  `unreachable` and `running` with bounded retry backoff, and neither API nor
  journal output exposes the token embedded in Telegram request URLs.
- [ ] Stopping or killing mihomo cannot produce an alert from inside the dead
  process. Only an independent external probe may claim process availability.

Clear the disposable token before archiving evidence, but rebuild the host
rather than treating cleanup as rollback proof.

## 5. Managed controller and complete config apply

- [ ] Submit otherwise valid complete-config payloads that change, one at a
  time, the managed secret, controller certificate, private key, or safe
  external UI path. Each returns 409 restart required. The prior TLS listener,
  secret, UI route, data-plane generation, and authenticated WebSocket remain
  usable.
- [ ] Submit configs that add plaintext/DoH/Unix/pipe controller transport,
  change the fixed TLS listen address, set a routing mark, add client-auth or
  ECH, or name an unsafe UI path. Managed validation rejects each with 400
  before hot-apply; these invalid transitions are not reported as restartable.
- [ ] A command-line override that changes any managed controller projection is
  rejected before listeners open. Same-value options remain harmless, and
  ordinary non-managed mihomo mode retains its upstream override behavior.
- [ ] Submit an invalid complete config while the controller is live. Parsing or
  preflight fails before publication; the old controller and data-plane
  generation remain active.
- [ ] Submit a valid complete payload that keeps the managed controller
  projection identical and changes one ordinary runtime field. The change is
  atomic in memory, the operator YAML bytes remain unchanged, and loading the
  default path removes the payload-only change.
- [ ] Race two complete config applies. They serialize at one apply boundary;
  one writer cannot interleave its controller reconciliation and data-plane
  apply with the other, and the final live projection corresponds to one
  complete accepted config rather than a field-level merge.
- [ ] Force the current controller listener or a required DNS listener to end
  unexpectedly through the acceptance harness. The monolith exits instead of
  leaving a partially live gateway. Systemd replacement is host integration
  evidence and is recorded separately by the 5gpn repository.

## 6. Completion

- [ ] Capture final hashes, revisions, PIDs, restart counters, cgroup or Job
  Object evidence, worker cleanup, file descriptors, and redacted journals.
- [ ] Compare the observed behavior against every checkpoint. Do not convert a
  skipped destructive step into a pass.
- [ ] Revoke the disposable Telegram token and rebuild the gateway from the
  tested release before any later use.
