# Read-only 5gpn runtime smoke

This smoke verifies the running mihomo process without changing its durable or
live configuration. If a step needs `PUT`, `POST`, `PATCH`, `DELETE`, a signal,
a service restart, a fixture that intentionally blocks, or a file write, run it
only under [runtime-disposable.md](runtime-disposable.md).

## Prerequisites

- Deployment acceptance has already established the tested binary, process,
  controller origin, and DNS query endpoint. This checklist does not re-test
  artifact installation, systemd policy, bind addresses, or public listener
  publication.
- `MIHOMO_BINARY` is the exact tested executable and `MIHOMO_PID` is its current
  long-running process.
- `curl`, `jq`, `dig`, `sha256sum`, and process/cgroup inspection tools are
  available.
- `CONSOLE`, `CONTROLLER_ADDRESS`, and `CONTROLLER_PORT` identify the established
  controller endpoint, and `CONTROLLER_CA` is its trust file. `DNS_SERVER`,
  `DNS_PORT`, and `DNS_TLS_NAME` identify the DoT endpoint already proved by
  deployment acceptance.
- `CONTROLLER_HEADER_FILE` is a pre-existing root-owned regular file, is not a
  symlink, has mode `0600`, and contains exactly one
  `Authorization: Bearer ...` header plus its line ending. It is passed only to
  curl's `--header @file` input; never use a general curl config for secrets.
- `BLOCK_NAME`, `DIRECT_NAME`, `PROXY_NAME`, and `FALLBACK_NAME` name stable
  records already covered by the current DNS document. The evidence must show
  why each name exercises the claimed rule or fallback; this smoke does not add
  temporary rules.
- `NXDOMAIN_NAME` and `SERVFAIL_NAME` are stable fixture records whose expected
  Rcode and authority RRsets were recorded by the deployment fixture.

Use one helper for authenticated reads:

```bash
controller_get() {
  curl --disable --request GET --fail --silent --show-error \
    --proto '=https' --noproxy '*' \
    --resolve "${CONSOLE}:${CONTROLLER_PORT}:${CONTROLLER_ADDRESS}" \
    --cacert "$CONTROLLER_CA" \
    --header "@${CONTROLLER_HEADER_FILE}" \
    "https://${CONSOLE}:${CONTROLLER_PORT}$1"
}
```

The header file and its contents are never copied into the evidence bundle.
Negative authentication requests use the same fixed curl options and endpoint,
changing only whether the single Authorization header is absent or deliberately
invalid.

## 1. Runtime identity and worker boundary

- [ ] Record `$MIHOMO_BINARY -v`, its SHA-256, and `$MIHOMO_PID`. The process
  executable identity matches the recorded binary.
- [ ] The process tree contains the one long-running mihomo process and no
  reusable extension worker pool or sidecar. An idle gateway has no surviving
  `5gpn-extension-worker-v1` child.
- [ ] On Linux, within the delegated cgroup root already established by
  deployment acceptance, there is one `workers.<main-pid>.<nonce>` aggregate
  cgroup with
  `memory.max=1073741824`, `pids.max=64`, and `memory.oom.group=0`.
- [ ] The process log stream since `$MIHOMO_PID` started contains no
  hard-isolation startup-probe failure, unexpected controller-listener end,
  critical DNS-listener end, or escaped panic.

## 2. Controller discovery and authentication

- [ ] An authenticated `GET /capabilities` returns `controllerApi: "1"` and
  advertises `5gpn-core` version 1, `5gpn-dns` version 2,
  `5gpn-interception` version 7, and `5gpn-bot` version 1.
- [ ] Capability, DNS, interception, bot, and engine-log reads include
  `Cache-Control: no-store`.
- [ ] A missing or deliberately wrong credential returns 401 for
  `/5gpn/dns`, `/5gpn/interception`, `/5gpn/bot`, `/configs`, and `/proxies`.
  Error bodies contain neither the real secret nor engine-log text.
- [ ] The correct credential returns 200 from the same authenticated reads.
  `/ui/` remains the only public controller tree; this smoke checks only the
  route and cache headers, not Console content.

TLS identity, controller bind addresses, and absence of extra public listeners
belong to the 5gpn deployment smoke rather than this runtime-internal checklist.

## 3. DNS engine and current-policy observations

- [ ] Use the DNS query endpoint already established by deployment acceptance;
  for example, `dig +tls @$DNS_SERVER -p "$DNS_PORT" "$FALLBACK_NAME" A
  +tls-host="$DNS_TLS_NAME"`. This checklist makes no claim about which host
  facility published that endpoint.
- [ ] AAAA receives the configured IPv4-only negative response. HTTPS/SVCB
  receives NOERROR/NODATA with the expected synthetic authority.
  `$NXDOMAIN_NAME` and `$SERVFAIL_NAME` retain their recorded Rcode and authority
  RRsets.
- [ ] `GET /5gpn/dns` returns one document and the revision that names it. The
  installation-owned listener, certificate, private-key, origin-listener, and
  gateway coordinates are present as one round-tripped projection and are not
  inferred from caller input.
- [ ] `$BLOCK_NAME`, `$DIRECT_NAME`, `$PROXY_NAME`, and `$FALLBACK_NAME` produce
  the expected live answers. Their wire-query log entries carry the expected
  verdict, reason, upstream, Rcode, and answer.
- [ ] `GET /5gpn/dns/resolve?name=...` agrees with the corresponding wire query
  on final verdict, reason, upstream, Rcode, and answer. Its `cacheHit` describes
  the diagnostic call itself and is not compared with an earlier query-log
  entry.
- [ ] A repeated wire query becomes a cache hit in its own newest query-log
  entry without changing the original verdict/reason/upstream metadata.
- [ ] `/5gpn/dns/stats` counters advance consistently with the observed
  requests, and the subscription projection reports rule ID, attempt/success
  times, entry count, and last error without exposing cached list contents or
  its private source fence.

Policy reordering, China/trust timing, member fallback, cache-generation races,
and subscription failure injection require the disposable checklist.

## 4. Interception projection and fixed boundary

- [ ] `GET /5gpn/interception` returns non-null arrays for modules, execution
  order, available egress groups, and active capture hosts. `http3` is `false`.
- [ ] Every installed extension has a non-empty egress binding and a capture
  DNS binding of exactly `trust` or `china`. A missing live egress group leaves
  the configured name visible while runtime readiness is false.
- [ ] Active capture hosts contain only ready enabled extensions while the
  master is enabled. An armed but pending extension remains visible with its
  certificate/runtime reason and is not presented as ready.
- [ ] The live rule projection contains exactly one enabled global
  `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT` before extension routing and
  capture behavior.
- [ ] There is no loopback interception service, SOCKS return hop, extension
  sidecar, or worker pool. HTTP/TLS capture is an in-process mihomo stage.
- [ ] A bounded `GET /5gpn/interception/logs` returns a decimal-string sequence,
  a stream ID, and at most the requested capped limit. An incremental read with
  the returned cursor advances or returns an explicit reset; it never becomes
  permanently empty behind a new stream.
- [ ] If the ring contains a unique synthetic log marker, that marker is absent
  from the persistent journal. Do not generate a marker during this smoke.

If a pre-installed acceptance extension and read-only origin are available,
one ordinary H1 and one H2 GET may additionally prove that both enter the same
native action chain. The fixture action must have no network or persistent
storage side effect. Installing, enabling, or changing that extension belongs
to the disposable checklist.

## 5. Telegram projection

- [ ] `GET /5gpn/bot` returns `enabled`, `token_set`, `admins`, `alerts`,
  `state`, and a revision. It never returns the token or a Telegram request URL
  containing the token.
- [ ] When the bot is disabled, no poll loop is running and the projection says
  `stopped`. When a dedicated acceptance bot is already enabled, the projection
  says `running` or exposes a redacted reachability error.

Do not send Telegram messages, configure a token, change administrators, or
trigger alerts during this read-only run. Command authorization and alert
transitions belong to the disposable checklist.

## 6. Completion record

- [ ] Re-read the four file hashes and three runtime document revisions. They
  match the before-state exactly.
- [ ] `$MIHOMO_PID` is unchanged.
- [ ] Record the result of every checkbox and archive only redacted outputs.
