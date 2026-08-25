# 5gpn mihomo runtime acceptance

These checklists own acceptance for behavior implemented inside the
`moooyo/mihomo` process. They deliberately do not repeat installer publication,
host ownership, Certbot, profile generation, or Console interaction tests.

Use the checklists as follows:

- [runtime-smoke.md](runtime-smoke.md) is read-only. It may run on an explicitly
  designated gateway because it sends queries and authenticated reads but does
  not write a controller document, signal a process, consume worker capacity on
  purpose, or change a file.
- [runtime-disposable.md](runtime-disposable.md) changes runtime documents and
  configuration, occupies worker slots, and injects failures. It is restricted
  to a disposable Linux or Windows host that can be rebuilt after the run.

The 5gpn repository remains responsible for installed-artifact, systemd-unit,
listener-publication, certificate-publisher, filesystem, reinstall, and
cross-repository integration acceptance. The zashboard repository remains
responsible for Console rendering and interaction acceptance.

## Required evidence

Every run records all of the following before interpreting a result:

- the exact mihomo Git commit, release tag, binary version output, and binary
  SHA-256;
- the operating system, kernel, systemd version on Linux, and whether the host
  uses the required pure cgroup-v2 hierarchy;
- the raw revisions and pre-run SHA-256 values of `dns.json`, `intercept.json`,
  `bot.json`, and the operator-owned mihomo YAML;
- the exact commit or immutable image digest of every controlled DNS, HTTPS,
  interception-origin, and fault-injection fixture;
- the URL, byte length, and SHA-256 of every remotely fetched manifest, script,
  subscription, or catalog input;
- the start and end timestamps and every intentionally skipped assertion with a
  reason.

A branch name, moving tag, unqualified container tag, or mutable download URL is
not an acceptance input. A run stops before mutation when any fetched byte
stream differs from its recorded SHA-256.

Synthetic capacity and failure fixtures should be served from an acceptance
origin controlled by the runner. Their source commit and every served-object
digest must be recorded in the run evidence; they must not be fetched from a
development branch.

## Ownership boundary

The runtime checklists cover:

- DNS policy order, China/trust arbitration, ordered upstream-member fallback,
  cache generation, subscriptions, and runtime diagnostics;
- mandatory one-shot worker isolation, memory and process bounds, non-queuing
  admission, and operation-local failure;
- native HTTP/H1/H2 interception, the UDP/443 boundary, immutable extension
  snapshots, routing and egress bindings, certificate readiness projection,
  and the in-memory engine log stream;
- the read-only Telegram command and alert plane, including credential
  redaction and loop lifecycle;
- the authenticated controller, managed controller immutability, and complete
  runtime config apply behavior.

The checklists do not validate the visual Console, installation TUI, release
resolver, host firewall, root certificate helper, Certbot transaction, or iOS
profile contents.
