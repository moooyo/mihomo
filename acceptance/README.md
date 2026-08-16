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

## Pinned external extension fixture

The optional Apple WLOC path uses the following immutable inputs. Verify the
bytes before exposing the manifest URL to the importer. The manifest's own
source URLs already name the exact upstream commit, and the two script digests
below make that dependency independently auditable.

| Resource | Immutable source | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Apple WLOC manifest | `https://raw.githubusercontent.com/moooyo/5gpn-extensions/e5c550c46e819a06e078751ee9a245dda07bcbe7/apple-wloc/extension.yaml` | 3952 | `facffe31b49539a0628379607cdf1b81306f45d2ff81a5586102fa31468055f7` |
| WLOC response script | `https://raw.githubusercontent.com/Yu9191/wloc/782e9c5cadf215263d9d168314113e47baaa302c/dist/wloc.js` | 41180 | `a1b361e60f0b434585260fb59c65d1ddbe3bff89ace3639f592e7d8af432b3c1` |
| WLOC settings script | `https://raw.githubusercontent.com/Yu9191/wloc/782e9c5cadf215263d9d168314113e47baaa302c/dist/wloc-settings.js` | 13101 | `433073eed20064ee59cafc857eb444e0bcc958290323ac7586a77093776d8f42` |

Record the importer-returned immutable snapshot digest as additional run
evidence. The manifest digest alone does not cover separately fetched script
bytes.

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
