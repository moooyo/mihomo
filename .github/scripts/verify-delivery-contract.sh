#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'delivery contract: %s\n' "$*" >&2
  exit 1
}

module_floor="$(awk '$1 == "go" { print $2; exit }' go.mod)"
[[ "$module_floor" == "1.25.0" ]] \
  || fail "go.mod must declare Go 1.25.0, got ${module_floor:-missing}"

build_workflow=".github/workflows/build.yml"
test_workflow=".github/workflows/test.yml"

grep -Fq 'DELIVERY_BRANCH: feat/5gpn-monolith' "$build_workflow" \
  || fail "build workflow is not bound to the delivery branch"
grep -Fq -- '- feat/5gpn-monolith' "$test_workflow" \
  || fail "test workflow does not gate the delivery branch"
grep -Fq 'go-version: "1.25"' "$test_workflow" \
  || fail "test workflow does not exercise the module floor"
grep -Fq 'GO_VERSION: "1.26"' "$build_workflow" \
  || fail "build workflow does not pin the release toolchain"
if grep -Eq '^  (push|pull_request):' "$build_workflow"; then
  fail "release artifact workflow must be manual-only"
fi
grep -Fq "github.event.inputs.version || github.ref" "$build_workflow" \
  || fail "release concurrency is not isolated by version"
grep -Fq "if: \${{ github.event_name == 'workflow_dispatch' }}" "$build_workflow" \
  || fail "production artifact matrix is not dispatch-only"

if grep -Eq 'goos: (android|darwin|freebsd)' "$build_workflow"; then
  fail "build workflow publishes a platform without production worker isolation"
fi
if grep -Eq 'go-version: .*1\.(20|21|22|23|24)(\.|"|$)' \
  "$build_workflow" "$test_workflow"; then
  fail "workflow still uses a Go version below the module floor"
fi
if grep -Eq '^  Docker:' "$build_workflow"; then
  fail "workflow still publishes unsupported container images"
fi
if grep -Eq 'uses: [^ ]+@(main|v[0-9])' "$build_workflow" "$test_workflow"; then
  fail "workflow action is not pinned to a full commit SHA"
fi
if grep -Eq '^  Upload-Prerelease:' "$build_workflow"; then
  fail "workflow still moves a rolling prerelease tag"
fi
grep -Fq -- '--latest=false' "$build_workflow" \
  || fail "publish job does not opt out of implicit latest selection"
grep -Fq 'Reconcile-Latest:' "$build_workflow" \
  || fail "workflow does not reconcile latest after publication"
grep -Fq 'group: mihomo-monolith-reconcile-latest' "$build_workflow" \
  || fail "latest reconciliation does not use its fixed concurrency group"
grep -Fq 'git cat-file -t "refs/tags/${CURRENT_VERSION}"' "$build_workflow" \
  || fail "release resume does not require an annotated tag"
grep -Fq 'grep -vxF "${CURRENT_VERSION}"' "$build_workflow" \
  || fail "monotonic version check does not exclude a resumable current tag"
if grep -Eq 'Package (DEB|RPM|Pacman)' "$build_workflow"; then
  fail "workflow still publishes packages without the 5gpn systemd boundary"
fi
if grep -Eq '(^|[[:space:]])(android|darwin|freebsd)-' Makefile; then
  fail "Makefile still includes unsupported production targets"
fi

grep -Fq 'goos: linux, goarch: amd64, goamd64: v1, output: amd64-compatible' \
  "$build_workflow" \
  || fail "installer-consumed linux-amd64-compatible artifact is missing"

printf 'delivery contract: ok\n'
