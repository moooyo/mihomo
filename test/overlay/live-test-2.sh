#!/bin/bash
set -u
D=/tmp/overlay-test
CTL="curl -s --unix-socket $D/control.sock"
GEN="curl -s --unix-socket $D/generation.sock"
pass=0; fail=0
chk() { if echo "$3" | grep -qE "$2"; then echo "  PASS  $1"; pass=$((pass+1));
        else echo "  FAIL  $1"; echo "        want ~ $2"; echo "        got    $(echo "$3" | head -c 300)"; fail=$((fail+1)); fi; }
notin() { if echo "$3" | grep -q "$2"; then echo "  FAIL  $1 (found $2)"; fail=$((fail+1));
          else echo "  PASS  $1"; pass=$((pass+1)); fi; }

echo "== A. corrected checks from the first pass =="
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x socks5h://127.0.0.1:17801 http://www.capture.test/ 2>/dev/null)
chk "capture does not succeed" '^(000|5[0-9][0-9])$' "$code"
g=$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/proxies/GLOBAL)
notin "MODULE-INTERCEPT absent from GLOBAL" 'MODULE-INTERCEPT' "$g"
notin "MODULE-INTERCEPT absent from the reserved provider" 'MODULE-INTERCEPT' \
      "$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/providers/proxies/default)"
chk  "MODULE-INTERCEPT is still addressable by name" '"name":"MODULE-INTERCEPT"' \
      "$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/proxies/MODULE-INTERCEPT)"

echo "== B. a non-capture overlay deny is enforced =="
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x socks5h://127.0.0.1:17801 http://ads.example.test/ 2>/dev/null)
chk "overlay reject rule denies" '^(000|5[0-9][0-9])$' "$code"

echo "== C. traffic the overlay does not select still routes normally =="
grep -c 'RuntimeOverlayClient' $D/mihomo.log >/dev/null 2>&1
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -x socks5h://127.0.0.1:17801 http://example.com/ 2>/dev/null)
chk "unselected traffic is not blocked by the overlay" '^(000|2[0-9][0-9]|3[0-9][0-9])$' "$code"

echo "== D. graceful transition drains the old capability =="
cat > $D/g2.json <<'JSON'
{"schemaVersion":1,"owner":"5gpn","generationId":"g2","parentGenerationId":"g1","documentRevision":2,
 "transitionMode":"graceful",
 "processorTargets":[{"id":"intercept","name":"MODULE-INTERCEPT"}],
 "client":{"rules":[{"kind":"domain-suffix","value":"capture.test","action":"capture","processor":"intercept"}]},
 "egress":{"capabilities":[{"id":"cap-beta","group":"Proxies"}]}}
JSON
$CTL -X PUT -H 'Content-Type: application/json' --data-binary @$D/g2.json http://x/runtime-overlays/5gpn/generations/g2 >/dev/null
$CTL -X POST -H 'Content-Type: application/json' -d '{"processorId":"intercept","processInstanceId":"inst-1","generationId":"g2"}' http://x/runtime-overlays/5gpn/readiness >/dev/null
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveGeneration":"g1"}' http://x/runtime-overlays/5gpn/generations/g2/commit)
chk "g2 committed" '"activeGeneration":"g2"' "$out"
out=$($CTL http://x/runtime-overlays/5gpn)
chk "g1 is draining" '"drainingGenerations":\["g1"\]' "$out"

echo "== E. hard revoke clears the drain registry =="
cat > $D/g3.json <<'JSON'
{"schemaVersion":1,"owner":"5gpn","generationId":"g3","parentGenerationId":"g2","documentRevision":3,
 "transitionMode":"revoke",
 "processorTargets":[{"id":"intercept","name":"MODULE-INTERCEPT"}],
 "client":{"rules":[]},
 "egress":{"capabilities":[{"id":"cap-gamma","group":"Proxies"}]}}
JSON
$CTL -X PUT -H 'Content-Type: application/json' --data-binary @$D/g3.json http://x/runtime-overlays/5gpn/generations/g3 >/dev/null
$CTL -X POST -H 'Content-Type: application/json' -d '{"processorId":"intercept","processInstanceId":"inst-1","generationId":"g3"}' http://x/runtime-overlays/5gpn/readiness >/dev/null
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveGeneration":"g2"}' http://x/runtime-overlays/5gpn/generations/g3/commit)
chk "g3 committed" '"activeGeneration":"g3"' "$out"
out=$($CTL http://x/runtime-overlays/5gpn)
# g1 is still inside its own 300s drain window from the graceful g2 commit;
# what the revoke must guarantee is that g2 never entered the registry.
notin "g2 was hard-revoked rather than drained" '"g2"' "$(echo "$out" | grep -o '"drainingGenerations":\[[^]]*\]')"
chk   "g1 is still draining" '"g1"' "$(echo "$out" | grep -o '"drainingGenerations":\[[^]]*\]')"

echo "== F. lease expiry fails captures closed without changing desired state =="
sleep 17
out=$($CTL http://x/runtime-overlays/5gpn)
chk "lease expired" '"leaseState":"expired"' "$out"
chk "generation is still active" '"activeGeneration":"g3"' "$out"
chk "processor is not ready" '"processorState":"not-ready"' "$out"

echo "== G. restart recovers into quarantine =="
pkill -x mihomo-overlay ; sleep 2
nohup /tmp/mihomo-overlay -d /tmp/overlay-test -f /tmp/overlay-test/config.yaml > $D/mihomo2.log 2>&1 &
sleep 4
out=$($CTL http://x/runtime-overlays/5gpn)
chk "persisted generation reloaded" '"activeGeneration":"g3"' "$out"
chk "reloaded into quarantine"      '"processorState":"quarantined"' "$out"
chk "recovery logged"               'recovered generation g3' "$(cat $D/mihomo2.log)"
out=$($GEN http://x/runtime-overlays/5gpn/active)
chk "the generation socket agrees" '"processorState":"quarantined"' "$out"

echo "== H. a config with no anchors is refused while a generation is persisted =="
sed '/^  - RUNTIME-OVERLAY/d;/^  - IN-NAME,intercept-egress/d' $D/config.yaml > $D/noanchor.yaml
# `-t` parses without recovering the persisted generation, so it legitimately
# passes; the refusal happens at startup, where recovery has run.
out=$(timeout 15 /tmp/mihomo-overlay -d /tmp/overlay-test -f $D/noanchor.yaml 2>&1 | tail -3)
chk "anchor-free config refused at startup while a generation is persisted" 'declares no' "$out"

echo "== I. purge leaves nothing to resurrect =="
$CTL -X DELETE http://x/runtime-overlays/5gpn >/dev/null
out=$($CTL http://x/runtime-overlays/5gpn)
chk "purged" '"activeGeneration":""' "$out"
pkill -x mihomo-overlay; sleep 2
nohup /tmp/mihomo-overlay -d /tmp/overlay-test -f /tmp/overlay-test/config.yaml > $D/mihomo3.log 2>&1 &
sleep 4
out=$($CTL http://x/runtime-overlays/5gpn)
chk "still purged after restart" '"activeGeneration":""' "$out"
notin "no generation resurrected" 'recovered generation' "$(cat $D/mihomo3.log)"

echo
echo "passed=$pass failed=$fail"
