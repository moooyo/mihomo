#!/bin/bash
# Live end-to-end exercise of the runtime overlay against a running mihomo.
set -u
D=/tmp/overlay-test
CTL="curl -s --unix-socket $D/control.sock"
GEN="curl -s --unix-socket $D/generation.sock"
API="curl -s -H 'Authorization: Bearer testsecret'"
pass=0; fail=0
chk() { # chk <name> <expected-substring> <actual>
  if echo "$3" | grep -qE "$2"; then echo "  PASS  $1"; pass=$((pass+1));
  else echo "  FAIL  $1"; echo "        want ~ $2"; echo "        got    $(echo "$3" | head -c 400)"; fail=$((fail+1)); fi
}

echo "== 1. capabilities discovery =="
out=$($CTL http://x/capabilities)
chk "runtime-overlays advertised" '"runtime-overlays"' "$out"
chk "owner reported"              '"owner":"5gpn"'     "$out"

echo "== 2. readback before any generation =="
out=$($CTL http://x/runtime-overlays/5gpn)
chk "no active generation" '"activeGeneration":""' "$out"
chk "processor disabled"   '"processorState":"disabled"' "$out"

echo "== 3. wrong owner is not found =="
code=$($CTL -o /dev/null -w '%{http_code}' http://x/runtime-overlays/someone-else)
chk "404 for unknown owner" '404' "$code"

echo "== 4. stage generation g1 =="
cat > $D/g1.json <<'JSON'
{"schemaVersion":1,"owner":"5gpn","generationId":"g1","documentRevision":1,
 "transitionMode":"revoke",
 "processorTargets":[{"id":"intercept","name":"MODULE-INTERCEPT"}],
 "client":{"rules":[
   {"kind":"domain","value":"ads.example.test","action":"reject"},
   {"kind":"domain-suffix","value":"capture.test","action":"capture","processor":"intercept","ports":[{"from":80,"to":443}]}
 ]},
 "egress":{"capabilities":[{"id":"cap-alpha","group":"Proxies"}]}}
JSON
out=$($CTL -X PUT -H 'Content-Type: application/json' --data-binary @$D/g1.json http://x/runtime-overlays/5gpn/generations/g1)
chk "staged"          '"generationId":"g1"' "$out"
chk "2 client rules"  '"clientRules":2'     "$out"

echo "== 5. a staged generation is not live =="
out=$($CTL http://x/runtime-overlays/5gpn)
chk "still no active generation" '"activeGeneration":""' "$out"
chk "listed as prepared"         '"preparedGenerations":\["g1"\]' "$out"

echo "== 6. CAS conflict on a wrong expected-active =="
out=$($CTL -X POST -H 'Content-Type: application/json' -d '{"expectedActiveGeneration":"g0"}' http://x/runtime-overlays/5gpn/generations/g1/commit)
chk "cas_conflict" '"code":"cas_conflict"' "$out"

echo "== 7. commit g1 =="
out=$($CTL -X POST http://x/runtime-overlays/5gpn/generations/g1/commit)
chk "committed" '"activeGeneration":"g1"' "$out"

echo "== 8. quarantined until the processor attests readiness =="
out=$($CTL http://x/runtime-overlays/5gpn)
chk "quarantined" '"processorState":"quarantined"' "$out"

echo "== 9. capture fails closed while quarantined =="
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x socks5h://127.0.0.1:17801 http://www.capture.test/ 2>/dev/null)
chk "capture refused (no 200)" '^(000|5..)$' "$code"

echo "== 10. processor registers readiness =="
out=$($CTL -X POST -H 'Content-Type: application/json' \
  -d '{"processorId":"intercept","processInstanceId":"inst-1","generationId":"g1"}' \
  http://x/runtime-overlays/5gpn/readiness)
chk "lease issued" '"leaseId"' "$out"
out=$($CTL http://x/runtime-overlays/5gpn)
chk "now ready" '"processorState":"ready"' "$out"

echo "== 11. the read-only generation socket =="
out=$($GEN http://x/runtime-overlays/5gpn/active)
chk "active generation" '"activeGeneration":"g1"' "$out"
chk "boot epoch carried" '"bootEpoch"' "$out"
chk "fencing token carried" '"fencingToken"' "$out"
code=$($GEN -o /dev/null -w '%{http_code}' -X POST http://x/runtime-overlays/5gpn/active)
chk "POST refused on the read-only socket" '40[45]' "$code"
code=$($GEN -o /dev/null -w '%{http_code}' http://x/capabilities)
chk "control paths absent from the read socket" '404' "$code"

echo "== 12. idempotent repeat commit =="
out=$($CTL -X POST http://x/runtime-overlays/5gpn/generations/g1/commit)
chk "repeated" '"repeated":true' "$out"

echo "== 13. abort refuses an active generation =="
out=$($CTL -X POST http://x/runtime-overlays/5gpn/generations/g1/abort)
chk "wrong_state" '"code":"wrong_state"' "$out"

echo "== 14. processor target is excluded from groups =="
notin() { if echo "$3" | grep -q "$2"; then echo "  FAIL  $1 (found $2)"; fail=$((fail+1)); else echo "  PASS  $1"; pass=$((pass+1)); fi; }
notin "MODULE-INTERCEPT absent from GLOBAL" 'MODULE-INTERCEPT'   "$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/proxies/GLOBAL)"
notin "MODULE-INTERCEPT absent from the include-all group" 'MODULE-INTERCEPT'   "$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/proxies/EverythingElse)"

echo "== 15. the anchors cannot be disabled =="
out=$(curl -s -H 'Authorization: Bearer testsecret' -X PATCH -d '{"1":true}' http://127.0.0.1:19090/rules/disable)
chk "anchor protected" 'anchor' "$out"
out=$(curl -s -H 'Authorization: Bearer testsecret' -X PATCH -d '{"2":true}' http://127.0.0.1:19090/rules/disable)
chk "terminator protected" 'protected system guard' "$out"

echo "== 16. mode cannot be changed while a generation is active =="
out=$(curl -s -H 'Authorization: Bearer testsecret' -X PATCH -d '{"mode":"global"}' http://127.0.0.1:19090/configs)
chk "mode change refused" 'cannot switch to' "$out"
out=$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/configs)
chk "mode is unchanged" '"mode":"rule"' "$out"

echo "== 17. a mixed payload leaves nothing mutated =="
before=$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/configs | grep -o '"allow-lan":[a-z]*')
curl -s -H 'Authorization: Bearer testsecret' -X PATCH -d '{"allow-lan":true,"mode":"direct"}' http://127.0.0.1:19090/configs >/dev/null
after=$(curl -s -H 'Authorization: Bearer testsecret' http://127.0.0.1:19090/configs | grep -o '"allow-lan":[a-z]*')
chk "allow-lan not applied from a rejected payload" "$before" "$after"

echo "== 18. sniffing cannot be disabled while a generation is active =="
out=$(curl -s -H 'Authorization: Bearer testsecret' -X PATCH -d '{"sniffing":false}' http://127.0.0.1:19090/configs)
chk "sniffing change refused" 'cannot disable sniffing' "$out"

echo "== 19. unauthenticated SOCKS UDP is dropped =="
python3 - <<'PY' 2>&1 | tail -1
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
pkt = b'\x00\x00\x00\x01' + socket.inet_aton('1.1.1.1') + struct.pack('!H', 53) + b'\x00'*12
s.sendto(pkt, ('127.0.0.1', 17802))
try:
    s.recvfrom(512); print("  FAIL  unassociated datagram was answered")
except socket.timeout:
    print("  PASS  unassociated datagram dropped")
PY

echo
echo "passed=$pass failed=$fail"
