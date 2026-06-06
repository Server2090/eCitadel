#!/usr/bin/env bash
# =============================================================================
#  anomaly_lab.sh  -  eCitadel Team 76  -  safe practice range for anomaly_guard.py
# =============================================================================
#  Lets you WATCH the anomaly sensor fire before competition day, using only
#  local loopback traffic - nothing leaves the box, no other host is touched,
#  no prohibited tools are used.
#
#  It will:
#    1. start a multi-port listener on 127.0.0.1 (so there are "our" ports),
#    2. capture a short IDLE baseline,
#    3. launch a local "scanner" that hammers all those ports (a port scan),
#    4. run  anomaly_guard.py --once --demo  so you see the scan get flagged,
#    5. run the DNS exfil/DGA detector on a crafted resolver log,
#    6. clean everything up.
#
#  --demo turns OFF the allow-list so loopback test traffic CAN be flagged.
#  NEVER run anomaly_guard.py with --demo in the real event - it would let the
#  scorer's ranges be flagged. This harness only uses it against 127.0.0.1.
#
#  USAGE:  bash scripts/anomaly_lab.sh         (override with NPORTS=, BASE_PORT=)
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${SCRIPT_DIR}/anomaly_guard.py"
BASE_PORT="${BASE_PORT:-9001}"
NPORTS="${NPORTS:-25}"          # >=15 distinct ports => trips the port-scan rule
TMP="$(mktemp -d)"
LISTENER_PID=""; SCANNER_PID=""

cleanup() {
  [ -n "${LISTENER_PID}" ] && kill "${LISTENER_PID}" 2>/dev/null
  [ -n "${SCANNER_PID}" ]  && kill "${SCANNER_PID}"  2>/dev/null
  rm -rf "${TMP}"
}
trap cleanup EXIT

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
[ -f "${GUARD}" ] || { echo "cannot find anomaly_guard.py next to this script"; exit 1; }

echo "[lab] All traffic is local to 127.0.0.1 ports ${BASE_PORT}..$((BASE_PORT+NPORTS-1)). Nothing leaves the box."

# --- the listener: bind N ports and keep every accepted connection open ------
cat > "${TMP}/listener.py" <<'PY'
import socket, sys, select
base, n = int(sys.argv[1]), int(sys.argv[2])
socks = []
for p in range(base, base + n):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", p)); s.listen(16); socks.append(s)
    except OSError:
        pass
conns = []
while True:
    r, _, _ = select.select(socks, [], [], 1.0)
    for s in r:
        try:
            c, _ = s.accept(); conns.append(c)   # hold it open so it shows in ss
        except OSError:
            pass
PY

# --- the scanner: open a connection to every port and hold them open ---------
cat > "${TMP}/scanner.py" <<'PY'
import socket, sys, time
base, n = int(sys.argv[1]), int(sys.argv[2])
held = []
for p in range(base, base + n):
    try:
        c = socket.socket(); c.settimeout(1); c.connect(("127.0.0.1", p)); held.append(c)
    except OSError:
        pass
time.sleep(3600)
PY

# 1) listener
setsid python3 "${TMP}/listener.py" "${BASE_PORT}" "${NPORTS}" </dev/null >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 2
echo "[lab] listener up on ${NPORTS} ports (pid ${LISTENER_PID})"

# 2) idle baseline (no scan running yet -> 'normal' = quiet)
python3 "${GUARD}" --learn --minutes 0.1 --sample 2 --out "${TMP}/base.json" >/dev/null 2>&1
echo "[lab] captured a short idle baseline"

# 3) scanner
setsid python3 "${TMP}/scanner.py" "${BASE_PORT}" "${NPORTS}" </dev/null >/dev/null 2>&1 &
SCANNER_PID=$!
sleep 2
echo "[lab] scanner running (pid ${SCANNER_PID}) - 127.0.0.1 is now touching ${NPORTS} ports"

# 4) score it - demo mode so loopback is not allow-listed away
echo
echo "================= anomaly_guard.py --once --demo (connection scan) ================="
python3 "${GUARD}" --once --demo --baseline "${TMP}/base.json" --interval 2
echo "(expected: an ANOMALY line for 127.0.0.1 with a 'port-scan' reason + a RECOMMEND line)"

# 5) DNS detector demo on a crafted resolver log
echo
echo "================= anomaly_guard.py --dns (DNS exfil / DGA) ========================="
python3 - > "${TMP}/dns.log" <<'PY'
import random; random.seed(11)
A = "abcdefghijklmnopqrstuvwxyz0123456789"
r = lambda n: "".join(random.choice(A) for _ in range(n))
L = []
for d in ["www.google.com", "api.github.com", "update.fedoraproject.org"]:
    for _ in range(8):
        L.append(f"query[A] {d} from 127.0.0.1")          # normal, low entropy
for _ in range(30):
    L.append(f"query[A] {r(22)}.tun.exfil-demo.io from 127.0.0.1")   # tunneling
print("\n".join(L))
PY
python3 "${GUARD}" --dns --dns-source log --dns-file "${TMP}/dns.log"
echo "(expected: a HIGH 'DNS tunneling/exfil under exfil-demo.io' finding; google/github spared)"

echo
echo "[lab] done - listener + scanner cleaned up. Re-run any time; tune with NPORTS=40 bash $0"
