#!/usr/bin/env python3
# =============================================================================
#  anomaly_guard.py  -  eCitadel Team 76  -  behavioral / ML network anomaly sensor
# =============================================================================
#  WHAT IT IS
#    A small "AI/ML firewall" sensor. It learns what NORMAL connection behavior
#    looks like on a box, then flags peers (IPs) that behave abnormally -
#    port scans, SYN floods, connection storms, and (for outbound) steady C2
#    "beaconing". If scikit-learn is installed it uses an IsolationForest
#    (unsupervised anomaly detection); if not, it falls back to a pure-Python
#    robust-statistics detector (median/MAD z-scores) plus hard rules. Either way
#    it needs no internet at run time once a baseline is captured.
#
#  WHY IT ONLY *RECOMMENDS* FOR INBOUND (read this - it matters)
#    The scoring engine ROTATES its IP and lives in the SAME SUBNET as the Red
#    Team. An automatic blocker that bans "anomalous" INBOUND traffic will sooner
#    or later ban the scorer and cost you service points. So for inbound this tool
#    ALERTS and prints a suggested single-IP block for YOU to confirm - it never
#    auto-blocks inbound. For OUTBOUND (C2/exfil) a false positive cannot hurt the
#    inbound scoring check, so you may opt into --auto-block-egress.
#    It also NEVER flags/blocks an allow-listed range (loopback, your internal
#    172.21/16-ish space, and the scored-NAT 172.27.x via 172.16/12), so the
#    scorer is protected by construction.
#
#  IT DOES NOT REPLACE the rest of the kit. Persistence removal (hunt_malware.sh)
#  and egress-lockdown (defend_redteam.sh) are still your primary levers. This is
#  an extra sensor that turns "weird traffic" into a concrete, confirmable action.
#
#  USAGE
#    # 1) LEARN normal behavior for a few minutes (do this once the box is clean):
#    sudo python3 anomaly_guard.py --learn --minutes 10 --out baseline.json
#
#    # 2) WATCH continuously, alert on anomalies (recommend-only by default):
#    sudo python3 anomaly_guard.py --watch --baseline baseline.json
#
#    # optional: also AUTO-BLOCK outbound anomalies (safe for scoring):
#    sudo python3 anomaly_guard.py --watch --baseline baseline.json --auto-block-egress
#
#    # one snapshot (good for cron / quick check):
#    sudo python3 anomaly_guard.py --once --baseline baseline.json
#
#    # prove the detector works on synthetic data (no traffic needed):
#    python3 anomaly_guard.py --selftest
#
#  Add ranges that must never be flagged with --allow 203.0.113.0/24 (repeatable).
#  Force the no-dependency detector with --no-sklearn.
# =============================================================================

import argparse, ipaddress, json, math, os, statistics, subprocess, sys, time
from collections import defaultdict, deque
from datetime import datetime

# --- optional ML backend -----------------------------------------------------
# We try scikit-learn. If it is not installed (e.g. you already locked egress and
# can't pip-install), we transparently use the built-in statistical detector.
SKLEARN = False
try:
    if os.environ.get("ANOMALY_NO_SKLEARN") != "1":
        from sklearn.ensemble import IsolationForest  # noqa
        import numpy as np  # noqa
        SKLEARN = True
except Exception:
    SKLEARN = False

# --- ranges we will NEVER flag or block (protects the scorer + your own boxes) -
# 172.16.0.0/12 covers BOTH your internal 172.21.x and the scored-NAT 172.27.x,
# so the rotating scoring engine can never be flagged by this tool.
DEFAULT_ALLOW = [
    "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "169.254.0.0/16", "fe80::/10",
]

# Hard rules that flag obviously-malicious behavior regardless of the model.
RULE_SCAN_PORTS = 15     # one peer touching >=15 distinct local ports = scan
RULE_HALF_OPEN  = 10     # >=10 half-open (SYN_SENT/RECV) = scan/flood
RULE_CONN_FLOOD = 200    # >=200 concurrent connections from one peer = flood

# Beacon (C2) heuristic for OUTBOUND peers seen across many watch windows.
BEACON_MIN_WINDOWS = 6   # must appear in at least this many recent windows
BEACON_CV_MAX      = 0.25  # low coefficient-of-variation of intervals = regular = beacon

FEATURES = ["conns", "distinct_local_ports", "distinct_peer_ports", "half_open"]

# --- DNS exfil / DGA detection tunables --------------------------------------
# Parent domains we never flag (your zone + reverse-DNS + localhost).
DNS_ALLOW_DOMAINS = {
    "rrintel.internal", "in-addr.arpa", "ip6.arpa", "arpa",
    "localhost", "localdomain",
}
DNS_TUNNEL_MIN_SUBS = 20    # many unique subdomains under ONE parent = tunneling
DNS_TUNNEL_ENTROPY  = 3.5   # mean entropy of the encoded label for tunneling
DNS_DGA_ENTROPY     = 4.0   # high mean single-label entropy = DGA-like
DNS_DGA_MIN_NAMES   = 5
DNS_SINGLE_ENTROPY  = 4.2   # one-off very-random long label = exfil chunk
DNS_SINGLE_LEN      = 30


# =============================================================================
# Data collection
# =============================================================================
def listening_ports():
    """Local TCP/UDP ports we LISTEN on - a peer hitting these is 'inbound'."""
    ports = set()
    for proto in ("-tln", "-uln"):
        try:
            out = subprocess.run(["ss", proto, "-H"], capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            # local address is the 4th field for -t, but layout varies; grab the
            # field that looks like ADDR:PORT and take the trailing :PORT.
            for f in parts:
                if ":" in f and f.rsplit(":", 1)[-1].isdigit():
                    ports.add(int(f.rsplit(":", 1)[-1]))
                    break
    return ports


def snapshot(listen):
    """
    One read of the connection table via `ss -tan`. Returns per-peer features:
       peer_ip -> dict(conns, distinct_local_ports, distinct_peer_ports,
                       half_open, direction)
    direction is 'in' (peer connected to a port we listen on) or 'out'.
    """
    try:
        out = subprocess.run(["ss", "-tan", "-H"], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        print(f"[!] could not run ss: {e}", file=sys.stderr)
        return {}

    agg = defaultdict(lambda: {"conns": 0, "lp": set(), "pp": set(),
                               "half_open": 0, "in": 0, "out": 0})
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        if state == "LISTEN":
            continue
        local, peer = parts[3], parts[4]
        try:
            lip, lport = _split_hostport(local)
            pip, pport = _split_hostport(peer)
        except Exception:
            continue
        if pip in ("*", "", "0.0.0.0", "::"):
            continue
        a = agg[pip]
        a["conns"] += 1
        a["lp"].add(lport)
        a["pp"].add(pport)
        if state in ("SYN-SENT", "SYN-RECV"):
            a["half_open"] += 1
        if lport in listen:
            a["in"] += 1
        else:
            a["out"] += 1

    feats = {}
    for ip, a in agg.items():
        feats[ip] = {
            "conns": a["conns"],
            "distinct_local_ports": len(a["lp"]),
            "distinct_peer_ports": len(a["pp"]),
            "half_open": a["half_open"],
            "direction": "in" if a["in"] >= a["out"] else "out",
        }
    return feats


def _split_hostport(s):
    """Split ADDR:PORT, handling IPv6 [::1]:22 and trailing %iface."""
    s = s.strip()
    if s.startswith("["):                      # [ipv6]:port
        host, port = s[1:].split("]:")
    else:
        host, port = s.rsplit(":", 1)
    host = host.split("%")[0]
    return host, int(port)


# =============================================================================
# Allow-list
# =============================================================================
class AllowList:
    def __init__(self, cidrs):
        self.nets = []
        for c in cidrs:
            try:
                self.nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    def covers(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)


# =============================================================================
# Detectors
# =============================================================================
class IForestDetector:
    """Unsupervised anomaly detection with scikit-learn IsolationForest.

    We standardize features first (z = (x-mean)/std). Without scaling, the
    feature with the largest numeric range (e.g. 'conns', which can reach the
    hundreds) dominates the tree splits and drowns out 'half_open'/'ports'.
    We also pin contamination low (2%) so points at the edge of normal are not
    misread as attacks - in this competition a false positive on inbound is
    expensive, so we bias toward precision.
    """
    def __init__(self, matrix):
        arr = np.array(matrix, dtype=float)
        self.mean = arr.mean(axis=0)
        self.std = arr.std(axis=0)
        self.std[self.std == 0] = 1.0          # avoid divide-by-zero on flat features
        self.model = IsolationForest(n_estimators=200, contamination=0.02,
                                     random_state=42)
        self.model.fit((arr - self.mean) / self.std)

    def score(self, vec):
        # returns (is_anomaly, score) where higher score = more anomalous
        x = (np.array([vec], dtype=float) - self.mean) / self.std
        pred = self.model.predict(x)[0]            # -1 anomaly, 1 normal
        s = -float(self.model.score_samples(x)[0])  # flip so bigger = weirder
        return pred == -1, s


class StatDetector:
    """
    No-dependency fallback. Robust per-feature outlier test using the median and
    MAD (median absolute deviation). A peer is anomalous if ANY feature's robust
    z-score exceeds the threshold. This is the same idea as IsolationForest for
    simple feature distributions, just lighter and fully explainable.
    """
    def __init__(self, matrix, z=3.5):
        self.z = z
        cols = list(zip(*matrix)) if matrix else [[] for _ in FEATURES]
        self.med, self.mad = [], []
        for col in cols:
            col = list(col)
            m = statistics.median(col) if col else 0.0
            devs = [abs(x - m) for x in col]
            mad = statistics.median(devs) if devs else 0.0
            self.med.append(m)
            self.mad.append(mad)

    def score(self, vec):
        worst = 0.0
        for i, x in enumerate(vec):
            mad = self.mad[i]
            if mad == 0:
                # no spread in training: treat any positive value above median as
                # mildly suspicious, scaled, but don't divide by zero.
                rz = 0.0 if x <= self.med[i] else (x - self.med[i])
            else:
                rz = 0.6745 * (x - self.med[i]) / mad
            worst = max(worst, rz)
        return worst >= self.z, worst


def rule_hits(f):
    """Model-independent 'obvious attack' rules. Returns a list of reasons."""
    r = []
    if f["distinct_local_ports"] >= RULE_SCAN_PORTS:
        r.append(f"port-scan ({f['distinct_local_ports']} local ports)")
    if f["half_open"] >= RULE_HALF_OPEN:
        r.append(f"half-open flood ({f['half_open']} SYN)")
    if f["conns"] >= RULE_CONN_FLOOD:
        r.append(f"connection flood ({f['conns']} conns)")
    return r


def build_detector(matrix, force_stat=False):
    if SKLEARN and not force_stat and len(matrix) >= 8:
        return IForestDetector(matrix), "IsolationForest (scikit-learn)"
    return StatDetector(matrix), "robust-stats (median/MAD, no deps)"


def vec_of(f):
    return [f[k] for k in FEATURES]


# =============================================================================
# DNS exfil / DGA detection
# =============================================================================
import re as _re

def shannon_entropy(s):
    """Bits-per-character entropy. Random/encoded labels score high (~3.8-5);
    dictionary-ish labels score low (~2.5-3.5)."""
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _dns_parent(name):
    labels = name.strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _dns_leftmost(name):
    labels = name.strip(".").split(".")
    return labels[0] if labels else name


_DNS_RE = _re.compile(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}")

def collect_dns_from_lines(lines):
    """Extract (query_name, is_nxdomain) from arbitrary resolver log lines
    (dnsmasq / bind / unbound / systemd-resolved). Best-effort, format-agnostic:
    the longest domain-looking token on a line is almost always the query name."""
    recs = []
    for ln in lines:
        toks = _DNS_RE.findall(ln)
        if not toks:
            continue
        name = max(toks, key=len).lower().rstrip(".")
        recs.append((name, "nxdomain" in ln.lower()))
    return recs


def collect_dns(args):
    src = args.dns_source
    if src == "stdin":
        return collect_dns_from_lines(sys.stdin.read().splitlines())
    if src == "log":
        if not args.dns_file:
            print("[!] --dns-source log needs --dns-file <path>", file=sys.stderr); return []
        try:
            with open(args.dns_file, errors="replace") as fh:
                return collect_dns_from_lines(fh.read().splitlines())
        except Exception as e:
            print(f"[!] cannot read {args.dns_file}: {e}", file=sys.stderr); return []
    if src == "journal":
        # Pull recent DNS-resolver logs from journald (whatever resolver is in use).
        try:
            out = subprocess.run(
                ["journalctl", "--no-pager", "-S", "-1h",
                 "-u", "dnsmasq", "-u", "systemd-resolved", "-u", "unbound", "-u", "named"],
                capture_output=True, text=True, timeout=30).stdout
            return collect_dns_from_lines(out.splitlines())
        except Exception as e:
            print(f"[!] journalctl failed: {e}", file=sys.stderr); return []
    return []


def score_dns(records, allow_domains):
    """records: list of (name, is_nx). Returns a list of finding strings.

    The strongest exfil signal is MANY unique high-entropy subdomains under ONE
    parent domain (data encoded into the left-hand labels). DGA shows as several
    random-looking names and/or a high NXDOMAIN rate.
    """
    per = defaultdict(lambda: {"names": set(), "ent": [], "nx": 0, "maxlen": 0})
    findings = []
    for name, nx in records:
        parent = _dns_parent(name)
        if parent in allow_domains or name in allow_domains:
            continue
        d = per[parent]
        if name not in d["names"]:
            d["names"].add(name)
            left = _dns_leftmost(name)
            e = shannon_entropy(left)
            d["ent"].append(e)
            d["maxlen"] = max(d["maxlen"], len(left))
            if e >= DNS_SINGLE_ENTROPY and len(left) >= DNS_SINGLE_LEN:
                findings.append(f"[HIGH] DNS one-off high-entropy label (exfil chunk?): {name} "
                                f"(entropy {e:.2f}, len {len(left)})")
        if nx:
            d["nx"] += 1
    for parent, d in per.items():
        if not d["ent"]:
            continue
        n = len(d["names"])
        mean_e = sum(d["ent"]) / len(d["ent"])
        if n >= DNS_TUNNEL_MIN_SUBS and mean_e >= DNS_TUNNEL_ENTROPY:
            findings.append(f"[HIGH] DNS tunneling/exfil under '{parent}': {n} unique high-entropy "
                            f"subdomains (mean entropy {mean_e:.2f}, longest label {d['maxlen']})")
        elif mean_e >= DNS_DGA_ENTROPY and n >= DNS_DGA_MIN_NAMES:
            findings.append(f"[HIGH] DGA-like domain '{parent}': {n} random-looking names "
                            f"(mean entropy {mean_e:.2f})")
        elif d["nx"] >= 10 and n >= 10 and (d["nx"] / n) >= 0.5:
            findings.append(f"[MED] Possible DGA '{parent}': high NXDOMAIN ({d['nx']}) across {n} names")
    return findings


# =============================================================================
# Modes
# =============================================================================
def do_learn(args, allow):
    listen = listening_ports()
    rows, seen = [], set()
    end = time.time() + args.minutes * 60
    print(f"[i] Learning normal behavior for {args.minutes} min "
          f"(sampling every {args.sample}s). Keep the box in a normal state.")
    while time.time() < end:
        for ip, f in snapshot(listen).items():
            if allow.covers(ip):      # learn from everyone, but note allow-listed
                seen.add(ip)
            rows.append(vec_of(f))
        time.sleep(args.sample)
    base = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "features": FEATURES, "matrix": rows,
        "listen_ports": sorted(listen),
        "samples": len(rows),
    }
    with open(args.out, "w") as fh:
        json.dump(base, fh)
    print(f"[✓] Captured {len(rows)} samples -> {args.out}")
    print(f"    Now run:  sudo python3 {sys.argv[0]} --watch --baseline {args.out}")


def load_baseline(path):
    with open(path) as fh:
        return json.load(fh)


def do_watch(args, allow, once=False):
    base = load_baseline(args.baseline)
    matrix = base.get("matrix", [])
    det, name = build_detector(matrix, force_stat=args.no_sklearn)
    listen = set(base.get("listen_ports", [])) or listening_ports()
    print(f"[i] Detector: {name}   |  baseline samples: {len(matrix)}")
    print(f"[i] Inbound anomalies are RECOMMEND-ONLY (the scorer rotates IPs). "
          f"Egress auto-block: {'ON' if args.auto_block_egress else 'off'}")
    report = _report_path()
    history = defaultdict(lambda: deque(maxlen=20))   # peer -> recent timestamps (outbound)

    while True:
        now = time.time()
        stamp = datetime.now().strftime("%H:%M:%S")
        feats = snapshot(listen)
        for ip, f in feats.items():
            if allow.covers(ip):
                continue                       # never flag the scorer / internal
            reasons = rule_hits(f)
            is_anom, score = det.score(vec_of(f))
            if is_anom and not reasons:
                reasons.append(f"model outlier (score {score:.2f})")

            # outbound beacon detection (timing regularity across windows)
            if f["direction"] == "out":
                history[ip].append(now)
                b = _beacon_check(history[ip])
                if b:
                    reasons.append(b)

            if not reasons:
                continue

            direction = f["direction"]
            line = (f"[{stamp}] ANOMALY {ip} ({'inbound' if direction=='in' else 'outbound'}) "
                    f"conns={f['conns']} lports={f['distinct_local_ports']} "
                    f"half_open={f['half_open']} :: {', '.join(reasons)}")
            print(line)
            _append(report, line)

            if direction == "in":
                # NEVER auto-block inbound. Recommend, with the exact command.
                print(f"    -> RECOMMEND (confirm this is NOT the scorer first): "
                      f"sudo ./defend_redteam.sh block {ip}")
                _append(report, f"    RECOMMEND: defend_redteam.sh block {ip} (confirm not scorer)")
            else:
                if args.auto_block_egress:
                    _egress_block(ip, report)
                else:
                    print(f"    -> RECOMMEND egress block: "
                          f"sudo ./defend_redteam.sh block {ip}   (or egress-lockdown)")
                    _append(report, f"    RECOMMEND egress: defend_redteam.sh block {ip}")
        if once:
            break
        time.sleep(args.interval)


def _beacon_check(times):
    """Low-variance inter-arrival across enough windows = likely C2 beacon."""
    if len(times) < BEACON_MIN_WINDOWS:
        return None
    gaps = [t2 - t1 for t1, t2 in zip(times, list(times)[1:])]
    if len(gaps) < 3:
        return None
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return None
    sd = statistics.pstdev(gaps)
    cv = sd / mean
    if cv <= BEACON_CV_MAX:
        return f"steady beacon (~{mean:.0f}s interval, cv {cv:.2f}) - possible C2"
    return None


def _egress_block(ip, report):
    sd = os.path.dirname(os.path.abspath(__file__))
    cmd = ["bash", os.path.join(sd, "defend_redteam.sh"), "block", ip]
    print(f"    -> AUTO egress-block {ip} (safe for scoring): {' '.join(cmd)}")
    _append(report, f"    AUTO egress-block {ip}")
    try:
        subprocess.run(cmd, timeout=20)
    except Exception as e:
        print(f"    [!] block failed: {e} (run it by hand)")


def _report_path():
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"anomaly_{datetime.now():%Y%m%d_%H%M%S}.log")


def _append(path, line):
    try:
        with open(path, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def do_selftest(args):
    """Deterministic proof the detector flags an obvious scanner among normals."""
    import random
    random.seed(1)
    normal = []
    for _ in range(120):
        normal.append([random.randint(1, 4),    # conns
                       random.randint(1, 2),     # local ports
                       1,                         # peer ports
                       0])                        # half open
    det, name = build_detector(normal, force_stat=args.no_sklearn)
    print(f"[selftest] detector = {name}")

    cases = {
        "normal_peer":   ([2, 1, 1, 0],  False),
        "port_scanner":  ([60, 60, 1, 55], True),
        "syn_flooder":   ([300, 1, 1, 250], True),
        "quiet_normal":  ([1, 1, 1, 0],  False),
    }
    ok = True
    for label, (vec, want_anom) in cases.items():
        f = dict(zip(FEATURES, vec))
        got = bool(rule_hits(f)) or det.score(vec)[0]
        flag = "ANOMALY" if got else "normal"
        verdict = "PASS" if got == want_anom else "FAIL"
        if got != want_anom:
            ok = False
        print(f"  [{verdict}] {label:<13} -> {flag}")
    # ---- DNS detector checks (tunneling + DGA vs normal) ----
    import random as _r
    _r.seed(7)
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    rand = lambda n: "".join(_r.choice(alpha) for _ in range(n))
    normal = [("www.google.com", False)] * 20 + [("api.github.com", False)] * 15 + \
             [("mail.example.com", False)] * 10
    tunnel = [(f"{rand(20)}.t.evil.com", False) for _ in range(30)]   # exfil
    dga    = [(f"{rand(14)}.bad.net", True)  for _ in range(12)]      # DGA
    dfind  = " ".join(score_dns(normal + tunnel + dga, DNS_ALLOW_DOMAINS))
    dns_ok = ("evil.com" in dfind) and ("bad.net" in dfind) and ("google.com" not in dfind)
    print(f"  [{'PASS' if dns_ok else 'FAIL'}] dns_detector  -> "
          f"{'flagged evil.com + bad.net, spared google.com' if dns_ok else 'MISCLASSIFIED'}")
    ok = ok and dns_ok

    print("[selftest] RESULT:", "PASS - detector works" if ok else "FAIL")
    return 0 if ok else 1


def do_dns(args, allow_domains):
    recs = collect_dns(args)
    if not recs:
        print("[i] No DNS query names collected. Point --dns-file at a resolver query log, "
              "use --dns-source journal, or pipe names with --dns-source stdin.")
        return
    uniq = len({n for n, _ in recs})
    print(f"[i] Analyzed {len(recs)} DNS queries ({uniq} unique names).")
    findings = score_dns(recs, allow_domains)
    if not findings:
        print("[✓] No DNS exfil / DGA patterns detected.")
        return
    report = _report_path()
    for f in findings:
        print("  " + f)
        _append(report, f)
    print("\nThese are OUTBOUND indicators (your box resolving attacker domains). Treat them")
    print("like egress C2: find the process making the queries, remove its persistence, and")
    print("you may block the domain/resolver path. Record the domain(s) for your IR.")
    print(f"Report saved: {report}")


# =============================================================================
# main
# =============================================================================
def main():
    p = argparse.ArgumentParser(description="Behavioral/ML network anomaly sensor (scorer-safe).")
    m = p.add_mutually_exclusive_group(required=True)
    m.add_argument("--learn", action="store_true", help="capture a normal-behavior baseline")
    m.add_argument("--watch", action="store_true", help="continuously score live traffic")
    m.add_argument("--once", action="store_true", help="score a single snapshot vs baseline")
    m.add_argument("--dns", action="store_true", help="analyze DNS query names for exfil / DGA")
    m.add_argument("--selftest", action="store_true", help="prove the detectors on synthetic data")
    p.add_argument("--minutes", type=float, default=10, help="learn duration (default 10)")
    p.add_argument("--sample", type=float, default=5, help="learn sampling interval s (default 5)")
    p.add_argument("--interval", type=float, default=15, help="watch interval s (default 15)")
    p.add_argument("--out", default="baseline.json", help="learn output file")
    p.add_argument("--baseline", help="baseline file for --watch/--once")
    p.add_argument("--allow", action="append", default=[], help="extra CIDR never to flag (repeatable)")
    p.add_argument("--allow-domain", action="append", default=[],
                   help="extra parent domain never to flag in --dns (repeatable)")
    p.add_argument("--dns-source", choices=["log", "journal", "stdin"], default="log",
                   help="where --dns reads query names (default: log file)")
    p.add_argument("--dns-file", help="resolver query-log path for --dns-source log")
    p.add_argument("--auto-block-egress", action="store_true",
                   help="auto-block OUTBOUND anomalies (safe for scoring); inbound is never auto-blocked")
    p.add_argument("--no-sklearn", action="store_true", help="force the no-dependency detector")
    p.add_argument("--demo", action="store_true",
                   help="DEMO ONLY: disable the allow-list so loopback test traffic is flagged "
                        "(for the practice lab; never use in the real competition)")
    args = p.parse_args()

    if args.demo:
        print("=" * 70)
        print(" DEMO MODE: allow-list DISABLED so loopback/test traffic can be flagged.")
        print(" Do NOT use --demo in the real competition (it would let the scorer's")
        print(" ranges be flagged). Inbound is STILL never auto-blocked.")
        print("=" * 70)
        allow = AllowList(args.allow)            # only explicit allows; no scorer/internal defaults
        args.auto_block_egress = False
    else:
        allow = AllowList(DEFAULT_ALLOW + args.allow)

    if args.selftest:
        sys.exit(do_selftest(args))
    if args.dns:
        do_dns(args, DNS_ALLOW_DOMAINS | set(args.allow_domain)); return
    if args.learn:
        do_learn(args, allow); return
    if not args.baseline:
        p.error("--watch/--once require --baseline (capture one with --learn first)")
    do_watch(args, allow, once=args.once)


if __name__ == "__main__":
    main()
