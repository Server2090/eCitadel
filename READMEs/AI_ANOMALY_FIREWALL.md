# AI / ML anomaly "firewall" — `anomaly_guard.py`

**Team 76 · RR Intel / eCitadel Season IV**

You asked whether you can build a firewall that *adapts* and blocks **suspicious, not‑normal
behavior** with AI/ML. Yes — and `scripts/anomaly_guard.py` is a working, tested version.
This README explains exactly what it does, the machine learning under the hood, and — most
importantly — **how to use it without shooting yourself in the foot in this competition.**

---

## The one thing you must understand first

In eCitadel, the **scoring engine rotates its IP and lives in the same subnet as the Red
Team.** That single fact breaks the naïve "ML firewall that auto‑blocks anomalies" idea:

> If a model auto‑blocks *inbound* traffic it judges "abnormal," it will eventually block
> the **scorer**, and you lose service points (and possibly get penalized for disrupting
> scoring).

So this tool is built the only way that's safe here:

- **Inbound anomalies → ALERT + RECOMMEND.** It prints the exact
  `defend_redteam.sh block <ip>` command for **you** to run *after confirming the IP isn't
  the scorer*. It never auto‑blocks inbound.
- **Outbound anomalies → optional AUTO‑BLOCK.** C2/exfil goes *out*; a false positive there
  can't hurt the inbound scoring check, so `--auto-block-egress` is offered.
- **Allow‑list by construction.** It will **never** flag or block loopback, your internal
  `172.21.x`, or the scored‑NAT `172.27.x` (covered by `172.16.0.0/12`), so the rotating
  scorer is protected no matter how its traffic looks. *(Verified: a port‑scan coming from
  the scored subnet is skipped before it's ever scored.)*

This is "human‑in‑the‑loop ML": the model does the watching and the triage; you make the
block decision on inbound. That's the right division of labor when a wrong block is costly.

---

## What it actually detects

Every interval it reads the live connection table (`ss -tan`) and builds a feature vector
**per peer IP**:

| Feature | Catches |
|---|---|
| `conns` — concurrent connections | connection floods / DoS |
| `distinct_local_ports` — how many of *your* ports a peer touched | **port scans** |
| `distinct_peer_ports` | scanning / odd fan‑out |
| `half_open` — SYN_SENT/SYN_RECV count | **SYN scans / floods** |

Plus two behavioral checks the model alone wouldn't catch:

- **Hard rules** (always on, fully explainable): ≥15 local ports = scan, ≥10 half‑open =
  flood, ≥200 conns = storm. These fire even if the model is undertrained.
- **Beacon detection** (outbound): it tracks the time between a peer's appearances across
  windows and flags **low‑variance, regular intervals** (coefficient of variation ≤ 0.25) —
  the signature of a C2 **beacon** (Realm/Sliver call home on a schedule). *(Verified: a
  steady 30‑second beacon is flagged; jittery human‑like traffic is not.)*

### DNS exfil / DGA detection (built in — `--dns`)

A separate detector scores **DNS query names** for two attacker behaviors:

- **DNS tunneling / exfil** — data encoded into the left‑hand labels produces **many unique,
  high‑entropy subdomains under one parent domain** (e.g. `<base32-chunk>.tun.evil.io`). This
  "many unique subdomains under one parent" signal is the strongest tell, and it's what the
  detector keys on.
- **DGA (domain‑generation algorithm)** — malware cycling through random‑looking domains
  shows up as several high‑entropy names and/or a high **NXDOMAIN** rate.

It uses **Shannon entropy** of the encoded label (random/encoded ≈ 3.8–5 bits/char;
dictionary words ≈ 2.5–3.5) plus the unique‑subdomain count and NXDOMAIN rate. Your zone
`rrintel.internal`, reverse‑DNS, and `localhost` are never flagged; add more with
`--allow-domain`. *(Verified end‑to‑end: it flags a 35‑subdomain tunnel and a DGA domain
while sparing google/github, and catches a single oversized high‑entropy label as a one‑off
exfil chunk.)*

Because wireshark/tshark are **prohibited** in this competition, the detector does **not**
sniff packets. It reads query names from a source you choose: a **resolver query log**
(`--dns-source log --dns-file …`, formats: dnsmasq / bind / unbound / systemd‑resolved),
**journald** (`--dns-source journal`), or **stdin** (`--dns-source stdin`, one name per line —
handy for pasting the DC's DNS query log). These are OUTBOUND indicators, so treat a hit like
egress C2: find the process, remove its persistence, optionally block the domain.

---

## The machine learning

The detector has two interchangeable backends; the script picks automatically:

1. **`IsolationForest` (scikit‑learn)** — an unsupervised anomaly detector. It builds random
   decision trees; points that get **isolated in very few splits** are outliers. It learns
   "normal" from your baseline with **no labels** (you don't have to tell it what an attack
   looks like). We **standardize features** first (so `conns`, which can hit the hundreds,
   doesn't drown out `half_open`) and pin **contamination to 2%** (bias toward precision —
   in this game a false positive on inbound is expensive).
2. **Robust statistics (pure Python, no dependencies)** — for each feature it computes the
   **median** and **MAD** (median absolute deviation) of normal, then flags a peer if any
   feature's **robust z‑score** exceeds 3.5. Same idea, lighter, and **works with zero
   internet** — which matters because once you run `egress-lockdown` the box can't
   pip‑install anything.

> **Install scikit‑learn *before* you lock egress** if you want the IsolationForest backend:
> `pip install --break-system-packages scikit-learn`. Otherwise the tool silently uses the
> built‑in statistical detector — both pass the self‑test. Force the no‑deps path with
> `--no-sklearn`.

Why IsolationForest (and not a deep neural net)? With minutes of unlabeled traffic and a
need for explainability and tiny footprint, IsolationForest is the right tool — fast to
train, no GPU, no labels, and you can explain every alert. A neural net would be overkill,
slower, hungrier, and harder to justify to a judge in your write‑up.

---

## How to use it (the safe workflow)

```bash
# 0) (optional, do BEFORE egress-lockdown) get the ML backend:
pip install --break-system-packages scikit-learn

# 1) After the box is CLEAN (post hunt_malware.sh), learn normal for ~10 min:
sudo python3 scripts/anomaly_guard.py --learn --minutes 10 --out baseline.json

# 2) Watch live. Inbound = recommend-only; add egress auto-block if you want:
sudo python3 scripts/anomaly_guard.py --watch --baseline baseline.json
sudo python3 scripts/anomaly_guard.py --watch --baseline baseline.json --auto-block-egress

# one-shot check (e.g. from cron):
sudo python3 scripts/anomaly_guard.py --once --baseline baseline.json

# prove the detector works on synthetic data, no traffic needed:
python3 scripts/anomaly_guard.py --selftest

# analyze DNS for exfil/DGA (no packet capture; reads query names from a source):
python3 scripts/anomaly_guard.py --dns --dns-source log --dns-file /var/log/dnsmasq.log
python3 scripts/anomaly_guard.py --dns --dns-source journal          # from journald
cat dc_dns_queries.txt | python3 scripts/anomaly_guard.py --dns --dns-source stdin
```

### Practice lab — watch it fire before the event (`anomaly_lab.sh`)

`scripts/anomaly_lab.sh` is a **fully local** range (everything stays on `127.0.0.1`, no other
host touched, no prohibited tools). It stands up loopback listeners, captures an idle
baseline, runs a real **port scan** against them, shows the sensor flag it, then runs the
**DNS exfil** detector on a crafted log — and cleans up after itself.

```bash
bash scripts/anomaly_lab.sh           # ~15s end to end
NPORTS=40 bash scripts/anomaly_lab.sh # bigger scan
```

It runs the sensor with `--demo`, which **disables the allow‑list** so loopback traffic can be
flagged for the demo. **Never use `--demo` in the real competition** — it exists only so the
lab can show you a flag; in the event the allow‑list is what protects the scorer. *(Verified:
the lab flags the 50‑port scan with a RECOMMEND line and the DNS tunnel, then exits clean.)*

- **Learn while the box is clean and traffic is representative** (let the scorer hit it a
  few times during the learn window so "normal" includes scorer‑like patterns).
- Alerts are printed and written to `reports/anomaly_<timestamp>.log` — use them as
  **Incident‑Report evidence** (peer IP, what it did, when).
- When you get an **inbound** alert: glance at whether the IP fits the scorer's cadence (use
  `scoring_recon.sh`). If it's clearly a scanner/attacker and *not* the scorer, run the
  recommended `defend_redteam.sh block <ip>`. If unsure, **don't block inbound** — prefer
  egress‑lockdown + persistence removal.
- Add any extra never‑touch range with `--allow 198.51.100.0/24` (repeatable).

---

## Honest limitations

- **It sees connection structure, not payload.** It catches scans, floods, odd fan‑out, and
  beacons; it does **not** do deep packet inspection or decrypt TLS.
- **Garbage‑in:** if you "learn" while the box is already compromised and beaconing, the
  model treats that beacon as normal. Learn **after** cleaning.
- **It's a sensor, not a cure.** The Red Team's foothold is *on the box*; removing
  persistence (`hunt_malware.sh`) and sealing egress (`defend_redteam.sh`) do more than any
  packet‑level model. Treat this as an early‑warning layer on top.
- **`ss` is required.** If `ss` (iproute2) is missing, install it; the script reads the
  connection table from it.

---

## Want to go further? (sound extensions, same safety rules)

- **DNS‑exfil / DGA detection — DONE.** Built in as `--dns` (see above). Next step would be
  to wire `--dns-source journal` into the `--watch` loop so DNS anomalies alert continuously
  alongside connection anomalies.
- **Byte‑volume features:** add bytes‑out per peer (from `ss -ti` or conntrack accounting)
  to catch bulk exfil even without a beacon signature.
- **Log‑based source scoring:** featurize `journald`/`auth.log` (failed‑vs‑accepted auth
  rate, new usernames) and the web `access.log` (status‑code mix, request rate) to rank
  suspicious *sources* — again, allow‑listing the scored ranges.
- **Per‑service profiles:** learn a separate baseline per scored port so an anomaly on 22
  is judged against SSH‑normal, not web‑normal.

All of these keep the same rule: **alert on inbound, optionally auto‑act only on egress,
and never touch the scored/internal ranges.**
