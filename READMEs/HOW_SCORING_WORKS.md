# HOW SCORING WORKS — and how to "allow only scoring + real users"

**Team 76 · RR Intel / eCitadel Season IV**
Companion to `scripts/scoring_recon.sh` (measures it live) and
`scripts/defend_redteam.sh egress-lockdown` (the safe block lever).

This doc has two jobs:
1. Explain **exactly how the competition decides whether a service is "up"** — the
   documented rules, plus how to **confirm them empirically on your own boxes**.
2. Answer your real question: **"is there a way to block everything except the
   scoring engine and true users?"** — honestly, with the method that works and
   the one trap that loses you the round.

---

## Part 1 — The documented scoring rules (your yardstick)

These come straight from the orientation. Treat them as ground truth, then verify
the timing on your box with `scoring_recon.sh`.

| Rule | Value | Consequence |
|---|---|---|
| **Weight** | non-SSH up+functional = **3 pts**; SSH up = **1 pt**; down = **0** | The web/DNS checks are worth 3× SSH. Protect them first. |
| **Cadence** | external engine checks at **random ~2–3 min** intervals | You don't control when. A fix isn't "seen" until the next check + portal lag. |
| **Portal lag** | status shows **~2–3 min after** a check; up to **~5 min** end-to-end | After a fix, wait ~5 min before trusting the scoreboard. |
| **SLA** | **5 consecutive** misses = penalty: **−15** (non-SSH) / **−5** (SSH) | Non-overlapping. **One good check resets the counter to 0.** |
| **What "up" means** | service reachable on the **external IP** *and* content/functionality correct | A port that's open but broken = **0**. |
| **Web check** | logs in via **AD**, clicks around, performs an action | Static page or broken login = **0**, even if the homepage loads. |
| **Auth** | **almost all checks use Active Directory** (`rrintel.internal`) | If the DC/DNS is down, many services fail at once (cascade). |
| **Scorer IPs** | engine **reuses + rotates** its IP, and sits in the **same subnet as Red Team** | **Do NOT block inbound by IP** — you will eventually block the scorer. |

### The SLA math, worked out
A penalty needs **5 misses in a row**. At ~2–3 min/check that's a window of roughly
**10–15 minutes** of continuous downtime before the −15/−5 hits. Practical takeaways:

- A service that flaps (down 1–2 checks, then up) costs you those checks' points but
  **never triggers the SLA** — one good check zeros the counter.
- If you're mid-fix and the clock is ticking, **getting even one good check in**
  resets the SLA counter, buying you the next 10–15 min.
- Each service has its **own** counter. Losing SSH's SLA doesn't touch HTTP's.

---

## Part 2 — How to confirm scoring empirically (scoring_recon.sh)

You can't see the scoreboard's internals, but your **boxes log every check**. Run:

```bash
sudo ./scripts/scoring_recon.sh --window 15      # watch live for 15 minutes
sudo ./scripts/scoring_recon.sh --logs-only      # analyze existing logs now
```

What it does (100% read-only, localhost only):

- **Samples live inbound connections** to your scored ports (22/80/443/53) and tallies
  who is connecting and how often.
- **Parses the SSH journal** for `Accepted`/`Failed` logins → source IPs + timestamps.
- **Parses the web access log** for 2xx/3xx responses → source IPs + timestamps.
- **Computes the real cadence** — the min/mean/max gap between successful checks. That
  mean gap, ×5, is **your actual SLA window in minutes** on this box right now.
- Prints a **per-source-IP summary** labelled by behaviour (authenticated-OK vs.
  connected-but-no-auth) — to *understand* traffic, **not** to build a block list.

### How to read it
- **Successful SSH logins / HTTP 2xx every ~2–3 min** = the scorer is reaching you and
  your AD auth path works. This is the green-light you want.
- **No successful checks** = either nothing scored yet, or the **functional** check is
  failing (broken login, AD/DB/DNS down) even if the port is open. Cross-check with
  `watch_services.sh --once`.
- **A burst of failed SSH auth from one IP** = noise or a probe. Remember Red Team uses
  **planted creds/malware**, not brute force, so floods here are usually *not* the main
  threat — **investigate, don't auto-ban** (you might ban the scorer).

---

## Part 3 — "Block everything except scoring and true users"

This is the key question, so here is the blunt answer.

### Who are the "true users"?
- **The scoring engine** — connects *inbound* to your SSH/HTTP/DNS on the external IP,
  authenticates with AD, performs an action.
- **Orange Team** — automated users who log into the **RR Intel operations portal**
  (inbound) and file tickets. **Their credentials come from your password-change
  submissions**, so if you change a password and don't submit it correctly, Orange Team
  locks out and you lose points.

Both of these **connect INTO you**. Neither needs your box to reach *out* to them.

### Why you cannot do it with an inbound IP allow/deny list
The orientation is explicit: **the scorer rotates IPs and lives in the Red Team's
subnet** (e.g. `.50` red team, `.51` scorer, swapping over time). So:

- An **inbound allow-list** would eventually drop the scorer when it rotates to a new IP
  → missed checks → SLA penalties.
- An **inbound subnet block** would hit the scorer's subnet → instant point loss, and
  blocking subnets is explicitly **against the rules** (penalty/DQ risk).
- Even an inbound *single-IP* block is dangerous unless you have **positively confirmed**
  that IP is a live attacker and **not** the scorer.

**Conclusion: do not gate inbound by IP.** Keep your scored ports open to everyone and
control *what an attacker can accomplish* instead.

### The method that actually works (in priority order)

**1. Gate inbound by AUTH + HARDENING, not by IP.**
The scorer gets in because it has valid AD creds and hits a working service. An attacker
probing the same open port gets nothing **if the box is hardened**: root SSH off, empty
passwords off, no backdoor users, no extra listeners, AD as the auth gate. Run
`first5_secure.sh` then `audit_linux.sh`. Open port + hardened service = scorer passes,
prober bounces.

**2. EGRESS LOCKDOWN — the one real "block the bad, keep scoring" lever.**
The scorer and Orange Team connect *in*; their replies are allowed automatically as
established traffic. **C2 beacons and data exfil go *out*.** So block outbound:

```bash
sudo ./scripts/defend_redteam.sh egress-lockdown    # drop outbound except essentials
sudo ./scripts/defend_redteam.sh egress-status      # watch the drop counter climb
sudo ./scripts/defend_redteam.sh egress-restore     # undo instantly (e.g. to update)
```

It **allows**: loopback, established/related (so every inbound scorer/Orange-Team
connection still works), your **internal subnet `172.21.0.0/24`** (DC for AD/Kerberos/
LDAP/DNS, and your DB — the things scoring depends on), DNS to your resolvers, and ICMP.
It **drops** everything else outbound — which is exactly the C2/exfil path. It **never
touches the inbound path**, so scoring is unaffected. (Trade-off: blocks internet package
updates while on — do `dnf`/`apt` first, or `egress-restore`, update, re-lock.)

**3. REMOVE PERSISTENCE — often this alone ends Red Team.**
The Season III debrief said it directly: many teams **"cut out a small amount of
persistence and got no more activity."** The Red Team's actions ride on pre-planted
implants beaconing out; kill the implants and the actions stop. Run `hunt_malware.sh`,
work the findings, remove the footholds. This is higher-value than any firewall rule.

**4. Block a SPECIFIC confirmed-bad IP — narrowly, with evidence.**
If `scoring_recon.sh`/`hunt_malware.sh` show an active C2 or attacker IP **and you've
confirmed it is not the scorer**, block that single address and **file an Incident
Report** (naming the C2 IP can recover penalty points):

```bash
sudo ./scripts/defend_redteam.sh block <confirmed-bad-ip>
```

The tool refuses private/internal/scored-NAT/out-of-scope ranges to protect you. **Never
block a whole subnet.**

**5. Do egress filtering at pfSense too.**
The pfSense box is your network chokepoint and is itself scored during the real event.
A default-deny **outbound** WAN policy with allowances for your internal services mirrors
step 2 at the perimeter and catches anything host rules miss.

### Decision table

| Traffic | Direction | Decision | How |
|---|---|---|---|
| Scorer → your SSH/HTTP/DNS | inbound | **ALLOW (all IPs)** | keep ports open; AD + hardening gate it |
| Orange Team → operations portal | inbound | **ALLOW (all IPs)** | keep portal up; submit password changes correctly |
| Your box → C2 / webhook / internet | outbound | **DROP** | `egress-lockdown` (+ pfSense outbound deny) |
| Your box → DC / DB / DNS (172.21.0.0/24) | outbound | **ALLOW** | permitted by egress-lockdown |
| Confirmed attacker IP (not scorer) | either | **DROP that one IP** | `defend_redteam.sh block <ip>` + file IR |
| Any whole subnet | either | **NEVER block** | rules forbid it; you'd hit the scorer |

---

## Part 4 — Checklist

- [ ] Verified all services **green on the portal** before touching anything (grace period).
- [ ] Ran `scoring_recon.sh` → confirmed successful checks + know my **real cadence/SLA window**.
- [ ] Hardened with `first5_secure.sh`; `audit_linux.sh` shows no FAILs.
- [ ] Ran `hunt_malware.sh`; removed persistence (this may end Red Team by itself).
- [ ] Applied `egress-lockdown` (after updates) — drop counter rising, services still green.
- [ ] **Did NOT** block any subnet or any inbound IP without confirming it isn't the scorer.
- [ ] Any confirmed C2/attacker IP → single-IP block **+ Incident Report** (recovers penalty pts).
- [ ] After every fix, waited ~5 min and re-checked the scoreboard.
