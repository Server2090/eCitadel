# pfSense hardening & ruleset — `thebox`

**Team 76 · RR Intel / eCitadel Season IV**

`thebox` is your perimeter firewall (pfSense). It is the safest place to enforce the
**egress-first** strategy for the whole team, and in the real event it is itself a scored
target (a CCS find-and-fix box), so **make changes carefully and keep GUI access**.

> pfSense is configured from its **web GUI** (Firefox is buggy in the competition console
> — use Chrome). Prefer the GUI over the shell. If you ever lock yourself out, you still
> have your **4 reverts**. Every rule table below is something you build under
> *Firewall → Rules*; the shell snippets at the end are optional and clearly marked.

---

## The addressing you're working with

| Thing | Value | Note |
|---|---|---|
| LAN side (internal) | `172.21.0.0/24` | your three boxes: .101 blacklist, .102 concierge, .103 cabal |
| LAN IP of pfSense | `172.21.0.254` | the boxes' gateway |
| WAN IP of pfSense | `172.21.1.2/30` | transit network |
| Upstream gateway | `172.21.1.1` | **OUT OF SCOPE — never filter/scan/touch it** |
| External (NAT) range | `172.27.76.0/24` | 1:1 NAT to internal; the **scorer hits these** |

**1:1 NAT** maps each internal box to its external IP (e.g. `172.21.0.102 ↔ 172.27.76.102`).
With 1:1 NAT, **WAN firewall rules use the *internal* address as the destination** (rules
are evaluated after the inbound translation), so the tables below reference `172.21.0.x`.

---

## Golden rules (same logic as the host kit)

1. **Never block the scorer.** It **rotates its IP** and lives in the **same subnet as the
   Red Team**, so **do not filter inbound by source IP, and never block a subnet.** Filter
   by **destination port** instead (allow the scored ports; that's the gate).
2. **Egress is the safe lever.** Return traffic for the scorer's inbound checks rides on
   **existing states**, so restricting *new outbound* traffic kills C2/exfil **without**
   breaking inbound scoring.
3. **Keep yourself in.** Preserve the anti-lockout / management path or you'll be reverting.

---

## 1) WAN inbound rules — allow ONLY the scored services (by port, any source)

Build these under **Firewall → Rules → WAN** (top to bottom). Source = `any` on purpose
(the scorer's IP changes). Destination = the internal box that 1:1-NATs to the external IP.

| # | Action | Proto | Source | Destination | Dst Port | Purpose |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP | any | 172.21.0.102 | 80, 443 | Web check → concierge |
| 2 | Pass | TCP | any | 172.21.0.102 | 22 | SSH check → concierge |
| 3 | Pass | TCP | any | 172.21.0.101 | 22 | SSH check → blacklist |
| 4 | Pass | TCP/UDP | any | 172.21.0.103 | 53 | DNS check → cabal |
| 5 | Pass | TCP | any | 172.21.0.103 | 3389 | RDP check → cabal |
| 6 | Pass | TCP | any | 172.21.0.103 | 5985, 5986 | WinRM check → cabal |
| 7 | **Block** | any | any | any | any | default-deny everything else inbound |

- Leave the implicit deny on, or add rule 7 explicitly for clarity/logging.
- **Do not** add per-source-IP blocks here. If you confirm a single hostile IP and it is
  **not** the scorer, you *may* add one narrow block **above** rule 1 — but never a subnet,
  and prefer handling attackers via **host egress** + **incident report** instead.
- Make sure **WAN → pfSense GUI/SSH is NOT allowed** (no rule permitting 443/80/22 to
  `172.21.1.2`). Management stays on LAN only.

---

## 2) LAN outbound rules — mirror the host "egress-lockdown" at the perimeter

By default pfSense ships a **"Default allow LAN to any"** rule. Replace it with the set
below (under **Firewall → Rules → LAN**) so the boxes can do what they need and **nothing
else** leaves — this stops beacons/exfil from any compromised box. Order matters.

| # | Action | Proto | Source | Destination | Dst Port | Purpose |
|---|---|---|---|---|---|---|
| 1 | Pass | any | LAN net (172.21.0.0/24) | 172.21.0.0/24 | any | box-to-box (DB/DNS/AD between your hosts) |
| 2 | Pass | UDP/TCP | LAN net | 172.21.0.103 | 53 | DNS to your DC |
| 3 | Pass | any | LAN net | This Firewall (172.21.0.254) | any | gateway/anti-lockout |
| 4 | Pass | TCP/UDP | LAN net | any | 53 | DNS resolution (if boxes use external DNS) |
| 5 | (optional, temporary) Pass | TCP | LAN net | any | 80, 443 | ONLY while running OS updates; remove after |
| 6 | **Block** | any | LAN net | any | any | default-deny all other egress (kills C2/exfil) |

- Rules 1–3 keep AD/DNS/DB and your management working. Rule 6 drops everything else
  **outbound to the Internet/WAN**, which is exactly the C2/exfil path.
- Inbound scoring is unaffected (its replies use established states, which pfSense allows
  automatically).
- **Run your OS updates first**, with rule 5 enabled, then **disable rule 5** to seal egress
  (just like `defend_redteam.sh egress-lockdown` warns updates need outbound 80/443).
- If something legitimate breaks, you'll see it in **Status → System Logs → Firewall** as a
  block on a LAN rule — add a narrow Pass above rule 6 for that exact destination/port.

---

## 3) pfSense self-hardening (System / Admin)

- **System → Advanced → Admin Access:** set GUI to **HTTPS**; ensure the GUI/SSH are
  reachable from **LAN only** (never WAN). Enable the **anti-lockout** rule (default on).
- Change the **default `admin` password** — but if the **scorer or an Orange-Team check
  uses pfSense creds**, submit the new password through the password-change inject in the
  exact format (same rule as the other boxes). If unsure, leave admin auth alone early on.
- **Disable** any service you don't need on the firewall itself (e.g. UPnP).
- **Backup the config first:** *Diagnostics → Backup & Restore → Download configuration*.
  That XML lets you restore in seconds if a rule change goes wrong (cheaper than a revert).
- Turn on **logging** for the default-deny rules so you can see what's being dropped.
- If the firewall is a **CCS scored box** in the real event, expect find-and-fix items
  (weak admin password, WAN management exposed, permissive any-any rules, outdated build) —
  the steps above pre-empt the common ones.

---

## 4) Optional shell snippets (GUI is preferred — use with care)

pfSense has a shell (option 8 from the console menu) with `pfctl` and `pfSsh.php`. **GUI
rules survive reboots and config restores; raw `pfctl` edits do not and can desync the GUI.**
Use these only for quick visibility or an emergency, then reconcile in the GUI.

```sh
# READ-ONLY: see current rules, states, and what's being blocked
pfctl -sr            # show active filter rules
pfctl -ss | head     # show state table (active connections)
pfctl -si            # show filter stats/counters

# EMERGENCY egress cut for one box (temporary; prefer a GUI LAN block rule):
#   block new outbound from concierge to the Internet, keep box-to-box + DNS.
# Add to a custom anchor or test with a single rule, then make it permanent in the GUI.
```

> Don't hand-edit `/tmp/rules.debug` or `pf.conf` directly — a GUI *Filter Reload*
> (Status → Filter Reload) regenerates them and will wipe manual edits. Anything you want
> to keep, put in the GUI.

---

## Quick reference

| Goal | Where |
|---|---|
| Allow scored services in | Firewall → Rules → **WAN** (ports only, source any) |
| Seal egress / kill C2 | Firewall → Rules → **LAN** (allow box-to-box+DNS, block rest) |
| Keep GUI access | System → Advanced → Admin Access (LAN only, anti-lockout on) |
| Save a restore point | Diagnostics → Backup & Restore → Download config |
| See what's blocked | Status → System Logs → **Firewall** |
| Last resort | Use one of your **4 reverts** (wipes CCS pts; service/SLA survive) |
