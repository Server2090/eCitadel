# BLOCKING THE RED TEAM — without breaking scoring

**Team 76 · RR Intel / eCitadel Season IV**
Companion to `scripts/hunt_malware.sh`, `scripts/defend_redteam.sh`, and
`docs/HOW_SCORING_WORKS.md`.

The Red Team is **automated** and **already inside** your boxes when you get them
(pre-planted malware on a phased timer). It is a **penalty category**: continued
compromise drains points; catching it and filing a good Incident Report earns some
back. This doc explains what actually stops it.

---

## The three principles (in priority order)

1. **Availability first.** A perfectly "secure" box that fails its scored check is worth
   zero. Never take an action that risks the scorer's inbound check (no inbound IP/subnet
   blocks — see `HOW_SCORING_WORKS.md`).
2. **Removing persistence beats firewalling.** The Season III debrief said it outright:
   many teams **"cut out a small amount of persistence and got no more activity."** The
   timed actions ride on implants that beacon out; remove the implants and the actions
   stop. Hunt and clean *before* you reach for firewall rules.
3. **Egress beats ingress.** The scorer/Orange-Team come *in*; C2 and exfil go *out*.
   Blocking outbound (`egress-lockdown`) kills the threat and **cannot** hurt inbound
   scoring. Blocking inbound risks the rotating scorer. So default to egress.

---

## What's coming, and when (Season III timeline)

The exact Season IV timing is **not** published and will be randomized, but Season III is
the best available map. Treat it as "what to expect," not a schedule. **Crucial insight:
if a service drops early, assume it was *stopped or disabled*, not firewalled — go
restart it (in dependency order) before anything else.**

| ~Time in | Red Team action | Your response |
|---|---|---|
| **10 min** | "good luck" messages (wall / terminal / desktop) | Cosmetic. Note it as proof of compromise for your IR. Keep hardening. |
| **30 min** | "keep calm, red team is here" image dropped to desktop/home | The file's source/staging IP is **IR evidence**. Don't panic-delete before recording it. |
| **1 hr** | **DNS + database STOPPED** | Restart in dependency order (DB → DNS → web). See recovery runbook. |
| **2 hr** | DNS + DB stopped again | Same. If it keeps recurring, you still have **persistence** — hunt it. |
| **3 hr** | services **stopped AND disabled** | `systemctl enable --now <svc>`; then find what's re-disabling them. |
| **4 hr** | (Windows) Goose Desktop dropped | Windows DC concern; killing it blue-screens (critical process) — find the persisting binary. |
| **4.5 hr** | service binaries renamed (e.g. DNS exe → "brothers stop.exe") | A service "missing" may be **renamed**. Compare against your golden baseline. |
| **5 hr** | **web-root files deleted (incl. PHP)** | Restore from your backup/golden copy of the docroot; this is why you snapshot it early. |
| **5.5 hr** | forced **reboot / blue screen** | Boxes come back; re-verify services and that nothing re-armed at boot. |

**The pattern:** stop → stop-and-disable → rename → delete → reboot. Each phase is harder
to recover from, which is why removing persistence **early** pays off.

---

## The layered blocking strategy

### Layer 0 — Don't break scoring (always on)
- No inbound IP blocks unless an IP is **confirmed** hostile and **confirmed not** the scorer.
- **Never** block a subnet (rules forbid it; the scorer shares Red Team's subnet).
- Keep scored ports open; let **AD auth + hardening** be the gate.

### Layer 1 — Remove persistence (highest value)
Run the hunt and work every finding:
```bash
sudo ./scripts/hunt_malware.sh                       # full read-only sweep
sudo ./scripts/hunt_malware.sh --baseline baselines/<host>_<ts>   # diff vs first5 capture
```
Cross-reference with the **golden baseline** to catch what was planted *before* you arrived:
```bash
sudo ./scripts/build_golden_baseline.sh --compare baselines/golden/<clean-ref>
```
Document each implant (file/service name, C2 IP) **for your IR inject**, then remove it.

### Layer 2 — Egress lockdown (kills C2/exfil, safe for scoring)
```bash
sudo ./scripts/defend_redteam.sh egress-lockdown     # after running your updates
sudo ./scripts/defend_redteam.sh egress-status
```
Allows loopback + established/related + internal `172.21.0.0/24` (DC/DB/DNS) + resolver
DNS + ICMP; drops the rest outbound. The scorer's inbound checks are untouched.

### Layer 3 — Specific-IP block for a confirmed attacker (+ IR)
```bash
sudo ./scripts/defend_redteam.sh block <confirmed-bad-ip>
```
One address at a time, evidence-based, and **file an Incident Report** — naming the C2 IP
or the implant's file/service name is exactly what recovers Red-Team penalty points.

### Layer 4 — Cautious fail2ban (optional)
```bash
sudo ./scripts/defend_redteam.sh fail2ban --apply
```
Whitelists the internal + scored-NAT ranges (`172.16.0.0/12`) so the scorer can never be
banned; generous retry, short ban. Use only if you see a genuine brute-force source.

### Layer 5 — pfSense perimeter egress
Mirror Layer 2 at the firewall: default-deny **outbound** on WAN, allow your internal
service paths. pfSense is itself scored in the real event, so test changes carefully and
remember you can revert the box if you lock yourself out of its dashboard.

---

## Defeating two specific implants

### The firewall-dropper (custom Go binary)
Behaviour observed: it backs up `xtables-nft-multi`, and **every 5 minutes** re-adds a
rule tagged like *"…not redteam please don't delete"*, **starts SSH**, and **drops all
firewall rules** (restoring its backed-up binary if needed). Symptoms: your firewall
rules vanish on a ~5-min cycle; a weird marker rule reappears.

Counter:
1. Find the driver — it's usually a **systemd unit/timer or cron** entry. Hunt newest
   units and timers (`hunt_malware.sh` flags these; also `systemctl list-timers`).
2. **Stop and disable** the unit/timer, and remove the binary and its backup copy.
3. Verify `iptables`/`xtables-nft-multi`/`nft` are real **ELF** binaries, not scripts
   (`hunt_malware.sh` checks this).
4. Re-apply your firewall, then watch for ~10 min to confirm the rules **stay**.
5. Search firewall rules for the marker comment (`nft list ruleset | grep -i redteam`).

### Diamorphine (LKM rootkit) — manual detection
Diamorphine **hides itself from `lsmod`/`/proc/modules`**, so "nothing in lsmod" is *not*
proof it's absent. It gives root via a signal and can hide PIDs. Manual checks:

- **Cheap signals (the hunt script already does these):** `dmesg | grep -i diamorphine`,
  and search disk for a `diamorphine*.ko` or stray `*.ko` outside `/lib/modules`.
- **Hidden-PID scan:** compare the kernel's process list against `ps`. Any PID that exists
  in `/proc` but not in `ps` (or vice-versa) is suspicious:
  ```bash
  # PIDs the kernel knows about vs PIDs ps shows — differences = possibly hidden
  comm -23 <(ls /proc | grep -E '^[0-9]+$' | sort) <(ps -eo pid= | tr -d ' ' | sort)
  ```
- **Signal-toggle test (last resort, understand it first):** stock Diamorphine toggles its
  visibility on a magic signal (commonly `kill -64 <pid>` to grant root, `-63` to hide a
  PID). If you suspect it and have a candidate PID, researching/toggling can confirm — but
  do this only if you understand it, and **document before acting** for your IR.
- **If root keeps coming back** after you remove other footholds, suspect an LKM rootkit
  and consider whether a **revert** (you have 4) plus immediate re-hardening is cheaper
  than chasing it — remembering a revert wipes CCS points but not service/SLA points.

---

## Per-implant quick reference (Linux)

For each: how it hides → how to find → how to kill. All "find" steps are in
`hunt_malware.sh`; record evidence for your IR **before** removing.

| Implant | Hides as | Find it | Remove |
|---|---|---|---|
| **Realm C2** | beacon, sometimes a time-stomped `udevd` unit | newest systemd units; external beacon conns; the C2 IP | disable+remove unit/binary; egress-lockdown; **name the C2 IP in IR** |
| **Sliver C2** | HTTP(S) beacon | established conns to odd external hosts; suspicious binaries | kill PID, remove binary/unit; egress-lockdown |
| **Prism** | renames to **`udevd`** in `ps` | process whose name=`udevd` but binary isn't under `/…/systemd/` | kill PID, remove binary, clear its persistence |
| **netcat backdoor** | `systemd-tech.service` (looks systemd-ish) | newest units; ExecStart with `nc`/`/dev/tcp` | `systemctl disable --now`, delete unit + binary |
| **recompiled `pam_unix.so`** | exfils password changes to a webhook | PAM lib not owned by a package; webhook/IP string in the lib | reinstall the pam package (`apt reinstall libpam-modules` / `dnf reinstall pam`); rotate creds |
| **bashrc/sudo harvester** | logs sudo password to a file under `/var/lib/mysql`; sudo auth also broken | unexpected file in `/var/lib/mysql`; harvester line in shell rc | remove the rc hook + the log file; fix sudo (two separate vulns) |
| **fake nologin** | `/etc/passwd` shell = `/usr/sbin/nologin ` (trailing space) = real bash | `awk -F: '$7 ~ /[[:space:]]/' /etc/passwd` | set the account's shell back to true `nologin`; investigate the account |
| **SSH CA backdoor** | `TrustedUserCAKeys` / `AuthorizedKeysCommand` in sshd | `sshd -T | grep -iE 'trusteduserca|authorizedkeyscommand'` | remove the directive + CA file, `sshd -t`, reload |
| **firewall-dropper** | systemd/cron that flushes rules every 5 min | newest units/timers; marker comment in rules; non-ELF iptables | disable+remove driver and binary; restore rules; watch |
| **Diamorphine** | LKM hidden from lsmod | dmesg; stray `.ko`; hidden-PID scan (above) | unload if you can identify it; otherwise consider a revert + re-harden |

> **Windows DC (cabal)** has its own implants (ISRAID IIS module, Nosferatu NLM backdoor,
> King's Guard userland rootkit, sticky-keys/utilman IFEO debuggers, malicious WFP rule,
> Goose Desktop, and binaries signed by a **fake "Microsoft Corporation" CA**). Those need
> a Windows toolset — ask and I'll build a PowerShell DC pack to mirror this Linux kit.

---

## When a scored service goes down

Before you touch the firewall, assume **stopped / disabled / renamed**, not blocked:

1. `systemctl status <svc>` — stopped? `systemctl start <svc>`. Disabled? `enable --now`.
2. Still failing? It's probably a **dependency** — restart in order (DB → DNS → web). See
   the dependency-aware recovery runbook in `playbooks/RUNBOOKS.md`.
3. Binary "missing"? It may be **renamed** — diff against your golden baseline.
4. Web app up but check still red? The scorer does a **login + action via AD** — verify
   AD/DNS/DB, not just that the homepage loads.
5. Only after all that, consider whether an *outbound* dependency is being blocked — and
   never add an inbound block that could catch the scorer.
