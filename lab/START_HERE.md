# eCitadel Open — Team 76 Defense Kit (RR Intel // Season IV)

This kit is built from **your** competition material: the Competition Orientation, the
Practice Round README + three answer keys, the New User inject, the eCitadel website
(rules/event/source), and the open‑sourced 2024 + 2025 challenge repos. Every Linux
command in here was checked against the **actual** OS versions you will get
(**Fedora 43** and **Debian 13 "Trixie"**), not copied blindly from the older practice
answer keys — several commands changed between those versions (see notes below).

> **Read this whole file once before the competition.** It is the map for everything else.

---

## 1. What you are defending (confirmed from the Orientation deck)

| Host | Internal IP | External IP (Team 76) | OS | Role | Scored |
|---|---|---|---|---|---|
| `blacklist` | 172.21.0.101 | 172.27.76.101 | **Debian 13** | Database | SSH (+ DB as critical dependency) |
| `concierge` | 172.21.0.102 | 172.27.76.102 | **Fedora 43** | Web | HTTP, SSH |
| `cabal`     | 172.21.0.103 | 172.27.76.103 | Windows Server 2022 | Domain Controller | DNS, (RDP/WinRM) |
| `thebox`    | 172.21.0.254 (LAN) | — | pfSense | Firewall | — |

- **Domain:** `rrintel.internal`. Almost all web/service checks authenticate against AD.
- **NAT:** 1:1 NAT. Internal `172.21.0.0/24` ↔ External `172.27.76.0/24`. The scoring
  engine hits your **external** IPs. **Internal gateway for the servers is `172.21.0.254`.**
- **7 scored services** are spread across **SSH, HTTP, DNS**.
- This kit covers the **two Linux boxes you asked about** (`blacklist` = Debian,
  `concierge` = Fedora). The Windows DC and pfSense are covered at the *concept/checklist*
  level in the docs, but the **scripts are Linux‑only** (see "Scope & assumptions").

> **Your team number is 76**, so wherever past docs write `172.27.x.###`, your `x = 76`.

---

## 2. How you score (and how you LOSE) — the strategy in one screen

| Category | Weight | How to win it | How you lose points |
|---|---:|---|---|
| **CCS find‑and‑fix** | 20% | Fix the planted vulns (the agent scores you live). **Malware‑heavy** this year. | Negative actions (e.g. breaking a required service, removing required software) |
| **Injects** | 35% | Complete the business tasks; **submit a PDF** for each, on time | Late / incomplete / wrong format |
| **Scored services** | 35% | Keep SSH/HTTP/DNS **up AND functional** on the external IP | Down service = 0; **5 misses in a row = SLA penalty (3×)** |
| **Orange Team** | 10% | Keep the Operations Portal usable; reply to tickets | Users can't log in / can't get a reply / automation breaks |
| **Red Team** | penalty | **Detect → remove → file an Incident Report** to earn points back | Ongoing compromise / persistence keeps costing you |

**Per‑check points:** non‑SSH up+functional = **3**, SSH up = **1**, down = **0**.
**SLA:** down for 5 consecutive checks = penalty of **3×** (15 non‑SSH / 5 SSH), reapplied
each window; one good check resets the counter; each service counted separately.

### The single most important rule for this kit
> **Service availability is worth more than any single hardening point.**
> Never apply a change that takes a scored service offline. The scripts here are built
> *availability‑first*: they detect what is listening and protect it before they harden.

---

## 3. The first 15 minutes — exact order (don't improvise)

Do these **in order**. The detail for each is in `playbooks/RUNBOOKS.md`.

1. **Log in to all VMs and confirm services are green** on the portal. Establish a working
   SSH session to each Linux box and **leave it open** (so a bad change can't lock you out).
2. **Run the baseline capture** on each Linux box → `scripts/first5_secure.sh --baseline-only`.
   This snapshots users, listening ports, processes, connections, cron, SSH keys, SUID, etc.
   so you can prove what changed when the Red Team strikes (this is your IR evidence).
3. **Run the safe auto‑hardening** → `scripts/first5_secure.sh`. It does only
   *non‑breaking, reversible* hardening and **prints a TODO of the risky items it refused
   to auto‑do** (e.g. deleting users) for you to action by hand.
4. **Run the read‑only audit** → `scripts/audit_linux.sh`. Read its report; fix the flagged
   items using `docs/PAST_VULNERABILITIES.md`.
5. **Run the malware hunt** → `scripts/hunt_malware.sh`. Anything it flags → triage with the
   IR playbook. **Removing planted malware/persistence is where the points are this year**
   (often it ends Red‑Team activity entirely). If you captured a clean‑VM golden manifest,
   also run `scripts/build_golden_baseline.sh --compare baselines/golden/<ref>` to surface
   anything pre‑planted.
6. **Confirm scoring is landing** → `scripts/scoring_recon.sh --window 15`. It tells you the
   real check cadence (your SLA window) and that the engine is reaching you. Details in
   `docs/HOW_SCORING_WORKS.md`.
7. **Rotate credentials** the *safe* way (see `playbooks/RUNBOOKS.md` → Password Rotation)
   and **submit each change through the portal inject in the EXACT required format.**
8. **Stand up Red‑Team defenses** → run your updates, then `scripts/defend_redteam.sh
   egress-lockdown`. This is the **safe** lever: it blocks C2/exfil **outbound** and never
   touches the inbound scoring path. Read `docs/BLOCKING_THE_RED_TEAM.md` and
   `docs/HOW_SCORING_WORKS.md` first — **never block inbound by IP or block a subnet** (you'll
   ban the rotating scorer). Use `block <ip>` only for a confirmed attacker + file an IR.
9. **Start the watcher** → `scripts/watch_services.sh &` to get alerted the moment a scored
   service goes down or a baseline item changes.

---

## 4. What's in this kit

```
eCitadel_Team76/
├── START_HERE.md                      ← you are here
├── FIELD_CARD.md                      one‑page "first 30 minutes" (print this)
├── scripts/                           (Linux: concierge + blacklist)
│   ├── first5_secure.sh               safe auto‑hardening + baseline (RUN FIRST; --dry-run, --aggressive)
│   ├── audit_linux.sh                 READ‑ONLY vuln + misconfig scanner (Debian & Fedora)
│   ├── hunt_malware.sh                READ‑ONLY malware / persistence hunt (tuned to past TTPs)
│   ├── build_golden_baseline.sh       "build clean & compare" — find pre‑planted malware
│   ├── scoring_recon.sh               READ‑ONLY: measure how scoring behaves on your box
│   ├── defend_redteam.sh              egress lockdown + targeted IP block + cautious fail2ban
│   ├── anomaly_guard.py               ML/behavioral anomaly sensor (IsolationForest + stdlib fallback; --dns)
│   ├── anomaly_lab.sh                  safe local practice range to watch the sensor fire
│   └── watch_services.sh              live scored‑service + baseline‑drift monitor
├── windows/                           (Windows DC: cabal — run in elevated PowerShell)
│   ├── Harden-DC.ps1                  safe DC hardening (--DryRun, --Aggressive; never breaks AD)
│   ├── Hunt-DC.ps1                    READ‑ONLY DC hunt (IFEO, AppInit, LSA, WMI, fake‑MS certs…)
│   ├── Watch-DCServices.ps1           live monitor for DNS/RDP/WinRM/AD
│   ├── DRY_RUN_TRACE.md               line‑by‑line of every DC command + how to undo it
│   └── README_WINDOWS.md              DC TTPs, the SSH‑pubkey inject, domain‑join notes
├── pfsense/                           (firewall: thebox)
│   └── PFSENSE_HARDENING.md           WAN allow‑list + perimeter egress‑lockdown ruleset
├── docs/
│   ├── BASIC_HARDENING_SHEET.md       easy wins for all boxes + browser/console settings
│   ├── AI_ANOMALY_FIREWALL.md         how the ML anomaly sensor works + safe usage
│   ├── PAST_VULNERABILITIES.md        every vuln/TTP from past events: find / fix / why
│   ├── MISCONFIGURATIONS_AND_WATCHLIST.md   common misconfigs + "do NOT break these"
│   ├── LINUX_COMMAND_REFERENCE.md     command cheat‑sheet by task, with when‑to‑use
│   ├── HOW_SCORING_WORKS.md           scoring mechanics + "allow only scoring & real users"
│   └── BLOCKING_THE_RED_TEAM.md       stop the automation w/o breaking scoring (+ kill table)
├── playbooks/
│   └── RUNBOOKS.md                    first‑hour, incident response (+ IR template),
│                                      service recovery, password rotation, inject playbooks
├── practice-lab/                      build your own vulnerable targets in Proxmox to rehearse on
│   ├── README_LAB.md                  why/what/how + topology + safety
│   ├── build_proxmox_lab.sh           (on Proxmox host) fetch cloud images + create the VMs
│   ├── seed_linux.sh                  (in a Fedora/Debian VM) plant past vulns + malware + answer key
│   ├── seed_windows.ps1               (in the Windows DC VM) plant DC misconfigs + inert implants
│   └── pfsense_setup.md               import pfSense + misconfigs to practice fixing
├── baselines/                         (scripts write your captured baselines here;
│   └── golden/                         put clean‑VM golden manifests here)
└── reports/                           (scripts write their findings here)
```

Every script is **heavily commented** — read the comments; they explain *why* each step is
safe and what it touches. The docs explain the concepts. The playbooks tell you what to do
minute‑by‑minute and when something goes wrong.

> **Before you run anything:** make the scripts executable once after copying them onto a
> box — `chmod +x scripts/*.sh` — or just run each with `bash`, e.g.
> `sudo bash scripts/first5_secure.sh`. All scripts auto‑detect Fedora vs Debian, require
> root (`sudo`), and write their output into `baselines/` and `reports/` inside this kit.

---

## 5. Hard "do NOT" list (these cost points or get you disqualified)

- **Do NOT change the IP** of any VM, or the password of your **primary auto‑login user**.
- **Do NOT stop/remove a critical service** (sshd, the web server, the database, DNS).
- **Do NOT remove required software** (each box has a required package list — check it).
- **Do NOT disable `PasswordAuthentication` for SSH** unless you have *confirmed* the scorer
  uses keys — the SSH check very likely logs in with a password. (Disabling **root** login
  and **empty** passwords is fine and is scored‑positive.)
- **Do NOT set the host firewall to default‑deny before allowing the scored ports + SSH.**
- **Do NOT block whole subnets**, and **do NOT scan** `.1`/`.2` addresses, the Red Team,
  other teams, or anything that isn't your VM. (Rule‑book: instant DQ risk.)
- **Do NOT revert a VM** unless truly necessary — only 4 reverts before penalties, and a
  revert wipes all your CCS points and changes on that box.
- **Do NOT auto‑delete users in bulk.** Delete only accounts you've confirmed are
  unauthorized against this year's README user list (the script flags them; you decide).

---

## 6. Scope & assumptions (so you can correct me)

I made these choices deliberately. Tell me if you want any changed:

1. **All four boxes covered.** Linux automation (`scripts/`) targets `concierge` (Fedora 43)
   and `blacklist` (Debian 13); the **Windows DC** `cabal` has its own PowerShell pack
   (`windows/`), and **pfSense** `thebox` has a hardening + ruleset doc (`pfsense/`). The
   Linux and Windows hardening scripts both have a **`--dry-run`/`-DryRun`** preview and an
   **`--aggressive`/`-Aggressive`** mode.
2. **No assumptions about the exact service stack.** The actual planted services/vulns are
   secret until you start. So the scripts **detect what is actually running** and adapt,
   rather than assuming "it's WordPress + vsftpd + MariaDB" like past years. The docs list
   the past stacks (OpenCart, MediaWiki, WordPress, vsftpd, MariaDB, dovecot, postfix…) so
   you recognize them fast.
3. **Safe‑by‑default automation.** Per your "without breaking anything," the default run does
   only reversible, non‑breaking hardening and **backs up every file it edits**. Destructive
   actions (delete user, remove package, kill service) are **staged and printed for your
   confirmation**, not run by default. There is now a clearly‑labeled **`--aggressive`** mode
   that auto‑remediates only the *scoring‑safe* subset (locks empty‑password accounts,
   disables mail/discovery services, removes prohibited tools — never touches sshd/web/DB/
   DNS/vsftpd/SMB and never deletes a user), and a **`--dry-run`** that previews everything
   and changes nothing. **The Linux scripts were live‑tested on a deliberately compromised
   box and caught every planted indicator** (see §8).
4. **Team number = 76** everywhere. If that's wrong, it only affects the external IPs in the
   docs; tell me and I'll fix.

---

## 7. One‑paragraph answer to "block the automated Red Team without breaking scoring"

Yes — the rules permit firewall rules, TCP resets, and active response, and **you** own any
disruption to scoring, so the trick is choosing levers that *can't* hurt the inbound check.
Highest‑value moves, in order: **(1) hunt and remove the pre‑planted persistence/malware** —
the debrief says cutting a little persistence often ends Red‑Team activity entirely;
**(2) egress‑lockdown** (`defend_redteam.sh egress-lockdown`) to drop C2/exfil *outbound* —
this is the safe big lever because it never touches the inbound scoring path; **(3) rotate
every credential** (and submit them correctly so scoring/Orange‑Team keep working);
**(4) a host firewall that allows your scored *ports* + SSH + established/related, then
default‑denies** — note this is **port**‑based, not IP‑based; **(5) cautious fail2ban** tuned
so it can never ban the scorer. What you must **NOT** do: gate **inbound by IP**, block a
**subnet**, default‑deny before allowing scored ports, or disable password SSH if the scorer
needs it — the engine rotates IPs and shares Red Team's subnet, so an inbound IP/subnet block
will eventually drop the scorer. Full reasoning + exact commands:
`docs/HOW_SCORING_WORKS.md`, `docs/BLOCKING_THE_RED_TEAM.md`, and `scripts/defend_redteam.sh`.

---

## 8. What was tested (so you can trust the tools)

The Linux scripts were run against a **deliberately compromised box** seeded with the
Season III indicator set, and every script was checked with `bash -n` + shellcheck (0
warnings). Seeded and **caught**:

- netcat backdoor as a `systemd` unit; a `udevd`‑disguised process from `/tmp`; a
  **comm‑spoofed** `udevd` (the Prism trick) → caught by `hunt_malware.sh`.
- SSH **CA + AuthorizedKeysCommand** backdoor; **cron** downloader beacon; **web shell**;
  **unowned PAM module** with a Discord‑webhook string; **nologin‑with‑a‑space** account;
  `/etc/ld.so.preload` hook; **firewall red‑team marker** rule; calling‑card files →
  caught by `hunt_malware.sh`.
- **SUID‑root bash** backdoor and a **`/var/lib/mysql` credential‑harvest** file →
  these two slipped through on the first pass and the hunt was **fixed** (SUID now flagged
  by location/hidden even with no baseline; mysql harvest now found by content, not name).
- extra **UID‑0** account, **empty‑password** account, **prohibited tools**, **world‑
  writable** files → caught by `audit_linux.sh`.
- new unit, new listener (`:4444`), new users, new UID‑0, new SUID, cron, and an sshd
  config change → caught by `build_golden_baseline.sh --compare`.

`first5_secure.sh` was verified to (a) change **nothing** under `--dry-run`, and (b) under
`--aggressive` actually lock an empty‑password account, attempt prohibited‑tool removal,
write the validated SSH drop‑in, and back up every edited file — degrading gracefully when
a service isn't running. The **Windows** (`windows/`) and **pfSense** (`pfsense/`) packs are
written to the same safe‑by‑default standard; the PowerShell can't be executed from here, so
review it once on `cabal` with `-DryRun` before applying.
