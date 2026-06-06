# RUNBOOKS — what to do, in order

**Team 76 · RR Intel / eCitadel Season IV**
Operational playbooks. Pair with the scripts in `scripts/` and the strategy in
`docs/`. Print this or keep it open in a second tab.

Boxes (memorize):

| Host | Internal | External (Team 76) | OS | Role | Scored |
|---|---|---|---|---|---|
| `blacklist` | 172.21.0.101 | 172.27.76.101 | Debian 13 | Database | SSH (+ DB dependency) |
| `concierge` | 172.21.0.102 | 172.27.76.102 | Fedora 43 | Web | HTTP, SSH |
| `cabal` | 172.21.0.103 | 172.27.76.103 | Win 2022 | Domain Controller | DNS, RDP/WinRM |
| `thebox` | .254 / WAN .1.230 | — | pfSense | Firewall | (scored in real event) |

> Domain: `rrintel.internal`. Gateway `172.21.1.1` = **out of scope, never touch**.

---

## Runbook 0 — The 5-minute grace period (before you can touch anything)

1. Log into the portal (Chrome). Let it boot your boxes.
2. **Read the readme** on the Announcements tab.
3. Go to the **Scoring tab and confirm everything is GREEN.** This is your proof the org
   handed you a working environment — anything that breaks after is on you, so capture
   this mental snapshot.
4. **Download the WireGuard VPN config** (only available once you start) and connect.
5. If using it, set up the web console / VMRC now.

---

## Runbook 1 — First 15 minutes (in this exact order)

The goal: secure without breaking, and capture forensic state, fast.

1. **Open every box, confirm you can log in.** If a Windows login throws "invalid password"
   intermittently, that's a known implant (Nosferatu) — note it, keep trying.
2. **Capture a baseline first (read-only), before you change anything:**
   ```bash
   sudo ./scripts/first5_secure.sh --baseline-only
   ```
   This snapshots users, ports, processes, services, SUID, hashes, PAM, etc. into
   `baselines/<host>_<ts>/`. You need this to diff against later.
3. **Back up the web docroot now** (Red Team deletes it at ~5 hr):
   ```bash
   sudo tar czf /root/docroot-backup.tgz /var/www 2>/dev/null   # adjust path to your app
   ```
4. **Apply the safe hardening pass:**
   ```bash
   sudo ./scripts/first5_secure.sh
   ```
   Safe-by-default: root SSH off, empty passwords off, password policy, `ip_forward=0`,
   auto-updates, firewall that **allows current listeners + 22/53/80/443 first, then
   default-denies**. Destructive items are **reported, not executed**.
5. **Audit to see what still fails:**
   ```bash
   sudo ./scripts/audit_linux.sh
   ```
   Fix the `[FAIL]` items (each has a FIX line). Re-run to confirm.
6. **Verify services are still green** on the portal (wait ~5 min for lag). If anything
   went red, see Runbook 3 immediately.

> Do **not** change the auto-login user's password, and do **not** change any VM's IP.

---

## Runbook 2 — First hour (after the 15-min pass)

1. **Hunt malware:**
   ```bash
   sudo ./scripts/hunt_malware.sh --baseline baselines/<host>_<ts>
   ```
   Work every HIGH/MED finding. **Removing persistence may end Red Team entirely.**
2. **Clean-build compare** (if you've captured a golden manifest on a clean VM):
   ```bash
   sudo ./scripts/build_golden_baseline.sh --compare baselines/golden/<clean-ref>
   ```
   Triage the diff (extra users/units/ports/SUID/changed binaries = candidates).
3. **Understand scoring on your box:**
   ```bash
   sudo ./scripts/scoring_recon.sh --window 15
   ```
   Confirm checks are landing; learn your real cadence/SLA window.
4. **Run updates, then lock egress:**
   ```bash
   sudo dnf upgrade -y   # Fedora     |   sudo apt update && sudo apt upgrade -y   # Debian
   sudo ./scripts/defend_redteam.sh egress-lockdown
   ```
5. **Start the live monitor** in a spare terminal and leave it running:
   ```bash
   sudo ./scripts/watch_services.sh --baseline baselines/<host>_<ts>
   ```
6. **Check the Injects tab.** Injects arrive on a rolling basis with no notification —
   build the habit of checking every few minutes (see Runbook 6+).
7. **Rotate passwords** once, properly (Runbook 5) when the password-change inject appears.

---

## Runbook 3 — Service recovery (dependency-aware) ⭐

This is the single highest-leverage skill in this competition. A down service is **most
often stopped/disabled/renamed by Red Team, not firewalled.** And services depend on each
other, so order matters.

**Dependency chain:** `web (concierge)` → needs **DNS (cabal)** to resolve → needs
**database (blacklist)** → and almost everything needs **AD auth (cabal)**.

### Steps
1. **Identify the layer that's actually broken.** A red web check is often a DB/DNS/AD
   problem, not a web problem.
2. **Restart bottom-up:**
   - **Database (blacklist):** `systemctl status mariadb` → `systemctl enable --now mariadb`
   - **DNS + AD (cabal, Windows):** ensure the DC's DNS and directory services are running.
   - **Web (concierge):** `systemctl enable --now httpd` (Fedora) and the app service.
3. **Re-point and re-test top-down:** confirm web can resolve DNS and reach the DB.
4. **The NopCommerce-style trap:** some apps **refuse to work** until you restart the *web
   app/service itself* **after** its DB/DNS are back — even if you started them in order.
   So after the DB/DNS are healthy, **restart the web service once more** and re-test the
   actual login+action, not just the homepage.
5. **If the binary is "missing":** it may be **renamed** (the DNS-exe-rename TTP). Diff
   against your golden baseline; restore/rename back, then re-enable.
6. **If it keeps dying:** persistence is re-stopping/re-disabling it. Hunt the driver
   (newest systemd unit/timer/cron) and remove it (see `BLOCKING_THE_RED_TEAM.md`).
7. **Last resort — revert:** see Runbook 7. Remember a revert may **not** fix the service
   if the cause is a dependency on another box.

---

## Runbook 4 — Incident Response (catch it, report it, recover points)

Red Team is a **penalty** category; a good Incident Report recovers some of those points,
and naming the **C2 IP** or the **implant file/service name** is explicitly rewarded.

### When you see activity (calling-card file, dropped service, odd connection):
1. **Record before you clean.** Capture the evidence first:
   - Source/remote IPs of any beacon: `ss -tnp` / your `hunt_malware.sh` network section.
   - The implant's file path and service/unit name.
   - Affected host and what it did (stopped DNS, deleted docroot, etc.).
   - Timestamps.
2. **Contain:** egress-lockdown (kills the beacon), then remove the implant; if a single
   external attacker IP is confirmed (and not the scorer), `defend_redteam.sh block <ip>`.
3. **Write the IR memo** (template below) and **submit a PDF** to the inject.

### IR memo template (fill in, export to PDF)
```
MEMORANDUM — INCIDENT REPORT
To:        RR Intel Task Force
From:      Team 76, Incident Response
Date/Time: <when>
Subject:   Active malicious activity detected and contained

1. Summary
   Brief: what we found, on which system(s), and current status.

2. Affected System(s)
   Hostname(s) + IP(s): e.g. concierge (172.27.76.102 / 172.21.0.102)

3. Source / Indicators of Compromise
   - Malicious/polling connection(s): <remote IP:port>  (e.g. C2 beacon)
   - Exfil endpoint(s): <webhook/URL/IP>
   - Implant file path(s): <...>
   - Persistence unit/service name(s): <...>

4. Description of Activity & Impact
   What it was doing (beaconing/exfil/stopping services) and the impact
   (e.g. DNS stopped at ~T+1h causing web check failures).

5. Mitigation Steps Taken
   - Recorded IOCs (above).
   - Blocked outbound C2 via egress lockdown / blocked IP <x> at host & pfSense.
   - Removed implant <file> and disabled persistence <unit>.
   - Restored service(s) in dependency order; verified scoring green.

6. Recommendations
   Follow-up hardening to prevent recurrence.
```

---

## Runbook 5 — Password rotation (do it once, exactly right)

Assume every default/shared credential is compromised and actors are inside — so you
*should* rotate. But scoring and Orange Team **pull your new passwords from the portal**,
so a sloppy rotation breaks both.

1. **Wait for the password-change inject**, then read its **exact format** (the portal
   ignores anything not matching it, and your change won't register).
2. **Rotate the relevant accounts** (service/auth users that the scorer and Orange Team
   use). **Do not** change the primary auto-login user.
3. **Submit the new credentials via the portal inject in the exact format**, as a PDF if
   required.
4. **Rate limit:** roughly **one change per 30 minutes**. **Do not script bulk/rapid
   changes** — spamming the portal is a **DQ** risk.
5. **Verify:** within ~5 min, SSH/web checks should stay green (scorer logged in with the
   new password) and Orange Team can still log into the operations portal.

> If the scorer's SSH check uses a password, **keep `PasswordAuthentication on`** unless an
> inject tells you to go key-only.

---

## Runbook 6 — Inject discipline (worth 35%)

- **Monitor the Injects tab constantly** — rolling assignment, no notifications.
- **Every inject needs a PDF response.** No PDF this year = **not graded**. Even "we didn't
  get to this one" must be submitted as a PDF.
- **Write every response as a business memo:** address it to the sender (the Task Force /
  CEO), sign as Team 76 IT/IR staff, keep it professional, and (small bonus) play to the
  RR Intel theme. Memes score zero.
- **Watch due dates.** Missed due = zero, no late credit. Submit *something* before the
  deadline even if incomplete.

### Per-inject playbooks

**Incident Response** — see Runbook 4. Report **active/polling** connections (C2 + exfil
webhook + any staging/SSH source IPs). Name the C2 IP and implant service/file to recover
Red-Team penalty points.

**Network Map** — scan **only your own** boxes. Deliverable is **not** raw nmap output:
- Show **dependencies** (web → DB; everything → DC for AD and → DNS).
- **Differentiate scored/critical services** from "every open port."
- Include IPs, DNS records, roles. Format it as a clean, readable diagram/table.
- Never scan the gateway, other teams, or Red Team infra (DQ).

**Install Desktop Environment + set background** — easiest inject. Install the DE, set the
requested background, then **write a memo** ("we completed X") and **include a screenshot**.
A screenshot alone loses the memo/theming points.

**Domain Membership (join both Linux boxes to `rrintel.internal`)**:
- Use **realmd + SSSD** (the *realm* tool — not the C2).
- Authenticate with the **DOMAIN ADMIN** account, not the local user — pattern like
  `domainadmin@rrintel.internal` against the DC IP.
- If you hit Kerberos crypto errors, fix them on the DC **or** in the local `krb5.conf`.
- Show the successful join in your memo.

**New Admin / SSH pubkey auth to Windows** (no team has solved this in 3 years — be the
first):
- **Install OpenSSH** on the target.
- Add the user to the domain **and** the **Domain Admins** group (and show it).
- Ensure the box is **properly domain-joined** (ties to the domain-membership inject).
- **Key location is everything:**
  - **Windows:** all admins share **`C:\ProgramData\ssh\administrators_authorized_keys`**
    (NOT the user's home `.ssh`). Fix owner/permissions: **SYSTEM + Administrators only**;
    **remove "Authorized Users"** or sshd errors out; root/world-writable = fail.
  - **Linux:** put the key in the **domain user's** `.ssh/authorized_keys`, not a local
    account's, with correct ownership and not world-writable.
- Read Microsoft's OpenSSH docs on what's **different for administrators**.

**Final Report** — executive briefing for a board:
- **Executive summary.**
- **Security issues found, each with a severity/impact ranking** (this is what most teams
  miss — say which are critical vs minor and why).
- **Remediation** for each.
- **Future recommendations** ("if we had more time / next priorities").
- **List the injects you completed.** Include pictures + technical detail.
- Target **both technical and non-technical** readers.
- **Do NOT** paste your scoring report verbatim — talk in big ideas (unauthorized users,
  malware), not "I set registry key X."

---

## Runbook 7 — Revert decision (you have 4 total)

- A revert restores the box to its **original (already-compromised) state, powered off,
  zero CCS points.** You then power it on and re-harden from scratch.
- **You lose all CCS points and all your work on that box.** Service points and SLA points
  are **NOT** reset.
- You cannot take new snapshots; you can revert as many times as allowed, but **>4 total =
  penalty** (calculated after the event, not shown live).
- **A revert may not fix a down service** if the cause is a dependency on another box (DNS/
  AD/DB elsewhere).

**Use a revert when:** the box is so compromised (e.g. persistent rootkit you can't clear)
that the time to clean it exceeds the value of the CCS points you'd lose, and you can
re-harden faster than Red Team can re-own. Otherwise, **clean in place** — you keep your
CCS points that way.

---

## Quick command index

| Need | Command |
|---|---|
| Baseline only | `sudo ./scripts/first5_secure.sh --baseline-only` |
| Safe harden | `sudo ./scripts/first5_secure.sh` |
| Audit | `sudo ./scripts/audit_linux.sh` |
| Hunt malware | `sudo ./scripts/hunt_malware.sh --baseline baselines/<host>_<ts>` |
| Clean-build diff | `sudo ./scripts/build_golden_baseline.sh --compare baselines/golden/<ref>` |
| Understand scoring | `sudo ./scripts/scoring_recon.sh --window 15` |
| Egress lockdown | `sudo ./scripts/defend_redteam.sh egress-lockdown` |
| Block one bad IP | `sudo ./scripts/defend_redteam.sh block <ip>` |
| Live monitor | `sudo ./scripts/watch_services.sh --baseline baselines/<host>_<ts>` |
