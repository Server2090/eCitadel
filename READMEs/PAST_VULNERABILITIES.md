# PAST VULNERABILITIES & RED-TEAM TTPs — eCitadel Team 76

This is the master list of **every vulnerability, misconfiguration, and Red-Team
technique** seen in eCitadel's practice answer keys (Alma 9, Mint 21, Win 2016)
and the published 2024/2025 challenge repos and incident reports. For each item
you get: **what it is → how to FIND it → how to FIX it → why it matters**, plus
the **do-NOT-break** caveat where one applies.

> The practice boxes were Alma 9 / Mint 21 / Win 2016. Your **actual** boxes are
> **Fedora 43 (`concierge`, web)**, **Debian 13 (`blacklist`, DB)**, and
> **Windows Server 2022 (`cabal`, DC)**. The *categories* below carry over 1:1;
> only the exact commands differ (Fedora = `dnf5`/`firewalld`, Debian =
> `apt`/`nftables`/`ufw`). Version-specific commands are called out inline.

> **Golden rule for every "fix" here:** confirm against *this year's* README
> first. Several services that look like findings (FTP, the database, the web
> app, DNS) may be **required and scored** — stopping them loses you points.

---

## PART 1 — RED-TEAM TECHNIQUES (from real published Incident Reports)

The Red Team is **automated** and uses **pre-planted malware** that activates on
a timeline. Recovering points after they hit requires filing an **Incident
Report** (see `playbooks/RUNBOOKS.md`). These are the techniques they have
actually used, with the **Linux equivalents you must hunt** (`hunt_malware.sh`
checks every one).

| # | Past technique (observed) | Linux equivalent to hunt | Find it with | Remediate |
|---|---|---|---|---|
| R1 | **Sliver C2 implant** (e.g. a hidden `.clihost.exe` beaconing out) | Hidden ELF beacon in `/tmp`, `/dev/shm`, `/var/tmp`, or a dotfile binary in a home dir; periodic outbound connection | `hunt_malware.sh` → "Network" + "tmp/shm executables" + "deleted binary" checks; `ss -tnp state established` | Document src/dst IP for IR, kill the PID, delete the binary, then `defend_redteam.sh block <c2-ip>` |
| R2 | **Malicious password-filter DLL** stealing credentials, exfil to a **Discord webhook** | Rogue `pam_*.so` not owned by a package, or a `pam_exec`/`pam_python` line running a script | `hunt_malware.sh` → "PAM tampering" (diffs `/etc/pam.d` vs baseline; flags unpackaged modules) | Restore PAM from baseline, remove the rogue module, rotate all passwords |
| R3 | **Exfiltration to an external webhook/host** | Any established connection to a non-private IP; suspicious `curl`/`wget` in cron or a shell rc | `hunt_malware.sh` → "Network", "cron", "shell hooks"; watch with `watch_services.sh` | Block the egress IP (`defend_redteam.sh block`), remove the calling job |
| R4 | **Service disruption** (Red Team stops a scored service / deletes web content) | A scored service stopped; web root files deleted/defaced | `watch_services.sh` flags the service DOWN within one cycle | Restart the service, restore content from your baseline copy, file an IR |
| R5 | **Persistence to survive password resets** | `authorized_keys` backdoor key, new cron/timer, new UID-0 user, SUID backdoor | `hunt_malware.sh` → keys/cron/SUID checks; `watch_services.sh` drift alerts | Remove the artifact; this is why rotating passwords **alone** is not enough |

**Rule 6.1:** you lose points if the Red Team maintains persistence. Hunting and
removing R5-style footholds is as important as the initial hardening.

---

## PART 2 — RHEL-FAMILY FINDINGS  (Alma 9 key → applies to **Fedora 43 `concierge`**)

### F1. Forensics questions (answer, don't "fix")
- **What:** Graders ask things like "what is the first line of `ps -ef`?" or "what
  is the FTP server's `220` banner?" These are *scavenger-hunt* points.
- **Find:** `ps -ef | head -1`; for an FTP banner `ftp localhost` or
  `nc localhost 21` and read the `220` line; capture everything in your baseline.
- **Why:** Free points if you simply read the system. `first5_secure.sh` snapshots
  `processes.txt` so the answer is already on disk.

### F2. Unauthorized user accounts
- **What:** Accounts that are not in the README's authorized-user list.
- **Find:** `awk -F: '($3>=1000 && $3<65534)||$7~/sh$/{print $1, $3, $7}' /etc/passwd`
  (or read `baselines/.../login_users.txt`).
- **Fix:** `sudo userdel -r <user>` **after** confirming the account is truly
  unauthorized.
- **Why:** Extra accounts are both a scored finding and a Red-Team backdoor.
- **DO NOT:** delete the primary auto-login user or any required service account.

### F3. Password aging too lax (`PASS_MAX_DAYS`)
- **What:** `PASS_MAX_DAYS` set to `0` or `99999` (passwords never expire).
- **Find:** `grep PASS_MAX_DAYS /etc/login.defs`.
- **Fix:** set `PASS_MAX_DAYS 90` (also `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7`).
  Applied safely by `first5_secure.sh`.
- **Why:** Standard CIS hardening; recurring scored item.

### F4. Weak / missing password complexity
- **What:** No minimum length or complexity enforced (`pwquality`).
- **Find:** `grep -E 'minlen|cred' /etc/security/pwquality.conf`.
- **Fix:** `minlen = 14`, `dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1`. (Editing
  `pwquality.conf` is safe — it does **not** touch the PAM stack that can lock
  you out.) Applied by `first5_secure.sh`.

### F5. Host firewall disabled (`firewalld`)
- **What:** `firewalld` not running.
- **Find:** `systemctl is-active firewalld`.
- **Fix:** enable it **after** allow-listing every listening + scored port
  (`first5_secure.sh` does exactly this so nothing scored gets blocked).
- **Why:** A scored item *and* your first line of defense.

### F6. Unnecessary mail / network services running
- **What:** `postfix`, `dovecot`, `sendmail`, `telnet`, SMB, SNMP, etc. running
  with no business reason.
- **Find:** `systemctl is-active postfix dovecot ...` (audit script lists them).
- **Fix:** `sudo systemctl disable --now <svc>`.
- **DO NOT:** stop `sshd`, `httpd`/the web app, the DB, or `vsftpd` if FTP is
  scored. Check the README's service list first.

### F7. Automatic security updates not configured (`dnf-automatic`)
- **What:** `dnf-automatic` not installed/enabled, or `apply_updates = no`.
- **Find (Fedora 43):** `systemctl is-enabled dnf5-automatic.timer` and
  `grep apply_updates /etc/dnf/automatic.conf`.
- **Fix (Fedora 43 / dnf5):** `sudo dnf install -y dnf-automatic`; set
  `apply_updates = yes` in `/etc/dnf/automatic.conf`; then
  **`sudo systemctl enable --now dnf5-automatic.timer`** (note the **`dnf5-`**
  prefix on Fedora 43 — the old `dnf-automatic.timer` name is from earlier
  Fedora/RHEL). Done by `first5_secure.sh`.
- **Why:** Scored item; the timer fires on its own schedule so it will not
  surprise-upgrade a service mid-check.

### F8. Outdated packages
- **What:** Known-vulnerable package versions installed.
- **Find:** `dnf check-update`.
- **Fix:** `sudo dnf upgrade -y` **between** scoring checks, then immediately
  verify every scored service still answers (`watch_services.sh`).
- **Why:** Closes published CVEs. Time it carefully — a big upgrade can restart
  services.

### F9. Prohibited tools present
- **What:** Recon/attack tools (`nmap`, `wireshark`, `zenmap`, etc.) the README
  bans on a server.
- **Find:** `command -v nmap wireshark ...` (audit script lists them).
- **Fix:** `sudo dnf remove -y <tool>`.
- **DO NOT:** remove things the README explicitly keeps (past keys kept `lynx`,
  `php`, the web app/WordPress). Remove only what's prohibited.

### F10. SSH `PermitRootLogin yes`
- **What:** Root can log in over SSH directly.
- **Find:** `sshd -T | grep -i permitrootlogin`.
- **Fix:** `PermitRootLogin no` via a drop-in, then `sshd -t && systemctl reload sshd`.
  Applied by `first5_secure.sh`.
- **DO NOT:** also flip `PasswordAuthentication off` unless an inject requires
  key-only — the scorer's SSH check most likely uses a password.

### F11. FTP anonymous access (`vsftpd`)
- **What:** `anonymous_enable=YES` in `vsftpd.conf`.
- **Find:** `grep -i anonymous_enable /etc/vsftpd/vsftpd.conf`.
- **Fix:** set `anonymous_enable=NO`, then `systemctl restart vsftpd`.
- **DO NOT:** stop/disable `vsftpd` itself if FTP is a scored service — only
  disable the anonymous setting.

---

## PART 3 — DEBIAN-FAMILY FINDINGS  (Mint 21 key → applies to **Debian 13 `blacklist`**)

### D1. Forensics questions
- **What:** e.g. "first table from `SHOW TABLES;`" or "absolute path of an `.mp3`."
- **Find:** for DB, `mysql -e 'SHOW TABLES;' <db>` (or `mariadb`); for files,
  `find / -iname '*.mp3' 2>/dev/null`.
- **Why:** Free points; baseline captures most of it.

### D2. Unauthorized user accounts
- Same as **F2**. Find via `/etc/passwd` / `login_users.txt`; fix with
  `userdel -r` after confirming. Don't remove the primary user or service
  accounts.

### D3. Weak password policy / minimum length
- **What:** No minimum length enforced.
- **Find:** `grep minlen /etc/security/pwquality.conf`.
- **Fix (Debian 13):** `apt-get install -y libpam-pwquality` if missing, set
  `minlen = 14` in `/etc/security/pwquality.conf`. Safe; applied by
  `first5_secure.sh`. (Debian 13 uses **`pam_pwquality`** — editing the conf
  file avoids risky PAM-stack edits.)

### D4. IPv4 forwarding enabled
- **What:** `net.ipv4.ip_forward = 1` on a box that is not a router.
- **Find:** `sysctl net.ipv4.ip_forward`.
- **Fix:** set `net.ipv4.ip_forward = 0` in `/etc/sysctl.d/99-ecitadel.conf`,
  then `sysctl --system`. Applied by `first5_secure.sh`.
- **Why:** Recurring scored item; a server shouldn't route traffic.

### D5. Host firewall disabled (`ufw`)
- **What:** `ufw` inactive.
- **Find:** `ufw status`.
- **Fix:** allow SSH **first** (`ufw allow 22/tcp`), allow every scored/listening
  port, then `ufw --force enable`. `first5_secure.sh` does this in the safe
  order. (Debian 13's firewall backend is **nftables**; `ufw` drives it fine.)

### D6. Unnecessary services (`dovecot`/POP3, etc.)
- Same shape as **F6**. Find with `systemctl is-active dovecot ...`; disable with
  `systemctl disable --now <svc>`. **Do NOT** stop `sshd` or MariaDB.

### D7. Security update source disabled
- **What:** The `*-security` apt source is commented out / disabled.
- **Find:** `grep -r security /etc/apt/sources.list /etc/apt/sources.list.d/`.
- **Fix:** re-enable the security line, `apt-get update`, then install
  `unattended-upgrades` and enable it (`first5_secure.sh`).
- **Why:** Scored item; without it you can't pull security patches.

### D8. Outdated packages
- **Find:** `apt-get update && apt-get -s upgrade | grep ^Inst`.
- **Fix:** `apt-get upgrade -y` between checks; re-verify services after.

### D9. Prohibited files / media
- **What:** `.mp3` and similar non-work media; sometimes prohibited apps
  (past key: `gameconqueror`, `manaplus`).
- **Find:** `find /home /root -iname '*.mp3' ...` (audit lists candidates).
- **Fix:** `rm '<path>'` for non-business files; `apt-get remove -y <pkg>` for
  prohibited apps.
- **DO NOT:** delete legitimate business documents or remove `chromium` (past
  key explicitly kept it; some apps are required).

### D10. SSH `PermitEmptyPasswords yes`
- **What:** Empty passwords accepted over SSH.
- **Find:** `sshd -T | grep -i permitemptypasswords`.
- **Fix:** `PermitEmptyPasswords no` via drop-in, reload sshd. Applied by
  `first5_secure.sh`.

### D11. Browser / app pop-up & misc config items
- **What:** Practice keys included desktop-app settings (e.g. Chromium pop-up
  blocking). On a headless server these usually don't apply, but if `concierge`
  ends up with a desktop (an inject sometimes asks you to *install* one), apply
  the same idea: enable security prompts, disable auto-run of untrusted content.

---

## PART 4 — WINDOWS FINDINGS  (Win 2016 key → applies to **Windows Server 2022 `cabal`, DC**)

These are **Linux-team-adjacent** — included so you can coordinate, since `cabal`
is the domain controller your web auth depends on. (Ask me to generate a full
PowerShell hardening pack for `cabal` if you want it.)

| Area | Past finding | Fix direction |
|---|---|---|
| Accounts | Unauthorized local/domain users; users in Administrators | Remove unauthorized accounts; audit `Administrators`/`Domain Admins` |
| Password policy | No min length / complexity / lockout | Set domain password + lockout policy via Group Policy |
| Services | Unnecessary roles/features, SMBv1 enabled | Disable SMBv1, remove unneeded features |
| RDP | Weak RDP exposure | Restrict RDP, require NLA |
| Updates | Missing Windows updates | Apply updates; configure WSUS/Automatic Updates |
| Defender / firewall | Disabled AV or Windows Firewall | Re-enable Defender + Windows Firewall |
| Malware (R2) | Malicious password-filter DLL exfil to Discord | Remove the DLL from `Notification Packages` in LSA registry; rotate creds |
| DNS | DC is the DNS server (scored) — don't break it | Keep DNS role healthy; it's a scored service |

---

## PART 5 — HARDENING DONE IN THE PAST (the "good config" checklist)

This is the positive version of the list — the end-state a well-hardened box
should reach. `audit_linux.sh` checks each one and reports PASS/FAIL.

1. **SSH:** root login off, empty passwords off, modern protocol, sane
   `MaxAuthTries`/`LoginGraceTime` — **but password auth left ON** for the scorer.
2. **Accounts:** exactly one UID-0 (root); only README-authorized login users;
   no empty-password accounts; admin groups (`sudo`/`wheel`) match the README.
3. **Passwords:** `PASS_MAX_DAYS 90`, `pwquality minlen 14` + complexity.
4. **Firewall ON** with an explicit allow-list of scored/listening ports and a
   default-deny for everything else inbound.
5. **Kernel:** `ip_forward=0`, `tcp_syncookies=1`, no source routing / redirects.
6. **Updates:** automatic security updates enabled (`dnf5-automatic.timer` /
   `unattended-upgrades`); packages patched between checks.
7. **Services:** only required/scored services running; mail/SMB/telnet/etc. off
   unless the README needs them.
8. **No prohibited tools or media** on the box.
9. **Service configs hardened in place** (e.g. FTP anonymous off) **without
   stopping the scored service**.
10. **No persistence footholds:** clean `authorized_keys`, cron, timers, PAM,
    SUID set, and `ld.so.preload`.
11. **All passwords rotated** at the start (assume every credential is
    compromised) — and **submitted via the password-change inject** in the exact
    required format. Do **not** change the primary auto-login user's password or
    any VM's IP.

---

### How the scripts map to this document
- `first5_secure.sh` — auto-applies the **safe** subset of Parts 2–3 and 5
  (items it can't safely automate are printed as a TODO list).
- `audit_linux.sh` — checks **every** Part 2/3/5 item, PASS/FAIL, read-only.
- `hunt_malware.sh` — hunts **every** Part 1 technique, read-only.
- `defend_redteam.sh` — blocks Part 1 C2/exfil safely.
- `watch_services.sh` — catches Part 1 disruption + persistence drift live.
