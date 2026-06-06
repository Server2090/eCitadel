# BASIC HARDENING SHEET (+ how to use it)

**Team 76 · RR Intel / eCitadel Season IV**

The fast, **safe** wins — the things that earn CCS/hardening points and shut common doors
**without** breaking a scored service. This sheet is both the checklist *and* its own
README: each section says what to do and which tool does it for you.

> **The "won't break anything" script is `scripts/first5_secure.sh`.** It applies only
> reversible, non-breaking hardening, backs up every file it edits, and **reports** (never
> auto-runs) the risky stuff. Preview it first with `--dry-run`:
> ```bash
> sudo bash scripts/first5_secure.sh --dry-run     # shows every change, modifies nothing
> sudo bash scripts/first5_secure.sh               # apply the safe pass + capture a baseline
> sudo bash scripts/first5_secure.sh --aggressive  # also auto-fix the SAFE subset (still scoring-safe)
> ```
> Windows DC equivalent: `windows/Harden-DC.ps1 -DryRun` then `windows/Harden-DC.ps1`.
> pfSense: follow `pfsense/PFSENSE_HARDENING.md`.

---

## 0) The 5-minute "do not skip these" (all platforms)

- [ ] Log into every box; confirm the scoreboard is **green** before you change anything.
- [ ] **Capture a baseline first** so you can prove what changed:
      `sudo bash scripts/first5_secure.sh --baseline-only` (Linux) /
      `.\Harden-DC.ps1 -BaselineOnly` (DC).
- [ ] **Back up the web docroot and the pfSense config** (Red Team deletes content later).
- [ ] Don't change any **IP**, the **primary auto-login user's password**, or stop a
      **scored service** (SSH / HTTP / DNS / RDP / WinRM / the DB).

---

## 1) Linux easy wins — `concierge` (Fedora 43) & `blacklist` (Debian 13)

All of these are done by `first5_secure.sh` unless marked **(manual)**.

- [ ] **Disable root SSH login** and **empty-password SSH** (keeps password auth ON for the
      scorer). *(SSH drop-in, validated with `sshd -t`, reloaded — never restarted.)*
- [ ] **Password policy:** max-age 90, min length + complexity (`login.defs`, `pwquality`).
- [ ] **Network sysctls:** `ip_forward=0`, reverse-path filter on, syncookies on, ignore
      bogus ICMP, no redirects/source-routing.
- [ ] **Automatic security updates** on (`dnf-automatic` / `unattended-upgrades`).
- [ ] **Run the package updates** once: `sudo dnf upgrade -y` / `sudo apt update && sudo apt upgrade -y`.
- [ ] **Host firewall** that **allows the listening + scored ports FIRST, then default-denies
      inbound** (never blocks the rotating scorer). *(Skip with `--no-firewall` if pfSense
      already filters.)*
- [ ] **Lock empty-password accounts** / **disable mail+discovery services** (postfix,
      dovecot, exim4, sendmail, telnet, cups, avahi, rpcbind) / **remove prohibited tools**
      (nmap, wireshark, …). *(Automated only under `--aggressive`; otherwise listed for you.)*
- [ ] **(manual)** Delete unauthorized users after checking the README's user list:
      `sudo userdel -r <user>`. Never bulk-delete.
- [ ] **(manual)** Remove planted media/games the README bans (review first; don't delete
      business files).
- [ ] **Then audit + hunt:** `sudo bash scripts/audit_linux.sh` and
      `sudo bash scripts/hunt_malware.sh` — fix every `[FAIL]`/`[HIGH]`.

---

## 2) Windows DC easy wins — `cabal` (Server 2022)

Done by `windows/Harden-DC.ps1` unless marked **(manual)**. Run elevated.

- [ ] **RDP stays enabled** (scored) but **requires NLA**.
- [ ] **SMBv1 disabled** (SMBv2/3 stay on for AD).
- [ ] **Windows Firewall on**, with the **DNS / AD / RDP / WinRM rule groups enabled** and
      explicit allows for 53/3389/5985/5986. *(No blanket inbound-deny on the Domain
      profile — that cascade-fails AD.)*
- [ ] **Domain password policy:** min 14, complexity, 60-day max, 24 history.
- [ ] **Defender real-time protection ON**, **Guest disabled**, **audit logging ON**
      (logon, account management, process creation).
- [ ] **(aggressive)** Block inbound on the **Public** profile only; **disable Print
      Spooler** (PrintNightmare surface, not scored).
- [ ] **(manual)** Do **not** set a tight account-lockout policy — it can lock the scorer out.
- [ ] **Then hunt:** `.\Hunt-DC.ps1` — clear any IFEO/AppInit/LSA/WMI/backdoor-admin finding.

---

## 3) pfSense easy wins — `thebox`

From `pfsense/PFSENSE_HARDENING.md`:

- [ ] **WAN inbound:** allow **only** the scored ports (source = any; the scorer's IP
      rotates), default-deny the rest. **No WAN access to the pfSense GUI/SSH.**
- [ ] **LAN outbound:** allow box-to-box + DNS + gateway, **block the rest** (perimeter
      egress-lockdown that kills C2/exfil). Open 80/443 out only while updating, then close.
- [ ] **GUI over HTTPS, LAN-only, anti-lockout rule on.**
- [ ] **Download the config backup** (instant restore point — cheaper than a revert).
- [ ] **(careful)** Change the default admin password; if a check uses it, submit the new
      one via the inject in the exact format.

---

## 4) Browser & web-console settings (the console you use, and any browser on the boxes)

You run the competition through a **web console + the operations portal**. Two angles:

**A. The browser *you* use for the console/portal**
- [ ] Use **Chrome** — Firefox is buggy in the competition console; VMRC is unsupported.
- [ ] **Keep it updated** and use a **fresh/separate profile** for the competition (don't
      mix with personal logins).
- [ ] **Don't let a shared browser save** the portal or box passwords; if the machine is
      shared with teammates, clear saved passwords / use a private window for sensitive logins.
- [ ] Turn on **HTTPS-Only mode** and **Safe Browsing**; only enter portal creds on the real
      portal URL (watch for phishing-style injects).
- [ ] **Review extensions** — disable anything you don't recognize (a malicious extension can
      read everything you type into the console/portal).
- [ ] **Don't reuse** the portal/box passwords anywhere else; assume shared defaults are
      already compromised and rotate them via the inject.
- [ ] Keep the **operations portal** open in a tab and **reply to Orange-Team tickets
      promptly** — that's ~10% of your score, and their logins use the passwords you submit.

**B. Any browser installed *on the boxes* (e.g. Chromium/Firefox on the Linux hosts)**
- [ ] If a browser is a **required package** for the year (past years required Chromium /
      lynx), **do not remove it** — that loses points.
- [ ] **(manual)** Check for tampering an attacker may have left: a forced **homepage/start
      page**, a **proxy** pointing through attacker infrastructure, or **unknown extensions**.
      On Linux look under the user profile (e.g. `~/.config/chromium`, `~/.mozilla`); on the
      DC check system proxy (`netsh winhttp show proxy`) and browser policies.
- [ ] **(manual)** Clear any **saved credentials** in a box's browser profile — those are
      exactly what an attacker would harvest.
- [ ] **(manual)** Make sure no browser is configured to **auto-download/auto-run** files.

---

## 5) What NOT to touch (so you don't lose points)

- Don't change a **VM's IP** or the **primary auto-login user's password**.
- Don't **stop/remove** sshd, the web server, the database, DNS, RDP, or WinRM.
- Don't **default-deny inbound** before allowing the scored ports; don't **block a subnet**
  or **filter inbound by IP** (you'll ban the rotating scorer).
- Don't disable **SSH password auth** unless an inject says key-only.
- Don't **bulk-delete users** or delete files you haven't confirmed are unauthorized.
- Don't **revert** unless necessary — only 4, and it wipes your CCS points on that box.

---

### Where each piece lives
| Platform | Script / doc |
|---|---|
| Linux safe hardening | `scripts/first5_secure.sh` (`--dry-run`, `--aggressive`) |
| Linux audit / hunt | `scripts/audit_linux.sh`, `scripts/hunt_malware.sh` |
| Windows DC | `windows/Harden-DC.ps1`, `windows/Hunt-DC.ps1`, `windows/README_WINDOWS.md` |
| pfSense | `pfsense/PFSENSE_HARDENING.md` |
| Scoring / blocking strategy | `docs/HOW_SCORING_WORKS.md`, `docs/BLOCKING_THE_RED_TEAM.md` |
| Step-by-step play | `playbooks/RUNBOOKS.md` |
