# MISCONFIGURATIONS & WATCHLIST — eCitadel Team 76

Two jobs:
1. **What to check** — the common misconfigurations, each with a one-line check.
2. **What NOT to break** — the hard rules that cost you points if you trip them.

Keep this open on a second screen during the round.

---

## A. THE "DO NOT BREAK" LIST (read this first, re-read it before every action)

These come straight from the orientation + rules. Breaking one of these is the
fastest way to *lose* points, and it's self-inflicted.

1. **Do NOT stop or remove a scored/required service.** On Linux that means:
   - `sshd` (SSH is scored on **both** Linux boxes),
   - the **web server** on `concierge` (Apache/nginx — HTTP is scored),
   - the **database** on `blacklist` (MariaDB/MySQL — scored dependency),
   - **DNS** (on the DC `cabal`),
   - and **FTP** *if* the README lists it as scored.
   Harden their *config*; never take the service down.
2. **Do NOT turn off `PasswordAuthentication` in SSH** unless an inject
   explicitly says key-only. The scoring engine's SSH check most likely logs in
   with a password — kill that and you fail the SSH check.
3. **Do NOT change any VM's IP address.** Scoring hits fixed external IPs
   (`172.27.76.101/.102/.103`). Change an IP and the scorer can't reach you.
4. **Do NOT change the primary auto-login user's password** (you'll lose console
   access). Rotate *other* users; submit each change via the password inject.
5. **Do NOT block whole subnets** in any firewall. Block **specific** confirmed
   IPs only (`defend_redteam.sh` enforces this).
6. **Do NOT scan or attack** out-of-scope hosts: the upstream router
   (`172.21.1.1`), the pfSense WAN side, the Red Team, other teams, or anything
   that isn't your VM. No offensive operations — it risks **disqualification**.
7. **Do NOT casually revert a VM.** You get only a few reverts before a penalty,
   and a revert **wipes your CCS find-and-fix points**. Treat it as a last
   resort, not a fix.
8. **Do NOT remove packages the README keeps.** Past keys explicitly preserved
   `lynx`, `php`, the web app/WordPress, `chromium`. Remove only what's listed as
   prohibited.
9. **Do NOT let fail2ban (or any auto-ban) catch the scorer.** Use the cautious
   config (`defend_redteam.sh fail2ban`) and watch the banned list.
10. **Do NOT delete files before documenting them** if they're malware — you need
    source/impact details for the Incident Report inject first.

---

## B. COMMON MISCONFIGURATIONS — quick check table

`audit_linux.sh` automates all of these. This table is for eyeballing/odd cases.

| Area | Misconfiguration | One-line check |
|---|---|---|
| SSH | Root login allowed | `sshd -T \| grep -i permitrootlogin` |
| SSH | Empty passwords allowed | `sshd -T \| grep -i permitemptypasswords` |
| SSH | (info) password auth status | `sshd -T \| grep -i passwordauthentication` |
| Accounts | >1 UID-0 account | `awk -F: '$3==0{print $1}' /etc/passwd` |
| Accounts | Empty-password accounts | `sudo awk -F: '($2==""){print $1}' /etc/shadow` |
| Accounts | Unexpected login users | `awk -F: '($3>=1000&&$3<65534)\|\|$7~/sh$/{print $1,$3,$7}' /etc/passwd` |
| Accounts | Unexpected sudo/wheel members | `getent group sudo; getent group wheel` |
| Sudo | NOPASSWD backdoor | `grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` |
| Passwords | Lax max age | `grep PASS_MAX_DAYS /etc/login.defs` |
| Passwords | No min length | `grep minlen /etc/security/pwquality.conf` |
| Firewall (Fedora) | firewalld off | `systemctl is-active firewalld` |
| Firewall (Debian) | ufw off | `ufw status` |
| Kernel | IPv4 forwarding on | `sysctl net.ipv4.ip_forward` |
| Updates (Fedora) | timer off / apply=no | `systemctl is-enabled dnf5-automatic.timer; grep apply_updates /etc/dnf/automatic.conf` |
| Updates (Debian) | unattended-upgrades off | `dpkg -s unattended-upgrades; cat /etc/apt/apt.conf.d/20auto-upgrades` |
| Updates (Debian) | security source disabled | `grep -r security /etc/apt/sources.list*` |
| Packages | Outdated | Fedora `dnf check-update` · Debian `apt-get -s upgrade \| grep ^Inst` |
| Services | Unnecessary daemons | `systemctl is-active postfix dovecot telnet smbd snmpd` |
| FTP | Anonymous enabled | `grep -i anonymous_enable /etc/vsftpd/vsftpd.conf` |
| Files | World-writable files | `find / -xdev -type f -perm -0002 2>/dev/null \| head` |
| Files | Prohibited media | `find /home /root -iname '*.mp3' -o -iname '*.mp4' 2>/dev/null` |
| Tools | Prohibited tools | `command -v nmap wireshark zenmap ncat` |

---

## C. THINGS TO LOOK OUT FOR DURING THE ROUND

### Red-Team behavior (it's automated and timed)
- **Beacons are periodic**, not constant — a one-time clean network check means
  nothing. Re-run `hunt_malware.sh` regularly and keep `watch_services.sh`
  running; it flags new external connections each cycle.
- **They come back.** Persistence (a backdoor key, a cron job, a new UID-0 user)
  lets them return after you change passwords. Removing footholds matters as much
  as the initial reset (Rule 6.1 penalizes persistence).
- **They may flip your fixes back.** A setting you hardened (e.g.
  `PermitRootLogin`) can be reverted by their tooling. Re-run `audit_linux.sh`
  periodically to catch regressions.
- **They disrupt services.** Sudden SSH/HTTP/DNS DOWN in `watch_services.sh` is
  often the Red Team — restart, restore from baseline, file an IR.

### Scoring traps
- **SLA penalty at 5 consecutive misses = 3× points.** At a ~1–2 min cadence
  that's only a few minutes of downtime. The moment `watch_services.sh` shows
  "3 in a row," fix it. **One good check resets the counter.**
- **Each service is scored separately** and SLA windows are non-overlapping —
  don't let one fix distract you while another service is also down.
- **Web uses AD auth.** A static HTML page will **fail** the scored web check.
  Keep the real app + its DC/DNS dependency healthy (`cabal` must be up).
- **SSH is only worth 1 point up** (vs 3 for non-SSH) but its **SLA penalty is
  still 3×** — don't neglect it.

### Inject discipline (35% of your score)
- **Every inject wants a PDF submission.** Writing the fix isn't enough —
  **submit the document.** (See `playbooks/RUNBOOKS.md` for per-inject steps.)
- **Password changes are submitted via a rate-limited inject** in an **exact
  format**. Match the format precisely and don't spam it.
- **Incident Reports** must include: Team #, Source IP(s), Affected System(s),
  Description of Activity & Impact, Mitigation Steps. Only report **active/
  polling** connections to your external IPs — not random noise.

### Self-inflicted-outage watch
- After **any** `dnf upgrade` / `apt upgrade`, immediately confirm every scored
  service still answers (`watch_services.sh --once`). Upgrades can restart or
  reconfigure services.
- After **any** SSH config change, you must have run `sshd -t` (validate) and
  used `reload`, not `restart` — `first5_secure.sh` does this; do the same by
  hand.
- After enabling a firewall, confirm SSH from your jump host still works **before**
  you walk away.

---

## D. PER-BOX QUICK REFERENCE

| Box | OS | Scored | Keep alive no matter what | Family-specific tools |
|---|---|---|---|---|
| `concierge` 172.27.76.102 | Fedora 43 | HTTP, SSH | web server, sshd (+ DNS dep on `cabal`) | `dnf5`, `firewalld`, `firewall-cmd` |
| `blacklist` 172.27.76.101 | Debian 13 | SSH (+ DB dep) | MariaDB/MySQL, sshd | `apt`, `ufw`/`nft` |
| `cabal` 172.27.76.103 | Win 2022 | DNS, RDP/WinRM | DNS role, AD (web auth depends on it) | PowerShell, GPO |
| `thebox` (pfSense) | pfSense | — (firewall) | — | pfSense web UI / `pfctl` |

> Internal `172.21.0.x` ↔ external `172.27.76.x` are the **same** boxes via 1:1
> NAT (team number 76). The scorer hits the **external** `172.27.76.x` IPs.
