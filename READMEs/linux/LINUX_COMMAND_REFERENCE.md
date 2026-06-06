# LINUX COMMAND REFERENCE — eCitadel Team 76

Commands grouped by **what you're trying to do**, with **when to use** each and
the **Fedora 43 vs Debian 13** difference where it matters. Run most of these
with `sudo`. This is the "I need the command right now" sheet.

> Fedora 43 = `dnf5` + `firewalld`. Debian 13 = `apt` + `nftables`/`ufw`.
> systemd (`systemctl`, `journalctl`) is identical on both.

---

## 1. Situational awareness (run these first)
| Command | When to use |
|---|---|
| `cat /etc/os-release` | Confirm which distro/version you're on |
| `hostname -s; ip -br addr; ip route` | Confirm hostname, IPs, gateway (verify IP unchanged) |
| `ss -tulnp` | See every listening service + owning process (what's exposed) |
| `ss -tnp state established` | See active connections (hunt for external C2) |
| `ps auxww` / `ps -ef` | Full process list (also answers forensics "first line" Qs) |
| `systemctl list-units --type=service --state=running` | What's actually running |
| `who; w; last -n 20` | Who's logged in / recent logins |
| `uptime; free -h; df -h` | Load, memory, disk (spot a miner or disk-fill) |

---

## 2. Users & accounts
| Command | When to use |
|---|---|
| `awk -F: '($3>=1000&&$3<65534)\|\|$7~/sh$/{print $1,$3,$7}' /etc/passwd` | List login-capable users to compare to README |
| `awk -F: '$3==0{print $1}' /etc/passwd` | Find UID-0 accounts (should be only `root`) |
| `sudo awk -F: '($2==""){print $1}' /etc/shadow` | Find empty-password accounts |
| `getent group sudo` / `getent group wheel` | See admin-group members (Debian uses `sudo`, Fedora `wheel`) |
| `sudo userdel -r <user>` | **Remove** an unauthorized account (confirm first; `-r` removes home) |
| `sudo passwd -l <user>` | Lock an account without deleting it (safer if unsure) |
| `sudo passwd <user>` | Set/rotate a user's password |
| `sudo chage -l <user>` | View password-aging for a user |
| `grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` | Find sudo backdoors |
| `sudo visudo` / `sudo visudo -f /etc/sudoers.d/x` | Safely edit sudoers (validates syntax) |

---

## 3. SSH hardening
| Command | When to use |
|---|---|
| `sshd -T` | Print the **effective** sshd config (honors drop-ins) — use to verify settings |
| `sshd -T \| grep -iE 'permitrootlogin\|permitempty\|passwordauth'` | Check the key scored settings |
| edit `/etc/ssh/sshd_config.d/00-ecitadel-hardening.conf` | Put hardening in a drop-in (easy to remove) |
| `sudo sshd -t` | **Validate** config BEFORE applying (never skip this) |
| `sudo systemctl reload ssh` (Debian) / `reload sshd` (Fedora) | Apply config **without** dropping sessions |
| `sudo systemctl status ssh sshd` | Check SSH is healthy after changes |

> Safe settings: `PermitRootLogin no`, `PermitEmptyPasswords no`. **Leave
> `PasswordAuthentication yes`** unless an inject says key-only.

---

## 4. Firewall
### Fedora 43 — firewalld
| Command | When to use |
|---|---|
| `systemctl is-active firewalld` | Check it's running |
| `sudo systemctl enable --now firewalld` | Turn it on |
| `sudo firewall-cmd --list-all` | See current allowed services/ports |
| `sudo firewall-cmd --permanent --add-service=ssh` | Allow SSH (do this first!) |
| `sudo firewall-cmd --permanent --add-port=80/tcp` | Allow a scored port |
| `sudo firewall-cmd --reload` | Apply permanent rules |
| `sudo firewall-cmd --permanent --remove-port=23/tcp` | Close a port |

### Debian 13 — ufw (simplest) / nftables (backend)
| Command | When to use |
|---|---|
| `ufw status verbose` | See current rules |
| `sudo ufw allow 22/tcp` | Allow SSH (FIRST, before enabling) |
| `sudo ufw allow 3306/tcp` | Allow a scored port |
| `sudo ufw default deny incoming` | Default-deny inbound (after allowing scored ports) |
| `sudo ufw --force enable` | Turn the firewall on |
| `sudo ufw delete allow 23/tcp` | Remove a rule |
| `sudo nft list ruleset` | Inspect the raw nftables ruleset (advanced) |

---

## 5. Services (systemd — same on both)
| Command | When to use |
|---|---|
| `systemctl status <svc>` | Is it running? why did it fail? |
| `sudo systemctl start <svc>` | **Restore** a service the Red Team stopped |
| `sudo systemctl enable --now <svc>` | Start now + on boot |
| `sudo systemctl disable --now <svc>` | Stop + disable an **unnecessary** service |
| `sudo systemctl reload <svc>` | Re-read config without a full restart |
| `systemctl list-timers --all` | See systemd timers (a persistence spot) |
| `systemctl cat <svc>` | View a unit file (check `ExecStart` for tampering) |

---

## 6. Packages & updates
### Fedora 43 — dnf5
| Command | When to use |
|---|---|
| `dnf check-update` | List upgradable packages |
| `sudo dnf upgrade -y` | Patch everything (do **between** scoring checks; verify services after) |
| `sudo dnf install -y <pkg>` | Install a needed package (e.g. `dnf-automatic`) |
| `sudo dnf remove -y <pkg>` | Remove a prohibited package |
| `rpm -qf <path>` | Which package owns a file (integrity check) |
| `rpm -Va` | Verify all packages vs manifest (find tampered binaries) |
| `sudo systemctl enable --now dnf5-automatic.timer` | Enable auto security updates (**`dnf5-`** prefix on F43) |

### Debian 13 — apt
| Command | When to use |
|---|---|
| `sudo apt-get update` | Refresh package lists |
| `apt-get -s upgrade \| grep ^Inst` | Preview upgradable packages (simulate) |
| `sudo apt-get upgrade -y` | Patch (between checks; verify services after) |
| `sudo apt-get install -y <pkg>` | Install a needed package |
| `sudo apt-get remove -y <pkg>` | Remove a prohibited package |
| `dpkg -S <path>` | Which package owns a file |
| `sudo debsums -ec` | List changed packaged files (install `debsums` first) |

---

## 7. Process & network hunting (malware)
| Command | When to use |
|---|---|
| `ss -tnp state established` | Active connections + PID (find C2) |
| `ss -tulnp` | Listening ports + PID (find backdoor listeners) |
| `ls -l /proc/<pid>/exe` | What binary a PID runs (look for `(deleted)`) |
| `cat /proc/<pid>/cmdline \| tr '\0' ' '` | Full command line of a PID |
| `ls -l /proc/<pid>/cwd` | A process's working directory |
| `lsof -p <pid>` | Files/sockets a process has open |
| `ps -eo pid,ppid,user,%cpu,comm --sort=-%cpu \| head` | Top CPU (spot cryptominers) |
| `sudo kill -9 <pid>` | **Stop** a malicious process (document it for IR first!) |

---

## 8. Persistence inspection
| Command | When to use |
|---|---|
| `cat /etc/crontab; ls -la /etc/cron.*` | System cron (persistence) |
| `for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null; done` | Per-user cron |
| `systemctl list-timers --all` | systemd timer persistence |
| `atq` then `at -c <id>` | Pending `at` jobs |
| `cat ~/.ssh/authorized_keys` (per user) | **Backdoor SSH keys** (survive password changes!) |
| `cat /etc/ld.so.preload` | Library-injection rootkit hook (should be empty) |
| `find / -xdev -perm -4000 -type f 2>/dev/null` | SUID-root binaries (backdoors) |
| `grep -rnE 'pam_exec\|pam_python' /etc/pam.d` | PAM scripts (cred theft) |
| `diff -r <baseline>/pam.d /etc/pam.d` | Detect PAM tampering vs baseline |
| `lsmod` | Loaded kernel modules (rootkits) |
| `grep -rE 'curl\|wget\|/dev/tcp' /etc/profile.d ~/.bashrc` | Reverse-shell hooks in startup files |

---

## 9. Files & permissions
| Command | When to use |
|---|---|
| `find / -xdev -type f -perm -0002 2>/dev/null` | World-writable files |
| `find / -xdev \( -nouser -o -nogroup \) 2>/dev/null` | Orphaned files (possible tampering) |
| `find /home /root -iname '*.mp3' -o -iname '*.mp4' 2>/dev/null` | Prohibited media |
| `find <dir> -type f -mtime -1` | Files changed in the last day (recent drops) |
| `find /tmp /dev/shm /var/tmp -type f -perm -u+x 2>/dev/null` | Executables in temp dirs (malware) |
| `stat <file>` | Timestamps/owner of a suspicious file |
| `sha256sum <file>` | Hash a file (compare to baseline) |
| `file <file>` | What kind of file it is (ELF? script?) |
| `strings -n 8 <file> \| less` | Readable strings in a binary (IPs, URLs, webhooks) |

---

## 10. Logs & forensics (journalctl — same on both)
| Command | When to use |
|---|---|
| `journalctl -u ssh -n 50` (or `sshd`) | Recent SSH activity |
| `journalctl -u <svc> -e` | Why a service crashed |
| `journalctl --since "10 min ago"` | What just happened system-wide |
| `journalctl _COMM=sshd \| grep -i fail` | Failed SSH logins (brute force) |
| `last -n 30; lastb -n 30` | Successful / failed login history |
| `grep -rai 'discord\|webhook\|pastebin' /etc /home /var 2>/dev/null` | Hunt exfil endpoints |

---

## 11. Password rotation (start of round — assume all creds compromised)
| Command | When to use |
|---|---|
| `sudo passwd <user>` | Rotate a single account's password |
| `awk -F: '($3>=1000&&$3<65534){print $1}' /etc/passwd` | List human accounts to rotate |
| `sudo chage -d 0 <user>` | Force a password change at next login (optional) |
| For DB: `ALTER USER 'u'@'host' IDENTIFIED BY 'newpass'; FLUSH PRIVILEGES;` | Rotate MariaDB/MySQL creds (`blacklist`) |

> **Submit each change via the password-change inject in the EXACT required
> format** (it's rate-limited). **Never** change the primary auto-login user's
> password or any VM's IP.

---

## 12. Containment / response (after you've documented for IR)
| Command | When to use |
|---|---|
| `sudo kill -9 <pid>` | Stop a malicious process |
| `rm '<path>'` | Delete a malware file (record its hash + path first) |
| `sudo systemctl disable --now <unit>` | Kill a malicious systemd unit/timer |
| remove the line from `authorized_keys` | Revoke a backdoor SSH key |
| `sudo ./defend_redteam.sh block <c2-ip>` | Block egress+ingress to a confirmed C2 IP (safe) |
| `sudo systemctl start <scored-svc>` | Bring a disrupted scored service back up |

---

### Distro quick-switch cheat
| Task | Fedora 43 | Debian 13 |
|---|---|---|
| Update index | (automatic) | `apt-get update` |
| Upgrade all | `dnf upgrade -y` | `apt-get upgrade -y` |
| Install | `dnf install -y X` | `apt-get install -y X` |
| Remove | `dnf remove -y X` | `apt-get remove -y X` |
| Who owns file | `rpm -qf F` | `dpkg -S F` |
| Verify integrity | `rpm -Va` | `debsums -ec` |
| Firewall | `firewall-cmd` | `ufw` / `nft` |
| Auto-updates unit | `dnf5-automatic.timer` | `unattended-upgrades` |
| SSH service name | `sshd` | `ssh` |
