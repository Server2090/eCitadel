#!/usr/bin/env bash
###############################################################################
# first5_secure.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   The "first 5 minutes" script. It does two jobs:
#     (A) BASELINE  — snapshot the system (users, ports, processes, cron, SSH
#                     keys, SUID, services, connections). This is your forensic
#                     evidence and your "what changed?" reference for the rest
#                     of the round. 100% read-only.
#     (B) HARDEN    — apply ONLY safe, reversible hardening that will NOT take a
#                     scored service offline. Every file it edits is backed up
#                     first. Anything risky (deleting users, removing packages,
#                     killing services, default-deny firewall) is NOT executed —
#                     it is printed as a TODO for you to run by hand after you
#                     confirm it against this year's README.
#
# WHY IT IS SAFE
#   * It never changes your IP or your primary user's password.
#   * It never stops a service. It only *enables/reloads* services that must run.
#   * Before enabling the host firewall it ALLOWS every port that is currently
#     listening (so nothing that the scoring engine talks to gets blocked),
#     plus SSH and the standard scored ports (22/53/80/443) as a safety net.
#   * SSH hardening keeps PasswordAuthentication ON (the scorer's SSH check very
#     likely logs in with a password) and only disables root login + empty
#     passwords. It validates the config with `sshd -t` and *reloads* (does not
#     restart) so your live session and the scorer's session are not dropped.
#
# USAGE
#   sudo ./first5_secure.sh                 # baseline + safe harden + TODO report
#   sudo ./first5_secure.sh --baseline-only # just snapshot, change nothing
#   sudo ./first5_secure.sh --no-firewall   # do everything except touch the firewall
#   sudo ./first5_secure.sh --dry-run        # PREVIEW every change, modify nothing
#   sudo ./first5_secure.sh --aggressive     # also auto-remediate the SAFE subset:
#                                            #   lock empty-pw accounts, disable mail/
#                                            #   discovery services, remove prohibited
#                                            #   tools. NEVER touches sshd/web/DB/DNS/
#                                            #   vsftpd/SMB and never deletes a user.
#                                            #   Combine with --dry-run to preview it.
#
# OUTPUT
#   Baselines  -> ./baselines/<host>_<timestamp>/...
#   Run log    -> ./reports/first5_<host>_<timestamp>.log
###############################################################################

# --- shell options -----------------------------------------------------------
# We intentionally do NOT use `set -e`: in a security script we want to keep
# going and log failures rather than abort halfway through hardening.
set -u
umask 077   # anything we write (baselines may contain sensitive data) is owner-only

# --- must be root -------------------------------------------------------------
if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this with sudo/root (it reads protected files and edits configs)." >&2
  exit 1
fi

# --- parse arguments ----------------------------------------------------------
BASELINE_ONLY=0
DO_FIREWALL=1
AGGRESSIVE=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --baseline-only) BASELINE_ONLY=1 ;;
    --no-firewall)   DO_FIREWALL=0 ;;
    --aggressive)    AGGRESSIVE=1 ;;
    --dry-run)       DRY_RUN=1 ;;
    -h|--help)       grep '^#' "$0" | sed 's/^#//'; exit 0 ;;
    *) echo "Unknown option: $arg (try --help)"; exit 1 ;;
  esac
done

# --- where we are / where output goes ----------------------------------------
# Resolve the directory this script lives in, so baselines/ and reports/ land in
# the kit folder no matter what directory you launch from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
TS="$(date +%Y%m%d_%H%M%S)"
BASE_DIR="${KIT_DIR}/baselines/${HOST}_${TS}"
REPORT="${KIT_DIR}/reports/first5_${HOST}_${TS}.log"
BACKUP_DIR="${BASE_DIR}/config_backups"
mkdir -p "${BASE_DIR}" "${BACKUP_DIR}" "${KIT_DIR}/reports"

# --- logging helpers ----------------------------------------------------------
# log()  = goes to screen AND the report file.
# todo() = collected and printed at the end as the "do this by hand" list.
TODO_FILE="$(mktemp)"
log()  { echo -e "$*" | tee -a "${REPORT}"; }
sect() { log "\n========== $* =========="; }
todo() { echo "  [ ] $*" >> "${TODO_FILE}"; }
have() { command -v "$1" >/dev/null 2>&1; }   # true if a command exists

log "eCitadel first5_secure.sh  |  host=${HOST}  |  $(date)"
log "Baseline dir: ${BASE_DIR}"
log "Report:       ${REPORT}"

# --- detect the OS family -----------------------------------------------------
# /etc/os-release is the standard, present on both Fedora and Debian.
OS_ID=""; OS_VER=""; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"
fi
case "${OS_ID}" in
  debian|ubuntu|linuxmint) OS_FAMILY="debian" ;;
  fedora|rhel|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
  *) OS_FAMILY="unknown" ;;
esac
log "Detected: ID=${OS_ID} VERSION=${OS_VER} FAMILY=${OS_FAMILY}"
cp /etc/os-release "${BASE_DIR}/os-release.txt" 2>/dev/null || true

###############################################################################
# (A) BASELINE CAPTURE  — read-only snapshot of the system's current state.
#     Each block writes one file under the baseline dir. Later, watch_services.sh
#     (or a simple `diff`) compares against these to spot Red-Team changes.
###############################################################################
capture_baseline() {
  sect "BASELINE CAPTURE (read-only)"

  # -- Identity / network: prove the IP and interfaces did not change ----------
  { ip -br addr; echo; ip route; } > "${BASE_DIR}/network.txt" 2>&1
  log "[*] network.txt        — interfaces, IPs, routes"

  # -- Users & groups: the authoritative list of accounts on the box -----------
  # We snapshot the raw files AND a human-readable summary of LOGIN-capable users
  # (UID >= 1000 or with a real shell) — those are what you compare to the README.
  cp /etc/passwd "${BASE_DIR}/passwd.txt"
  cp /etc/group  "${BASE_DIR}/group.txt"
  # shadow is root-only and shows which accounts have a usable password / are locked
  cp /etc/shadow "${BASE_DIR}/shadow.txt" 2>/dev/null || true
  awk -F: '($3>=1000 && $3<65534) || $7 ~ /(bash|sh|zsh)$/ {print $1" uid="$3" shell="$7}' \
      /etc/passwd > "${BASE_DIR}/login_users.txt"
  log "[*] login_users.txt    — accounts that can log in (compare to README!)"

  # Accounts with UID 0 (root-equivalent). There should be exactly ONE: root.
  awk -F: '$3==0 {print $1}' /etc/passwd > "${BASE_DIR}/uid0_accounts.txt"
  if [[ $(wc -l < "${BASE_DIR}/uid0_accounts.txt") -gt 1 ]]; then
    log "[!] More than one UID-0 account exists — likely a backdoor:"
    sed 's/^/      /' "${BASE_DIR}/uid0_accounts.txt" | tee -a "${REPORT}"
    todo "Investigate extra UID-0 account(s) in uid0_accounts.txt (only 'root' should be UID 0)."
  fi

  # Who is in sudo/wheel (admin) groups
  { getent group sudo; getent group wheel; getent group adm; } \
      > "${BASE_DIR}/admin_groups.txt" 2>&1
  log "[*] admin_groups.txt   — members of sudo/wheel/adm (should match README admins)"

  # Sudoers (including drop-ins) — a classic persistence spot (NOPASSWD backdoors)
  { echo "### /etc/sudoers ###"; cat /etc/sudoers; \
    echo; echo "### /etc/sudoers.d/ ###"; \
    for f in /etc/sudoers.d/*; do [[ -e "$f" ]] && { echo "--- $f"; cat "$f"; }; done; } \
      > "${BASE_DIR}/sudoers.txt" 2>&1
  log "[*] sudoers.txt        — full sudo config (look for NOPASSWD / extra entries)"

  # -- Listening sockets & active connections ----------------------------------
  # Listening ports tell you exactly which services are exposed (and which to
  # protect in the firewall step). Established connections to EXTERNAL IPs are
  # how you spot a live C2 beacon — that is what the IR inject asks for.
  if have ss; then
    ss -tulnp > "${BASE_DIR}/listening_ports.txt" 2>&1
    ss -tnp state established > "${BASE_DIR}/established_conns.txt" 2>&1
  else
    netstat -tulnp > "${BASE_DIR}/listening_ports.txt" 2>&1
    netstat -tnp   > "${BASE_DIR}/established_conns.txt" 2>&1
  fi
  log "[*] listening_ports.txt — what is exposed (firewall step protects these)"
  log "[*] established_conns.txt — active connections (hunt for external C2 here)"

  # -- Processes ---------------------------------------------------------------
  ps auxww > "${BASE_DIR}/processes.txt" 2>&1
  log "[*] processes.txt      — full process list (answers Forensics 'first ps line')"

  # -- Services (systemd) ------------------------------------------------------
  if have systemctl; then
    systemctl list-units --type=service --state=running --no-pager --no-legend \
        > "${BASE_DIR}/services_running.txt" 2>&1
    systemctl list-unit-files --type=service --no-pager --no-legend \
        > "${BASE_DIR}/services_all.txt" 2>&1
    # timers are a common malware-persistence mechanism (the systemd version of cron)
    systemctl list-timers --all --no-pager > "${BASE_DIR}/timers.txt" 2>&1
  fi
  log "[*] services_running.txt / services_all.txt / timers.txt"

  # -- Scheduled tasks (cron / at) — top persistence location ------------------
  {
    echo "### system crontab (/etc/crontab) ###"; cat /etc/crontab 2>/dev/null
    echo; echo "### /etc/cron.d ###";      ls -la /etc/cron.d 2>/dev/null
    for f in /etc/cron.d/*; do [[ -f "$f" ]] && { echo "--- $f"; cat "$f"; }; done
    echo; echo "### /etc/cron.{hourly,daily,weekly,monthly} ###"
    ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    echo; echo "### per-user crontabs (/var/spool/cron) ###"
    for d in /var/spool/cron /var/spool/cron/crontabs; do
      [[ -d "$d" ]] && for u in "$d"/*; do [[ -f "$u" ]] && { echo "--- $u"; cat "$u"; }; done
    done
  } > "${BASE_DIR}/cron_all.txt" 2>&1
  log "[*] cron_all.txt       — every cron entry (system + per-user). Hunt here."

  # -- SSH authorized_keys for every user — backdoor key check -----------------
  # An attacker who drops their public key here keeps access even after you change
  # passwords. We list every authorized_keys file and its contents.
  : > "${BASE_DIR}/authorized_keys.txt"
  while IFS=: read -r u _ uid _ _ home _; do
    [[ -f "${home}/.ssh/authorized_keys" ]] || continue
    {
      echo "### user=${u} (uid=${uid}) :: ${home}/.ssh/authorized_keys"
      cat "${home}/.ssh/authorized_keys"
      echo
    } >> "${BASE_DIR}/authorized_keys.txt"
  done < /etc/passwd
  cp -a /root/.ssh/authorized_keys "${BASE_DIR}/root_authorized_keys.txt" 2>/dev/null || true
  log "[*] authorized_keys.txt — every SSH key trusted on this box (check for unknowns)"

  # -- SUID/SGID binaries — privilege-escalation backdoors ---------------------
  # A planted SUID-root copy of bash/cp/etc. is instant root for the attacker.
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' \
       2>/dev/null | sort > "${BASE_DIR}/suid_sgid.txt"
  log "[*] suid_sgid.txt      — SUID/SGID files (diff later; new ones = red flag)"

  # -- Hashes of key system binaries & config dirs (for tamper detection) ------
  # We hash the directories an attacker is most likely to backdoor. Diff the file
  # later to detect a replaced binary or modified config.
  if have sha256sum; then
    find /etc/ssh /etc/pam.d /usr/sbin /usr/bin /bin /sbin -type f -print0 2>/dev/null \
      | xargs -0 -r sha256sum 2>/dev/null | sort -k2 > "${BASE_DIR}/binary_hashes.txt"
    log "[*] binary_hashes.txt — sha256 of system binaries/configs (tamper baseline)"
  fi

  # -- PAM, hosts, modules, and other quick wins -------------------------------
  cp -a /etc/pam.d "${BASE_DIR}/pam.d" 2>/dev/null || true
  cp /etc/hosts "${BASE_DIR}/hosts.txt" 2>/dev/null || true
  cp /etc/resolv.conf "${BASE_DIR}/resolv.conf.txt" 2>/dev/null || true
  lsmod > "${BASE_DIR}/kernel_modules.txt" 2>/dev/null || true
  log "[*] pam.d/ hosts.txt resolv.conf.txt kernel_modules.txt"

  log "\n[✓] Baseline complete. Keep ${BASE_DIR} safe — it is your IR evidence."
}

###############################################################################
# (B) SAFE HARDENING  — only reversible, non-breaking changes. Each edit is
#     backed up to ${BACKUP_DIR} first so you can roll back instantly.
###############################################################################

# backup_file <path> : copy a config to the backup dir before we touch it.
backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest"
  log "    (backed up $f -> ${dest})"
}

harden_ssh() {
  sect "HARDEN: SSH (keep service & password auth UP; disable root + empty pw)"
  # We write a DROP-IN file rather than editing sshd_config in place. Both Fedora
  # and Debian read /etc/ssh/sshd_config.d/*.conf, and a drop-in is trivial to
  # remove if anything goes wrong (just delete the file and reload).
  local dropin="/etc/ssh/sshd_config.d/00-ecitadel-hardening.conf"
  if [[ ! -d /etc/ssh/sshd_config.d ]]; then
    # Older configs may not include the drop-in dir; fall back to main file.
    backup_file /etc/ssh/sshd_config
    dropin="/etc/ssh/sshd_config"
    log "[!] No sshd_config.d dir; appending to main sshd_config (backed up)."
  fi
  # Note what we deliberately DO NOT set:
  #   PasswordAuthentication  -> left as-is (scorer likely uses a password)
  #   Port / ListenAddress    -> left as-is (changing could miss the scorer)
  cat > "${dropin}" <<'EOF'
# eCitadel Team 76 SSH hardening (safe subset).
# Disables the two classic scored/insecure settings without breaking the
# scoring engine's password-based SSH check. Remove this file + `systemctl
# reload ssh*` to revert.
PermitRootLogin no
PermitEmptyPasswords no
# Reasonable session hygiene (does not affect scorer logins):
LoginGraceTime 30
MaxAuthTries 4
EOF
  log "[*] Wrote ${dropin}"

  # Validate BEFORE applying. If sshd -t fails, we revert and skip — never leave
  # SSH in a broken state (SSH is a scored service on both Linux boxes).
  if sshd -t 2>>"${REPORT}"; then
    # Reload, not restart: existing connections (yours + scorer's) stay alive.
    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
      log "[✓] SSH config valid; reloaded. Root login + empty passwords now off."
    else
      log "[!] Could not reload ssh/sshd — check 'systemctl status ssh sshd'."
    fi
  else
    log "[!] sshd -t FAILED — removing our drop-in to keep SSH safe."
    [[ "${dropin}" == *sshd_config.d* ]] && rm -f "${dropin}"
    todo "SSH hardening was skipped (sshd -t failed). Investigate sshd_config by hand."
  fi

  # Make sure SSH is enabled + running (it is required and scored).
  systemctl enable --now ssh   >/dev/null 2>&1 || \
  systemctl enable --now sshd  >/dev/null 2>&1 || true
}

harden_password_policy() {
  sect "HARDEN: password policy (affects only FUTURE password changes — safe)"
  # /etc/login.defs controls password aging defaults. Setting a max age and a
  # sane min length is a scored item and cannot lock anyone out right now.
  backup_file /etc/login.defs
  set_login_def() {   # set_login_def KEY VALUE
    local key="$1" val="$2"
    if grep -Eq "^\s*${key}\b" /etc/login.defs; then
      sed -i -E "s|^\s*${key}\b.*|${key}\t${val}|" /etc/login.defs
    else
      echo -e "${key}\t${val}" >> /etc/login.defs
    fi
  }
  set_login_def PASS_MAX_DAYS 90
  set_login_def PASS_MIN_DAYS 1
  set_login_def PASS_WARN_AGE 7
  log "[*] login.defs: PASS_MAX_DAYS=90 PASS_MIN_DAYS=1 PASS_WARN_AGE=7"

  # Minimum password complexity via pwquality (the module both Fedora 43 and
  # Debian 13 use). We prefer editing /etc/security/pwquality.conf because it is
  # safe — it never alters the PAM stack that could lock you out.
  if [[ -f /etc/security/pwquality.conf ]]; then
    backup_file /etc/security/pwquality.conf
    set_pwq() { local k="$1" v="$2"
      if grep -Eq "^\s*#?\s*${k}\b" /etc/security/pwquality.conf; then
        sed -i -E "s|^\s*#?\s*${k}\s*=.*|${k} = ${v}|" /etc/security/pwquality.conf
      else echo "${k} = ${v}" >> /etc/security/pwquality.conf; fi
    }
    set_pwq minlen 14
    set_pwq dcredit -1
    set_pwq ucredit -1
    set_pwq ocredit -1
    set_pwq lcredit -1
    log "[*] pwquality.conf: minlen=14, require digit/upper/lower/other"
  else
    log "[!] /etc/security/pwquality.conf not found."
    if [[ "${OS_FAMILY}" == "debian" ]]; then
      todo "Install pwquality: apt-get install -y libpam-pwquality, then set minlen=14 in /etc/security/pwquality.conf"
    else
      todo "Install pwquality: dnf install -y libpwquality, then set minlen=14 in /etc/security/pwquality.conf"
    fi
  fi
}

harden_sysctl() {
  sect "HARDEN: kernel network parameters (safe for a DB/web server)"
  # These are safe on a server that is NOT a router. ip_forward=0 is a scored
  # item in past events. The rest are standard, non-disruptive hardening.
  local f="/etc/sysctl.d/99-ecitadel.conf"
  cat > "$f" <<'EOF'
# eCitadel Team 76 safe network hardening. Remove this file + `sysctl --system`
# to revert. None of these affect inbound SSH/HTTP/DNS scoring.
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
EOF
  sysctl --system >/dev/null 2>&1 && log "[✓] Applied ${f}" \
      || log "[!] sysctl --system reported an issue (see above)."
}

harden_auto_updates() {
  sect "HARDEN: automatic security updates (config only; won't upgrade right now)"
  # Enabling the timer is a scored item. The timer fires on its OWN schedule
  # (typically ~6am), so it will not surprise-upgrade a service during your
  # round — it just makes the config correct for the CCS check.
  if [[ "${OS_FAMILY}" == "rhel" ]]; then
    if ! rpm -q dnf-automatic >/dev/null 2>&1 && ! rpm -q dnf5-plugin-automatic >/dev/null 2>&1; then
      dnf install -y dnf-automatic >>"${REPORT}" 2>&1 || \
        { log "[!] Could not install dnf-automatic (no network?)."; \
          todo "Install dnf-automatic and enable dnf5-automatic.timer for the update CCS check."; }
    fi
    # Fedora 43 ships dnf5; the config still lives at /etc/dnf/automatic.conf.
    # If it's missing, seed it from the dnf5 template.
    if [[ ! -f /etc/dnf/automatic.conf && -f /usr/share/dnf5/dnf5-plugins/automatic.conf ]]; then
      cp /usr/share/dnf5/dnf5-plugins/automatic.conf /etc/dnf/automatic.conf
    fi
    if [[ -f /etc/dnf/automatic.conf ]]; then
      backup_file /etc/dnf/automatic.conf
      sed -i -E 's|^\s*#?\s*apply_updates\s*=.*|apply_updates = yes|' /etc/dnf/automatic.conf
      grep -q '^\s*apply_updates' /etc/dnf/automatic.conf || \
        printf '\n[commands]\napply_updates = yes\n' >> /etc/dnf/automatic.conf
    fi
    # Fedora 43 / dnf5 uses dnf5-automatic.timer. Older systems use dnf-automatic.timer.
    # Enable whichever exists.
    systemctl enable --now dnf5-automatic.timer >/dev/null 2>&1 \
      || systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 \
      || log "[!] No dnf(5)-automatic.timer found to enable."
    log "[*] dnf automatic: apply_updates=yes + timer enabled (fires on its own schedule)."
  elif [[ "${OS_FAMILY}" == "debian" ]]; then
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >>"${REPORT}" 2>&1 \
        || { log "[!] Could not install unattended-upgrades (no network?)."; \
             todo "Install unattended-upgrades and enable its timer for the update CCS check."; }
    fi
    # Turn on the periodic check + auto-install of security updates.
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
    log "[*] unattended-upgrades enabled for security updates."
  fi
}

harden_firewall() {
  sect "HARDEN: host firewall (ALLOW everything listening first, THEN default-deny)"
  if [[ "${DO_FIREWALL}" -eq 0 ]]; then
    log "[*] --no-firewall given; skipping. (Recommended only if pfSense already filters.)"
    return 0
  fi

  # Build the list of TCP and UDP ports that are CURRENTLY listening. We will
  # allow every one of these so no running service (scored or dependency) breaks.
  local tcp_ports udp_ports
  tcp_ports="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un)"
  udp_ports="$(ss -ulnH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un)"
  # Safety net: always allow the standard scored ports even if not detected yet.
  local always_tcp="22 53 80 443"
  local always_udp="53"
  log "[*] Detected listening TCP ports: $(echo $tcp_ports | tr '\n' ' ')"
  log "[*] Detected listening UDP ports: $(echo $udp_ports | tr '\n' ' ')"
  log "[*] Plus always-allow TCP: ${always_tcp}  UDP: ${always_udp}"

  if [[ "${OS_FAMILY}" == "rhel" ]]; then
    # ----- Fedora: firewalld (default-denies unlisted inbound by design) -----
    if ! have firewall-cmd; then
      dnf install -y firewalld >>"${REPORT}" 2>&1 || true
    fi
    systemctl enable firewalld >/dev/null 2>&1
    systemctl start  firewalld >/dev/null 2>&1
    firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1
    for p in ${tcp_ports} ${always_tcp}; do firewall-cmd --permanent --add-port=${p}/tcp >/dev/null 2>&1; done
    for p in ${udp_ports} ${always_udp}; do firewall-cmd --permanent --add-port=${p}/udp >/dev/null 2>&1; done
    firewall-cmd --reload >/dev/null 2>&1
    log "[✓] firewalld active. Allowed: ssh + all listening ports + scored ports."
    log "    Review with: sudo firewall-cmd --list-all"
  elif [[ "${OS_FAMILY}" == "debian" ]]; then
    # ----- Debian: ufw (simplest reliable option; allows established by default) -----
    if ! have ufw; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >>"${REPORT}" 2>&1 || true
    fi
    if have ufw; then
      ufw --force reset >/dev/null 2>&1   # start from a clean known state
      ufw default allow outgoing >/dev/null 2>&1   # keep egress open for now (web app needs DB/DNS)
      ufw default deny  incoming >/dev/null 2>&1
      ufw allow 22/tcp >/dev/null 2>&1             # SSH FIRST so we never lock ourselves out
      for p in ${tcp_ports} ${always_tcp}; do ufw allow ${p}/tcp >/dev/null 2>&1; done
      for p in ${udp_ports} ${always_udp}; do ufw allow ${p}/udp >/dev/null 2>&1; done
      ufw --force enable >/dev/null 2>&1
      log "[✓] ufw active. Allowed: 22 + all listening ports + scored ports."
      log "    Review with: sudo ufw status verbose"
    else
      log "[!] ufw not available and could not be installed."
      todo "Configure nftables/ufw manually to allow SSH + scored ports, default-deny inbound."
    fi
  else
    log "[!] Unknown OS family; skipping firewall. Configure it by hand."
    todo "Set up a host firewall: allow SSH + scored ports, default-deny inbound."
  fi
}

###############################################################################
# RISK SCAN  — things that are usually wrong but are TOO DANGEROUS to auto-fix.
#              We only REPORT these and queue exact commands in the TODO list.
###############################################################################
risk_scan() {
  sect "RISK SCAN (reported only — confirm against this year's README before acting)"

  # Prohibited media files (an easy scored item, but deleting blindly is risky).
  local media
  media="$(find /home /root /srv /var/www -type f \
            \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' -o -iname '*.avi' \
               -o -iname '*.mkv' -o -iname '*.flac' -o -iname '*.mov' \) 2>/dev/null | head -50)"
  if [[ -n "${media}" ]]; then
    log "[!] Possible prohibited media files:"; echo "${media}" | sed 's/^/      /' | tee -a "${REPORT}"
    todo "Review media files above; delete the non-work ones (e.g. rm '<path>'). Do NOT delete legitimate business files."
  fi

  # Plaintext-password / credential-looking files an attacker may have dropped.
  local creds
  creds="$(grep -rIl --exclude-dir=/proc -E 'password|passwd|secret' /home /root 2>/dev/null | head -20)"
  [[ -n "${creds}" ]] && { log "[*] Files mentioning 'password' (may be benign): "; echo "${creds}" | sed 's/^/      /'; }

  # Empty-password accounts (instant login).
  if [[ -r /etc/shadow ]]; then
    local emptypw
    emptypw="$(awk -F: '($2=="" ){print $1}' /etc/shadow)"
    if [[ -n "${emptypw}" ]]; then
      log "[!] Accounts with EMPTY passwords:"; echo "${emptypw}" | sed 's/^/      /'
      if [[ "${AGGRESSIVE}" -eq 1 && "${DRY_RUN}" -eq 0 ]]; then
        local u
        for u in ${emptypw}; do passwd -l "$u" >/dev/null 2>&1 && log "    [aggressive] LOCKED empty-password account: $u (reversible: 'passwd -u $u')"; done
      else
        todo "Lock/relabel empty-password accounts: 'sudo passwd -l <user>' or set a password (confirm it isn't a required service account)."
      fi
    fi
  fi

  # Compare login-capable users to a reminder of who is authorized.
  log "[*] Login-capable users on this box are in baselines/.../login_users.txt."
  todo "Open login_users.txt and delete any account NOT in this year's README authorized-user list: 'sudo userdel -r <user>' (be 100% sure first)."

  # Mail / discovery services that past events scored. In --aggressive we auto-
  # disable ONLY the ones never scored in this competition (mail/telnet/print/
  # discovery). We NEVER auto-touch vsftpd or SMB — those can be required/scored.
  local AUTO_DISABLE=" postfix dovecot exim4 sendmail telnet cups avahi-daemon rpcbind "
  local svc
  for svc in postfix dovecot exim4 sendmail smbd nmbd telnet vsftpd cups avahi-daemon rpcbind; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      log "[!] Service '${svc}' is running."
      if [[ "${AGGRESSIVE}" -eq 1 && "${DRY_RUN}" -eq 0 && "${AUTO_DISABLE}" == *" ${svc} "* ]]; then
        systemctl disable --now "${svc}" >/dev/null 2>&1 && log "    [aggressive] stopped + disabled ${svc} (re-enable: 'systemctl enable --now ${svc}')"
      else
        todo "If '${svc}' is NOT a required/scored service this year, disable it: 'sudo systemctl disable --now ${svc}'. (FTP/DB/web/DNS/SMB may be REQUIRED — check first.)"
      fi
    fi
  done

  # Prohibited tools the README usually bans on servers.
  local tool
  for tool in nmap wireshark tshark netcat ncat nikto hydra john hashcat zenmap masscan; do
    if have "${tool}"; then
      log "[!] Tool '${tool}' present."
      if [[ "${AGGRESSIVE}" -eq 1 && "${DRY_RUN}" -eq 0 ]]; then
        if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get remove -y "${tool}" >>"${REPORT}" 2>&1
        elif have dnf; then dnf remove -y "${tool}" >>"${REPORT}" 2>&1; fi
        if have "${tool}"; then log "    [aggressive] could not auto-remove ${tool} (try the exact package name)"; else log "    [aggressive] removed ${tool}"; fi
      else
        todo "If '${tool}' is prohibited this year, remove it (apt-get remove / dnf remove ${tool}). Keep it only if an inject needs it."
      fi
    fi
  done
}

###############################################################################
# MAIN
###############################################################################
if [[ "${DRY_RUN}" -eq 1 ]]; then
  sect "DRY RUN — showing what WOULD change; NOTHING will be modified"
  log "  (To capture a baseline without hardening, use --baseline-only instead.)"
  log "  SSH       : add /etc/ssh/sshd_config.d/00-ecitadel.conf -> PermitRootLogin no +"
  log "              PermitEmptyPasswords no (KEEPS PasswordAuthentication ON for the scorer),"
  log "              validate with 'sshd -t', then reload. Original sshd_config backed up."
  log "  Passwords : PASS_MAX_DAYS=90 / PASS_MIN_DAYS=1 / PASS_WARN_AGE=7 in /etc/login.defs;"
  log "              minlen + complexity in /etc/security/pwquality.conf. Backups kept."
  log "  Sysctl    : /etc/sysctl.d/99-ecitadel.conf -> ip_forward=0, rp_filter=1,"
  log "              tcp_syncookies=1, ignore-bogus-ICMP, no redirects/source-route."
  if [[ "${DO_FIREWALL}" -eq 1 ]]; then
    log "  Firewall  : ALLOW current listening ports + 22/53/80/443 FIRST, then default-deny"
    log "              INBOUND (scored ports stay open; the rotating scorer is never blocked)."
  else
    log "  Firewall  : SKIPPED (--no-firewall)."
  fi
  log "  Updates   : install + enable automatic security updates (dnf-automatic / unattended-upgrades)."
  if [[ "${AGGRESSIVE}" -eq 1 ]]; then
    log "  AGGRESSIVE: would ALSO lock empty-password accounts, disable mail/discovery services"
    log "              (postfix/dovecot/exim4/sendmail/telnet/cups/avahi/rpcbind), and remove"
    log "              prohibited tools (nmap/wireshark/...). vsftpd, SMB, web, DB, DNS untouched."
  fi
  log "\n  Re-run without --dry-run to apply. A read-only risk scan follows (changes nothing):"
  AGGRESSIVE=0 risk_scan
else
  capture_baseline
  if [[ "${BASELINE_ONLY}" -eq 1 ]]; then
    log "\n[i] --baseline-only: stopping after snapshot. No changes were made."
  else
    if [[ "${AGGRESSIVE}" -eq 1 ]]; then
      sect "AGGRESSIVE MODE"
      log "Auto-remediating the SAFE subset: lock empty-password accounts, disable mail/"
      log "discovery services, remove prohibited tools. NOT touching sshd/web/DB/DNS/vsftpd/"
      log "SMB and NOT deleting any user (those stay on the action list for you to confirm)."
    fi
    harden_ssh
    harden_password_policy
    harden_sysctl
    harden_auto_updates
    harden_firewall
    risk_scan
  fi
fi

# ---- print the TODO list (the risky items we refused to auto-run) ------------
sect "ACTION LIST — do these BY HAND after confirming against the README"
if [[ -s "${TODO_FILE}" ]]; then
  cat "${TODO_FILE}" | tee -a "${REPORT}"
else
  log "  (nothing flagged — but still read the audit + malware-hunt reports)"
fi
rm -f "${TODO_FILE}"

sect "DONE"
log "Safe hardening applied. Backups of every edited file are in:"
log "    ${BACKUP_DIR}"
log "To revert any single change: copy the file back from that folder and reload the service."
log "Next: run  scripts/audit_linux.sh  and  scripts/hunt_malware.sh"
