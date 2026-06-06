#!/usr/bin/env bash
###############################################################################
# audit_linux.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   A 100% READ-ONLY scanner. It checks the box against EVERY misconfiguration
#   and vulnerability category that eCitadel has scored in past rounds (pulled
#   from the Alma9 and Mint21 practice answer keys) and prints a clean
#   PASS / FAIL / WARN checklist plus an exact "how to fix" line for each FAIL.
#
#   It changes NOTHING. You can run it as many times as you like. Use it to:
#     * find what the CCS "find-and-fix" graders are likely checking,
#     * re-run after first5_secure.sh to confirm what is now fixed,
#     * spot a setting the Red Team flipped back mid-round.
#
# WHY READ-ONLY
#   Auto-fixing is dangerous in a scored environment (you can take down a
#   service or delete something the README requires). This script's job is to
#   TELL you precisely what is wrong and the command to fix it; you (or
#   first5_secure.sh, for the safe subset) apply it deliberately.
#
# USAGE
#   sudo ./audit_linux.sh                 # full checklist to screen + report
#   sudo ./audit_linux.sh --quiet         # only show FAIL/WARN lines
#
# OUTPUT
#   ./reports/audit_<host>_<timestamp>.log
###############################################################################

set -u
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run with sudo/root (reads /etc/shadow, sshd_config, etc.)." >&2
  exit 1
fi

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
TS="$(date +%Y%m%d_%H%M%S)"
REPORT="${KIT_DIR}/reports/audit_${HOST}_${TS}.log"
mkdir -p "${KIT_DIR}/reports"

# --- counters + colored status helpers ---------------------------------------
PASS_N=0; FAIL_N=0; WARN_N=0; INFO_N=0
have() { command -v "$1" >/dev/null 2>&1; }

# Write a line to screen + report. In --quiet mode only FAIL/WARN reach screen.
out()  { echo -e "$*" >> "${REPORT}"; [[ "${QUIET}" -eq 0 ]] && echo -e "$*"; }
force(){ echo -e "$*" | tee -a "${REPORT}"; }   # always shown
sect() { force "\n========== $* =========="; }

# status helpers: pass/fail/warn/info "<check name>" "<detail / fix>"
pass() { PASS_N=$((PASS_N+1)); out  "  [PASS] $1"; [[ -n "${2:-}" ]] && out "         $2"; }
fail() { FAIL_N=$((FAIL_N+1)); force "  [FAIL] $1"; [[ -n "${2:-}" ]] && force "         FIX: $2"; }
warn() { WARN_N=$((WARN_N+1)); force "  [WARN] $1"; [[ -n "${2:-}" ]] && force "         $2"; }
info() { INFO_N=$((INFO_N+1)); out  "  [INFO] $1"; [[ -n "${2:-}" ]] && out "         $2"; }

force "eCitadel audit_linux.sh  |  host=${HOST}  |  $(date)"
force "Report: ${REPORT}"

# --- OS detection -------------------------------------------------------------
OS_ID=""; OS_VER=""; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; fi
case "${OS_ID}" in
  debian|ubuntu|linuxmint) OS_FAMILY="debian" ;;
  fedora|rhel|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
  *) OS_FAMILY="unknown" ;;
esac
force "Detected: ID=${OS_ID} VERSION=${OS_VER} FAMILY=${OS_FAMILY}"

# Helper: read an effective sshd setting (honors drop-ins). Falls back to grep.
sshd_val() {  # sshd_val <Keyword>
  local key="$1" v=""
  if have sshd; then
    v="$(sshd -T 2>/dev/null | awk -v k="$(echo "$key" | tr 'A-Z' 'a-z')" 'tolower($1)==k{print $2; exit}')"
  fi
  if [[ -z "$v" ]]; then
    v="$(grep -rhiE "^\s*${key}\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
          | awk '{print $2; exit}')"
  fi
  echo "$v"
}

###############################################################################
# 1. SSH HARDENING  — scored on BOTH Linux boxes every year.
###############################################################################
audit_ssh() {
  sect "SSH configuration"

  local root_login empty_pw proto x11
  root_login="$(sshd_val PermitRootLogin)"
  empty_pw="$(sshd_val PermitEmptyPasswords)"
  proto="$(sshd_val Protocol)"
  x11="$(sshd_val X11Forwarding)"

  if [[ "${root_login}" == "no" || "${root_login}" == "prohibit-password" ]]; then
    pass "PermitRootLogin is '${root_login}'"
  else
    fail "PermitRootLogin = '${root_login:-default(yes)}'" \
         "set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/00-ecitadel-hardening.conf then 'sshd -t && systemctl reload ssh sshd'"
  fi

  if [[ "${empty_pw}" == "no" || -z "${empty_pw}" ]]; then
    # default is 'no'; only an explicit 'yes' is a finding
    [[ "${empty_pw}" == "yes" ]] && fail "PermitEmptyPasswords = yes" \
        "set 'PermitEmptyPasswords no' and reload sshd" \
      || pass "PermitEmptyPasswords is not enabled"
  else
    fail "PermitEmptyPasswords = '${empty_pw}'" "set 'PermitEmptyPasswords no' and reload sshd"
  fi

  # Protocol 1 is ancient/insecure; modern sshd is 2-only, so this is informational.
  [[ "${proto}" == "1" ]] && fail "SSH Protocol 1 enabled" "set 'Protocol 2'" \
                          || info "SSH protocol is 2 (modern default)"

  # X11Forwarding yes is a minor hardening item; report as WARN, never break it.
  [[ "${x11}" == "yes" ]] && warn "X11Forwarding = yes (minor; disable if not needed)" \
        "set 'X11Forwarding no' if no inject needs GUI forwarding"

  # IMPORTANT scoring note, not a finding:
  local pwauth; pwauth="$(sshd_val PasswordAuthentication)"
  info "PasswordAuthentication = '${pwauth:-yes}' — KEEP this on unless an inject says key-only," \
       "because the scoring engine's SSH check most likely logs in with a password."

  # SSH certificate / command backdoors (Red Team has used SSH CA auth to hide).
  local caf akc
  caf="$(sshd_val TrustedUserCAKeys)"
  akc="$(sshd -T 2>/dev/null | awk 'tolower($1)=="authorizedkeyscommand"{ $1=""; print}')"
  [[ -n "${caf}" ]] && warn "SSH TrustedUserCAKeys set (${caf})" \
      "an SSH CA can mint valid login certs — confirm YOU created this; if not, remove the line and reload sshd"
  [[ -n "${akc// /}" ]] && warn "SSH AuthorizedKeysCommand set (${akc})" \
      "this program can hand out keys dynamically — verify it's legitimate"
}

###############################################################################
# 2. PASSWORD / ACCOUNT POLICY  — login.defs + pwquality + aging.
###############################################################################
audit_passwords() {
  sect "Password & account policy"

  # PASS_MAX_DAYS: past keys flagged 0 / 99999 and wanted ~90.
  local maxd mind
  maxd="$(awk '/^\s*PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null)"
  mind="$(awk '/^\s*PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null)"
  if [[ -n "${maxd}" && "${maxd}" -ge 1 && "${maxd}" -le 365 && "${maxd}" -ne 99999 ]]; then
    pass "PASS_MAX_DAYS = ${maxd}"
  else
    fail "PASS_MAX_DAYS = '${maxd:-unset}'" "edit /etc/login.defs -> PASS_MAX_DAYS 90"
  fi
  [[ -n "${mind}" && "${mind}" -ge 1 ]] && pass "PASS_MIN_DAYS = ${mind}" \
      || warn "PASS_MIN_DAYS = '${mind:-0}'" "consider PASS_MIN_DAYS 1 in /etc/login.defs"

  # pwquality minimum length (the module both distros use).
  if [[ -f /etc/security/pwquality.conf ]]; then
    local minlen; minlen="$(awk -F= '/^\s*minlen/{gsub(/ /,"",$2); print $2; exit}' /etc/security/pwquality.conf)"
    [[ -n "${minlen}" && "${minlen}" -ge 12 ]] && pass "pwquality minlen = ${minlen}" \
        || fail "pwquality minlen = '${minlen:-unset}'" "set 'minlen = 14' in /etc/security/pwquality.conf"
  else
    fail "pwquality.conf missing" \
         "$( [[ ${OS_FAMILY} == debian ]] && echo 'apt-get install -y libpam-pwquality' || echo 'dnf install -y libpwquality' ), then set minlen=14"
  fi

  # Accounts with empty password fields = instant login. Always a FAIL.
  if [[ -r /etc/shadow ]]; then
    local empties; empties="$(awk -F: '($2=="" ){print $1}' /etc/shadow | tr '\n' ' ')"
    [[ -n "${empties}" ]] && fail "Empty-password accounts: ${empties}" \
        "lock or set a password (confirm not a service acct): passwd -l <user>" \
      || pass "No empty-password accounts"
  fi

  # More than one UID-0 account is almost always a backdoor.
  local uid0; uid0="$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')"
  [[ "$(echo ${uid0} | wc -w)" -gt 1 ]] && fail "Multiple UID-0 accounts: ${uid0}" \
      "remove the non-root UID-0 account after confirming: userdel -r <user>" \
    || pass "Exactly one UID-0 account (root)"
}

###############################################################################
# 3. LOGIN-CAPABLE USERS  — compare to the README's authorized list by hand.
###############################################################################
audit_users() {
  sect "Login-capable users (compare to this year's README!)"
  local users
  users="$(awk -F: '($3>=1000 && $3<65534) || $7 ~ /(bash|sh|zsh)$/ {print $1" (uid="$3", shell="$7")"}' /etc/passwd)"
  out "${users}"
  warn "Verify every account above is in the README's authorized-user list" \
       "delete unauthorized ones with: userdel -r <user>  (be 100% certain first)"
}

###############################################################################
# 4. FIREWALL  — must be ENABLED (scored). We never enable it here, only report.
###############################################################################
audit_firewall() {
  sect "Host firewall"
  if [[ "${OS_FAMILY}" == "rhel" ]]; then
    if systemctl is-active --quiet firewalld; then
      pass "firewalld is active"
      out "$(firewall-cmd --list-all 2>/dev/null | sed 's/^/         /')"
    else
      fail "firewalld inactive" "systemctl enable --now firewalld (run first5_secure.sh to do this safely)"
    fi
  elif [[ "${OS_FAMILY}" == "debian" ]]; then
    if have ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
      pass "ufw is active"
      out "$(ufw status verbose 2>/dev/null | sed 's/^/         /')"
    elif have nft && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then
      warn "ufw inactive but nftables has rules" "verify nft ruleset allows scored ports + default-denies inbound"
    else
      fail "No active firewall (ufw inactive)" "ufw allow 22/tcp; ufw --force enable (or run first5_secure.sh)"
    fi
  else
    warn "Unknown OS; cannot auto-detect firewall" "ensure SSH + scored ports allowed, inbound default-deny"
  fi
}

###############################################################################
# 5. KERNEL / SYSCTL  — IPv4 forwarding off (scored on Debian key), etc.
###############################################################################
audit_sysctl() {
  sect "Kernel network parameters"
  local fwd; fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
  [[ "${fwd}" == "0" ]] && pass "net.ipv4.ip_forward = 0" \
      || fail "net.ipv4.ip_forward = ${fwd}" "set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-ecitadel.conf; sysctl --system  (servers are not routers)"

  local syncookies; syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)"
  [[ "${syncookies}" == "1" ]] && pass "tcp_syncookies = 1" \
      || warn "tcp_syncookies = ${syncookies}" "set net.ipv4.tcp_syncookies=1 (SYN-flood protection)"
}

###############################################################################
# 6. AUTOMATIC UPDATES  — scored item (dnf-automatic / unattended-upgrades).
###############################################################################
audit_updates() {
  sect "Automatic security updates"
  if [[ "${OS_FAMILY}" == "rhel" ]]; then
    if systemctl is-enabled --quiet dnf5-automatic.timer 2>/dev/null \
       || systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
      pass "dnf(5)-automatic.timer enabled"
      if grep -qE '^\s*apply_updates\s*=\s*yes' /etc/dnf/automatic.conf 2>/dev/null; then
        pass "automatic.conf apply_updates = yes"
      else
        fail "apply_updates not set to yes" "set apply_updates = yes in /etc/dnf/automatic.conf"
      fi
    else
      fail "dnf-automatic timer not enabled" "dnf install -y dnf-automatic; set apply_updates=yes; systemctl enable --now dnf5-automatic.timer"
    fi
  elif [[ "${OS_FAMILY}" == "debian" ]]; then
    if dpkg -s unattended-upgrades >/dev/null 2>&1; then
      pass "unattended-upgrades installed"
      grep -qE 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null \
        && pass "20auto-upgrades enables Unattended-Upgrade" \
        || fail "periodic Unattended-Upgrade not enabled" "create /etc/apt/apt.conf.d/20auto-upgrades with the Periodic settings"
    else
      fail "unattended-upgrades not installed" "apt-get install -y unattended-upgrades"
    fi
  fi
}

###############################################################################
# 7. OUTDATED PACKAGES  — count pending security/upgradable packages.
###############################################################################
audit_pkgs() {
  sect "Outdated packages"
  if [[ "${OS_FAMILY}" == "rhel" ]]; then
    local n; n="$( { dnf -q check-update 2>/dev/null || true; } | grep -cE '^[a-zA-Z0-9].*\.' )"
    [[ "${n}" -eq 0 ]] && pass "No packages flagged by 'dnf check-update'" \
        || warn "${n} package(s) upgradable" "review then 'dnf upgrade -y' between scoring checks (test services after)"
  elif [[ "${OS_FAMILY}" == "debian" ]]; then
    apt-get update -qq >/dev/null 2>&1 || true
    local n; n="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
    [[ "${n}" -eq 0 ]] && pass "No upgradable packages" \
        || warn "${n} package(s) upgradable" "review then 'apt-get upgrade -y' between checks (test services after)"
  fi
}

###############################################################################
# 8. UNNECESSARY / MAIL SERVICES  — past keys scored stopping these.
#    NOTE: we never tell you to stop sshd/httpd/DB/DNS/FTP — those may be REQUIRED.
###############################################################################
audit_services() {
  sect "Potentially-unnecessary services (confirm against README before disabling)"
  local found=0
  for svc in postfix dovecot exim4 sendmail telnet rsh-server rlogin \
             smbd nmbd snmpd cups avahi-daemon rpcbind nfs-server; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      found=1
      warn "Service '${svc}' is running" \
           "if NOT required/scored this year: systemctl disable --now ${svc}"
    fi
  done
  [[ "${found}" -eq 0 ]] && pass "No obvious unnecessary services running"

  # Show all listening services so you can eyeball anything unexpected.
  out "\n  Listening sockets (review for anything you don't recognize):"
  if have ss; then out "$(ss -tulnp 2>/dev/null | sed 's/^/         /')"; fi
}

###############################################################################
# 9. PROHIBITED TOOLS  — README usually bans recon/attack tools on servers.
###############################################################################
audit_tools() {
  sect "Prohibited / suspicious tools"
  local found=0
  for tool in nmap zenmap wireshark tshark ettercap nikto hydra john \
              hashcat aircrack-ng netcat ncat nc socat masscan responder; do
    if have "${tool}"; then
      found=1
      warn "Tool '${tool}' present" \
           "if prohibited this year: $( [[ ${OS_FAMILY} == debian ]] && echo apt-get remove -y || echo dnf remove -y ) ${tool}"
    fi
  done
  [[ "${found}" -eq 0 ]] && pass "No common prohibited tools found"
}

###############################################################################
# 10. PROHIBITED MEDIA / FILES  — easy scored item; we only list candidates.
###############################################################################
audit_media() {
  sect "Prohibited media files (review; delete only non-business files)"
  local media
  media="$(find /home /root /srv /var/www /opt -type f \
            \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' -o -iname '*.avi' \
               -o -iname '*.mkv' -o -iname '*.flac' -o -iname '*.mov' -o -iname '*.m4a' \
               -o -iname '*.wma' -o -iname '*.ogg' \) 2>/dev/null | head -100)"
  if [[ -n "${media}" ]]; then
    out "${media}"
    warn "$(echo "${media}" | wc -l) media file(s) found" "delete the non-work ones: rm '<path>'"
  else
    pass "No obvious media files in common locations"
  fi
}

###############################################################################
# 11. SERVICE-SPECIFIC INSECURE DEFAULTS  — FTP anon, etc. (only if present).
###############################################################################
audit_service_configs() {
  sect "Service-specific insecure settings (only checked if the service exists)"

  # vsftpd anonymous access (Alma key flagged anonymous_enable=YES)
  if [[ -f /etc/vsftpd/vsftpd.conf || -f /etc/vsftpd.conf ]]; then
    local conf; conf="$( [[ -f /etc/vsftpd/vsftpd.conf ]] && echo /etc/vsftpd/vsftpd.conf || echo /etc/vsftpd.conf )"
    if grep -qiE '^\s*anonymous_enable\s*=\s*YES' "${conf}"; then
      fail "vsftpd anonymous_enable = YES (${conf})" "set anonymous_enable=NO then restart vsftpd (do NOT disable vsftpd if FTP is scored)"
    else
      pass "vsftpd anonymous access disabled"
    fi
  fi

  # Apache/Nginx presence (informational — web is scored on concierge)
  systemctl is-active --quiet httpd 2>/dev/null && info "httpd (Apache) running — web is SCORED, keep it up"
  systemctl is-active --quiet apache2 2>/dev/null && info "apache2 running — web is SCORED, keep it up"
  systemctl is-active --quiet nginx 2>/dev/null && info "nginx running — web is SCORED, keep it up"

  # Database presence (blacklist box dependency)
  systemctl is-active --quiet mariadb 2>/dev/null && info "MariaDB running — DB is a scored dependency, keep it up"
  systemctl is-active --quiet mysql 2>/dev/null && info "MySQL running — DB is a scored dependency, keep it up"
  systemctl is-active --quiet postgresql 2>/dev/null && info "PostgreSQL running — keep it up if scored"
}

###############################################################################
# 12. WORLD-WRITABLE & NO-OWNER FILES  — quick integrity sanity checks.
###############################################################################
audit_perms() {
  sect "Risky file permissions (informational)"
  local ww
  ww="$(find / -xdev -type f -perm -0002 ! -path '/proc/*' 2>/dev/null | head -30)"
  [[ -n "${ww}" ]] && { warn "World-writable files exist (top 30 shown)"; out "$(echo "${ww}" | sed 's/^/         /')"; } \
    || pass "No world-writable files in top-level scan"

  local noown
  noown="$(find / -xdev \( -nouser -o -nogroup \) ! -path '/proc/*' 2>/dev/null | head -20)"
  [[ -n "${noown}" ]] && { warn "Files with no owner/group (possible tampering)"; out "$(echo "${noown}" | sed 's/^/         /')"; } \
    || pass "No orphaned (no-owner) files found"
}

###############################################################################
# MAIN
###############################################################################
audit_ssh
audit_passwords
audit_users
audit_firewall
audit_sysctl
audit_updates
audit_pkgs
audit_services
audit_tools
audit_media
audit_service_configs
audit_perms

sect "SUMMARY"
force "  PASS: ${PASS_N}   FAIL: ${FAIL_N}   WARN: ${WARN_N}   INFO: ${INFO_N}"
force "  Full report saved to: ${REPORT}"
if [[ "${FAIL_N}" -gt 0 ]]; then
  force "  -> Address the [FAIL] items first; each has a FIX line above."
  force "     The safe subset is applied automatically by first5_secure.sh."
fi
force "  Re-run this audit after fixing to confirm, and again if you suspect Red-Team tampering."
