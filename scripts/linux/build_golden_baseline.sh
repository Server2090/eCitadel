#!/usr/bin/env bash
###############################################################################
# build_golden_baseline.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   Implements the "build it clean and compare" method. You stand up a CLEAN VM
#   of the same OS (ideally configured to match the intended, malware-free box —
#   same web stack / DB / AD tooling), capture a GOLDEN manifest of it, then run
#   this tool in compare mode on the real competition box. It prints EVERYTHING
#   that differs — extra packages, extra services, extra users, extra listening
#   ports, new SUID files, changed system binaries, extra cron/timers, extra
#   kernel modules, PAM/sshd differences — i.e. the candidate PRE-PLANTED
#   malware and tampering.
#
#   WHY THIS IS THE RIGHT COMPLEMENT TO first5_secure.sh
#     * first5_secure.sh snapshots the box AS YOU RECEIVED IT — which is ALREADY
#       compromised — so it can only catch changes made AFTER you start.
#     * This golden baseline comes from a CLEAN system, so diffing against it
#       reveals the malware that was planted BEFORE you ever logged in.
#   Use both: golden-diff finds pre-existing implants; first5 + watch find new
#   Red-Team activity during the round.
#
#   HONEST CAVEAT
#     The diff is only as clean as your golden VM. A vanilla install will differ
#     from the competition box in legitimate ways (the org installed real apps),
#     so you will see legit app components as "added" too. Triage the list: OS-
#     level items (users, UID-0, SUID, PAM, sshd config, kernel modules, core
#     /usr/bin & /usr/sbin binaries) should barely differ — anything new there
#     is high-suspicion. Application packages need a human eye.
#
# USAGE
#   On the CLEAN VM:
#     sudo ./build_golden_baseline.sh --capture fedora43-clean
#     # -> writes baselines/golden/fedora43-clean/  (copy this to the comp box,
#     #    e.g. via the kit folder, scp, or paste — it is just text files)
#
#   On the COMPETITION box:
#     sudo ./build_golden_baseline.sh --compare baselines/golden/fedora43-clean
#     sudo ./build_golden_baseline.sh --compare <dir> --quick   # skip slow hashing
#
# OUTPUT
#   Capture -> ./baselines/golden/<name>/...
#   Compare -> ./reports/golden_diff_<host>_<timestamp>.log
###############################################################################

set -u
umask 077
if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run with sudo/root (reads /etc/shadow, all homes, hashes system files)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
TS="$(date +%Y%m%d_%H%M%S)"

MODE=""; GNAME=""; GOLDEN=""; QUICK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --capture) MODE="capture"; GNAME="${2:-}"; shift 2 ;;
    --compare) MODE="compare"; GOLDEN="${2:-}"; shift 2 ;;
    --quick)   QUICK=1; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done
[[ -z "${MODE}" ]] && { echo "Specify --capture <name> or --compare <golden-dir>. Try --help."; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

OS_ID=""; OS_VER=""; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; fi
case "${OS_ID}" in
  debian|ubuntu|linuxmint) OS_FAMILY="debian" ;;
  fedora|rhel|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
  *) OS_FAMILY="unknown" ;;
esac

###############################################################################
# capture_to <dir>  — write all normalized, sorted manifests into <dir>.
#   The SAME function is used to build the golden set and to snapshot the live
#   box, so the two are always directly comparable with `comm`/`diff`.
###############################################################################
capture_to() {
  local d="$1"
  mkdir -p "${d}"
  echo "${OS_ID} ${OS_VER} (${OS_FAMILY})" > "${d}/os.txt"

  # 1) Installed packages (name only, sorted) — extra packages = suspicious.
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    dpkg-query -W -f='${Package}\n' 2>/dev/null | sort -u > "${d}/packages.txt"
  elif [[ "${OS_FAMILY}" == "rhel" ]]; then
    rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u > "${d}/packages.txt"
  fi

  # 2) systemd unit FILES (names) + currently-enabled units.
  if have systemctl; then
    systemctl list-unit-files --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sort -u > "${d}/unit_files.txt"
    systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sort -u > "${d}/units_enabled.txt"
    systemctl list-timers --all --no-pager 2>/dev/null | awk '/timer/{print $NF, $(NF-1)}' | sort -u > "${d}/timers.txt"
  fi

  # 3) Listening ports (proto/port, sorted) — extra ports = candidate backdoor.
  ss -tulnH 2>/dev/null | awk '{split($5,a,":"); print $1"/"a[length(a)]}' | sort -u > "${d}/listening.txt"

  # 4) Accounts: login users, UID-0, sudo/wheel members.
  awk -F: '($3>=1000 && $3<65534) || $7 ~ /(bash|sh|zsh)$/ {print $1":"$3":"$7}' /etc/passwd | sort > "${d}/login_users.txt"
  awk -F: '$3==0{print $1}' /etc/passwd | sort > "${d}/uid0.txt"
  { getent group sudo; getent group wheel; } 2>/dev/null | sort -u > "${d}/admin_groups.txt"

  # 5) SUID/SGID set (mode+path).
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %p\n' 2>/dev/null | sort > "${d}/suid_sgid.txt"

  # 6) Cron (system + per-user, concatenated text).
  {
    cat /etc/crontab 2>/dev/null
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
      [[ -f "$f" ]] && { echo "## $f"; cat "$f"; }
    done
    for cd in /var/spool/cron /var/spool/cron/crontabs; do
      [[ -d "$cd" ]] && for u in "$cd"/*; do [[ -f "$u" ]] && { echo "## $u"; cat "$u"; }; done
    done
  } 2>/dev/null | sort -u > "${d}/cron.txt"

  # 7) Kernel modules (names).
  lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort -u > "${d}/modules.txt"

  # 8) PAM config tree + effective sshd config (copied for diffing).
  cp -a /etc/pam.d "${d}/pam.d" 2>/dev/null || true
  have sshd && sshd -T 2>/dev/null | sort > "${d}/sshd_effective.txt"

  # 9) Hashes of key binary/config dirs (skippable with --quick).
  if [[ "${QUICK}" -eq 0 ]] && have sha256sum; then
    find /usr/bin /usr/sbin /bin /sbin /etc/ssh /etc/pam.d \
         /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security \
         /usr/lib64/security /lib64/security \
         -type f -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null \
         | sort -k2 > "${d}/hashes.txt"
  fi
}

###############################################################################
# CAPTURE MODE
###############################################################################
if [[ "${MODE}" == "capture" ]]; then
  [[ -z "${GNAME}" ]] && { echo "Give a name: --capture <name>"; exit 1; }
  OUT="${KIT_DIR}/baselines/golden/${GNAME}"
  echo "[*] Capturing golden manifest for '${GNAME}' (OS: ${OS_ID} ${OS_VER})..."
  echo "[*] Run this on a CLEAN, malware-free VM for it to be meaningful."
  capture_to "${OUT}"
  echo "[✓] Golden manifest written to: ${OUT}"
  echo "    Copy that folder to your competition box's kit (it is plain text),"
  echo "    then run:  sudo ./build_golden_baseline.sh --compare ${OUT}"
  exit 0
fi

###############################################################################
# COMPARE MODE
###############################################################################
[[ -d "${GOLDEN}" ]] || { echo "Golden dir not found: ${GOLDEN}"; exit 1; }
REPORT="${KIT_DIR}/reports/golden_diff_${HOST}_${TS}.log"
mkdir -p "${KIT_DIR}/reports"
log()  { echo -e "$*" | tee -a "${REPORT}"; }
sect() { log "\n========== $* =========="; }

log "eCitadel build_golden_baseline.sh COMPARE | host=${HOST} | $(date)"
log "Golden: ${GOLDEN}"
log "Report: ${REPORT}"

# OS sanity check — comparing different OSes produces meaningless noise.
if [[ -f "${GOLDEN}/os.txt" ]]; then
  g_os="$(cat "${GOLDEN}/os.txt")"
  log "Golden OS: ${g_os}   |   This box: ${OS_ID} ${OS_VER} (${OS_FAMILY})"
  [[ "${g_os}" != *"${OS_FAMILY}"* ]] && log "[!] WARNING: golden OS family differs from this box — diffs will be noisy."
fi

# Snapshot the live box into a temp dir using the identical capture routine.
CUR="$(mktemp -d)"
log "\n[*] Snapshotting this box for comparison (this may take a moment for hashing)..."
capture_to "${CUR}"

# added_lines <golden-file> <current-file>  -> lines present NOW but not in golden.
added() { comm -13 "$1" "$2" 2>/dev/null; }
# removed_lines -> lines in golden but missing NOW (renamed/deleted — also a TTP).
removed() { comm -23 "$1" "$2" 2>/dev/null; }

# report_list <label> <golden> <current> <added-meaning> <removed-meaning>
report_list() {
  local label="$1" g="$2" c="$3" amean="$4" rmean="$5"
  sect "${label}"
  if [[ ! -f "$g" ]]; then log "  (no golden data for this category)"; return; fi
  local a r
  a="$(added "$g" "$c")"
  r="$(removed "$g" "$c")"
  if [[ -n "$a" ]]; then
    log "  >>> ADDED on this box (${amean}):"
    echo "$a" | sed 's/^/        + /' | tee -a "${REPORT}"
  else
    log "  [✓] nothing added vs golden"
  fi
  if [[ -n "$r" ]]; then
    log "  --- MISSING vs golden (${rmean}):"
    echo "$r" | sed 's/^/        - /' | tee -a "${REPORT}"
  fi
}

report_list "Packages"        "${GOLDEN}/packages.txt"     "${CUR}/packages.txt" \
  "extra packages — triage; attacker tools or app deps" \
  "removed packages — usually benign, but note if a security pkg vanished"

report_list "systemd unit files" "${GOLDEN}/unit_files.txt" "${CUR}/unit_files.txt" \
  "NEW units — TOP persistence spot; read each ExecStart (e.g. nc/reverse shell)" \
  "missing units — could be a renamed/removed service (DNS-exe-rename TTP)"

report_list "Enabled units"   "${GOLDEN}/units_enabled.txt" "${CUR}/units_enabled.txt" \
  "newly-enabled units — persistence" "disabled units — check if a scored service got disabled"

report_list "systemd timers"  "${GOLDEN}/timers.txt"       "${CUR}/timers.txt" \
  "new timers — scheduled persistence" "missing timers"

report_list "Listening ports" "${GOLDEN}/listening.txt"    "${CUR}/listening.txt" \
  "NEW listeners — candidate backdoor (map to a PID with: ss -tulnp)" \
  "ports no longer listening — a service may be DOWN (check scoring!)"

report_list "Login users"     "${GOLDEN}/login_users.txt"  "${CUR}/login_users.txt" \
  "EXTRA accounts — candidate backdoor users (userdel -r after confirming)" \
  "missing accounts"

report_list "UID-0 accounts"  "${GOLDEN}/uid0.txt"         "${CUR}/uid0.txt" \
  "EXTRA root-equivalent accounts — almost certainly a backdoor" "missing"

report_list "Admin group members" "${GOLDEN}/admin_groups.txt" "${CUR}/admin_groups.txt" \
  "new sudo/wheel members — privilege backdoor" "removed admins"

report_list "SUID/SGID files" "${GOLDEN}/suid_sgid.txt"    "${CUR}/suid_sgid.txt" \
  "NEW SUID/SGID — privilege-escalation backdoor (esp. shells/interpreters)" \
  "removed SUID — usually fine"

report_list "Cron entries"    "${GOLDEN}/cron.txt"         "${CUR}/cron.txt" \
  "new cron lines — persistence (look for curl/wget/base64/reverse shells)" "removed cron lines"

report_list "Kernel modules"  "${GOLDEN}/modules.txt"      "${CUR}/modules.txt" \
  "NEW modules — possible LKM rootkit (e.g. diamorphine)" "missing modules"

# PAM tree diff (structural).
sect "PAM configuration (/etc/pam.d)"
if [[ -d "${GOLDEN}/pam.d" ]]; then
  d="$(diff -rq "${GOLDEN}/pam.d" "${CUR}/pam.d" 2>/dev/null)"
  [[ -n "$d" ]] && { log "  >>> PAM differs from golden (cred-harvest / pam_exec backdoor?):"; echo "$d" | sed 's/^/        /' | tee -a "${REPORT}"; } \
    || log "  [✓] PAM matches golden"
else
  log "  (no golden PAM tree)"
fi

# sshd effective config diff.
sect "Effective sshd configuration"
if [[ -f "${GOLDEN}/sshd_effective.txt" && -f "${CUR}/sshd_effective.txt" ]]; then
  d="$(diff "${GOLDEN}/sshd_effective.txt" "${CUR}/sshd_effective.txt" 2>/dev/null)"
  [[ -n "$d" ]] && { log "  >>> sshd config differs (watch for TrustedUserCAKeys / AuthorizedKeysCommand / PermitRootLogin):"; echo "$d" | sed 's/^/        /' | tee -a "${REPORT}"; } \
    || log "  [✓] sshd effective config matches golden"
else
  log "  (no golden sshd config)"
fi

# Binary hash diff — changed/added/removed system binaries.
sect "System binary & security-lib hashes"
if [[ -f "${GOLDEN}/hashes.txt" && -f "${CUR}/hashes.txt" ]]; then
  # Build path->hash maps and compare by path.
  changed="$(join -j 2 <(sort -k2 "${GOLDEN}/hashes.txt") <(sort -k2 "${CUR}/hashes.txt") 2>/dev/null \
              | awk '$2!=$3{print $1}' )"
  addedb="$(comm -13 <(awk '{print $2}' "${GOLDEN}/hashes.txt" | sort) <(awk '{print $2}' "${CUR}/hashes.txt" | sort))"
  if [[ -n "${changed}" ]]; then
    log "  >>> CHANGED binaries (hash differs from clean — possible trojan):"
    echo "${changed}" | sed 's/^/        ~ /' | tee -a "${REPORT}"
  else
    log "  [✓] no changed binaries vs golden"
  fi
  if [[ -n "${addedb}" ]]; then
    log "  >>> ADDED files in system dirs (not on the clean box):"
    echo "${addedb}" | head -60 | sed 's/^/        + /' | tee -a "${REPORT}"
  fi
else
  log "  (hashes not captured — re-run without --quick, or golden lacks hashes)"
fi

rm -rf "${CUR}"

sect "HOW TO USE THIS OUTPUT"
log "  1. Start with UID-0, Login users, SUID, Kernel modules, PAM, sshd, CHANGED"
log "     binaries — these rarely differ legitimately, so additions are high-signal."
log "  2. For each NEW systemd unit / listening port / cron line: find the binary,"
log "     read it, document it for your IR inject, THEN remove it."
log "  3. Triage extra PACKAGES with a human eye (some are legit app components)."
log "  4. Cross-reference anything you find with hunt_malware.sh for confirmation."
log "\n  Report saved: ${REPORT}"
