#!/usr/bin/env bash
###############################################################################
# watch_services.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   A live "dashboard in a terminal." Every N seconds it:
#     (1) checks each scored service on THIS box (SSH / HTTP / DNS / DB) and
#         warns you BEFORE you hit the 5-consecutive-miss SLA penalty (which is
#         a 3x point hit), and
#     (2) watches for Red-Team tampering by diffing the live system against your
#         first5_secure.sh baseline: new listening ports, new UID-0 accounts,
#         changed SSH authorized_keys, new SUID files, new EXTERNAL connections,
#         and any monitored service that has stopped.
#
#   It is READ-ONLY. All probes hit localhost, so the monitor itself can never
#   trip fail2ban or look like an attacker to the scorer.
#
# WHY THIS MATTERS
#   Service points are 35% of your score and the SLA penalty triggers at 5
#   misses in a row. At a ~1-2 min scoring cadence that is only a few minutes of
#   downtime. Seeing "SSH DOWN (2 in a row)" immediately lets you fix it before
#   the penalty lands. One good check resets the counter.
#
# USAGE
#   ./watch_services.sh                       # auto-detect services, 30s loop
#   ./watch_services.sh --interval 20         # custom interval (seconds)
#   ./watch_services.sh --once                # run a single cycle and exit
#   ./watch_services.sh --baseline <dir>      # drift-compare against a specific baseline
#   sudo ./watch_services.sh                  # run as root for full drift detail (shadow/keys)
#
# OUTPUT
#   Live screen + ./reports/watch_<host>_<timestamp>.log
###############################################################################

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="${KIT_DIR}/reports/watch_${HOST}_${TS}.log"
mkdir -p "${KIT_DIR}/reports"

INTERVAL=30; ONCE=0; BASELINE_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval) INTERVAL="${2:-30}"; shift 2 ;;
    --once)     ONCE=1; shift ;;
    --baseline) BASELINE_DIR="${2:-}"; shift 2 ;;
    -h|--help)  grep -E '^#( |$)' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done
[[ -z "${BASELINE_DIR}" ]] && BASELINE_DIR="$(ls -1dt "${KIT_DIR}/baselines/${HOST}_"* 2>/dev/null | head -1)"

have() { command -v "$1" >/dev/null 2>&1; }
ts() { date '+%H:%M:%S'; }
logline() { echo -e "$*" | tee -a "${LOG}"; }

# Colors (fall back to plain if not a TTY).
if [[ -t 1 ]]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'; BOLD=$'\e[1m'
else R=""; G=""; Y=""; B=""; N=""; BOLD=""; fi

# --- detect which scored services this box actually runs ---------------------
# We probe a service only if it is listening, so each box monitors the right set
# (concierge -> SSH+HTTP, blacklist -> SSH+DB, etc.) with no assumptions.
LISTEN="$(ss -tulnH 2>/dev/null | awk '{print $5}')"
listens_on() { echo "${LISTEN}" | grep -qE "[:.]$1\$"; }

MON_SSH=0; MON_HTTP=0; MON_HTTPS=0; MON_DNS=0; MON_DB_MYSQL=0; MON_DB_PG=0; MON_FTP=0
listens_on 22  && MON_SSH=1
listens_on 80  && MON_HTTP=1
listens_on 443 && MON_HTTPS=1
listens_on 53  && MON_DNS=1
listens_on 3306 && MON_DB_MYSQL=1
listens_on 5432 && MON_DB_PG=1
listens_on 21  && MON_FTP=1

# Consecutive-failure counters (the SLA danger metric).
declare -A FAILS=()
SLA_WARN=3   # warn at 3 in a row; penalty hits at 5

# --- individual service probes (all localhost, all read-only) ----------------
# Each returns 0=up, 1=down and echoes a short status string.
probe_tcp() {  # probe_tcp <port>  — generic "is the port accepting connections"
  if have nc; then nc -z -w2 127.0.0.1 "$1" >/dev/null 2>&1; return $?; fi
  # bash /dev/tcp fallback (no nc needed)
  (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1 && { exec 3>&- 3<&-; return 0; } || return 1
}
probe_ssh()  { probe_tcp 22; }
probe_http() {
  if have curl; then
    local code; code="$(curl -s -o /dev/null -m 3 -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)"
    # Any HTTP response (even 401/403 from AD auth) means the web server is UP.
    [[ "${code}" =~ ^[1-5][0-9][0-9]$ && "${code}" != "000" ]]
  else probe_tcp 80; fi
}
probe_https() {
  if have curl; then
    local code; code="$(curl -sk -o /dev/null -m 3 -w '%{http_code}' https://127.0.0.1/ 2>/dev/null)"
    [[ "${code}" =~ ^[1-5][0-9][0-9]$ && "${code}" != "000" ]]
  else probe_tcp 443; fi
}
probe_dns()  {
  if have dig; then dig +time=2 +tries=1 @127.0.0.1 localhost A >/dev/null 2>&1
  elif have nslookup; then nslookup -timeout=2 localhost 127.0.0.1 >/dev/null 2>&1
  else probe_tcp 53; fi
}
probe_mysql(){ probe_tcp 3306; }
probe_pg()   { probe_tcp 5432; }
probe_ftp()  { probe_tcp 21; }

# check_one <NAME> <probe-fn> <is-ssh 0/1 for SLA threshold wording>
check_one() {
  local name="$1" fn="$2"
  if "${fn}"; then
    FAILS[$name]=0
    logline "  ${G}[UP]${N}   ${name}"
  else
    FAILS[$name]=$(( ${FAILS[$name]:-0} + 1 ))
    local c=${FAILS[$name]}
    if [[ $c -ge 5 ]]; then
      logline "  ${R}${BOLD}[DOWN]${N} ${name}  <<< ${c} IN A ROW — SLA 3x PENALTY RANGE. FIX NOW."
    elif [[ $c -ge ${SLA_WARN} ]]; then
      logline "  ${R}[DOWN]${N} ${name}  <<< ${c} in a row (penalty at 5) — investigate now"
    else
      logline "  ${Y}[DOWN]${N} ${name}  (${c} in a row)"
    fi
  fi
}

###############################################################################
# DRIFT DETECTION vs baseline (only if a baseline exists)
###############################################################################
DRIFT_PORTS="${KIT_DIR}/reports/.last_ports_${HOST}"
check_drift() {
  [[ -n "${BASELINE_DIR}" && -d "${BASELINE_DIR}" ]] || { logline "  ${Y}[drift]${N} no baseline found; skipping drift checks"; return; }

  # (1) New listening ports vs baseline (a new port = possible backdoor listener).
  if [[ -f "${BASELINE_DIR}/listening_ports.txt" ]]; then
    local base_ports cur_ports newp
    base_ports="$(grep -oE '[0-9]+ ' "${BASELINE_DIR}/listening_ports.txt" 2>/dev/null | sort -un)"
    cur_ports="$(ss -tulnH 2>/dev/null | awk '{print $5}' | sed -E 's/.*[:.]([0-9]+)$/\1/' | sort -un)"
    newp="$(comm -13 <(echo "${base_ports}") <(echo "${cur_ports}") 2>/dev/null | tr '\n' ' ')"
    [[ -n "${newp// /}" ]] && logline "  ${R}[drift]${N} NEW listening port(s) since baseline: ${newp} — check 'ss -tulnp'"
  fi

  # (2) New UID-0 accounts (backdoor root).
  if [[ -f "${BASELINE_DIR}/uid0_accounts.txt" ]]; then
    local cur0; cur0="$(awk -F: '$3==0{print $1}' /etc/passwd | sort)"
    local new0; new0="$(comm -13 <(sort "${BASELINE_DIR}/uid0_accounts.txt") <(echo "${cur0}") | tr '\n' ' ')"
    [[ -n "${new0// /}" ]] && logline "  ${R}[drift]${N} NEW UID-0 account(s): ${new0} — likely backdoor, investigate!"
  fi

  # (3) authorized_keys changed (new backdoor key). Needs root to read all homes.
  if [[ -f "${BASELINE_DIR}/authorized_keys.txt" && ${EUID} -eq 0 ]]; then
    local cur_ak; cur_ak="$(mktemp)"
    while IFS=: read -r u _ uid _ _ home _; do
      [[ -f "${home}/.ssh/authorized_keys" ]] && { echo "### ${u}"; cat "${home}/.ssh/authorized_keys"; } >> "${cur_ak}"
    done < /etc/passwd
    if ! diff -q "${BASELINE_DIR}/authorized_keys.txt" "${cur_ak}" >/dev/null 2>&1; then
      logline "  ${R}[drift]${N} SSH authorized_keys CHANGED since baseline — a backdoor key may have been added!"
    fi
    rm -f "${cur_ak}"
  fi

  # (4) New SUID/SGID files.
  if [[ -f "${BASELINE_DIR}/suid_sgid.txt" ]]; then
    local cur_suid; cur_suid="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' 2>/dev/null | sort)"
    local new_suid; new_suid="$(comm -13 <(sort "${BASELINE_DIR}/suid_sgid.txt") <(echo "${cur_suid}") | head -10)"
    [[ -n "${new_suid}" ]] && { logline "  ${R}[drift]${N} NEW SUID/SGID file(s):"; echo "${new_suid}" | sed "s/^/        /" | tee -a "${LOG}"; }
  fi

  # (5) New connections to EXTERNAL (non-private) IPs (live C2 beacon).
  local extconn
  extconn="$(ss -tnp state established 2>/dev/null | awk '{print $5}' \
              | grep -vE '^(127\.|\[?::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
              | grep -E '^[0-9]' | sort -u | head -10)"
  [[ -n "${extconn}" ]] && { logline "  ${R}[drift]${N} Established connection(s) to EXTERNAL IP(s) — possible C2/exfil:"; echo "${extconn}" | sed "s/^/        /" | tee -a "${LOG}"; logline "        -> identify the process ('ss -tnp'), document for IR, then block: defend_redteam.sh block <ip>"; }
}

###############################################################################
# one full monitoring cycle
###############################################################################
cycle() {
  logline "\n${B}==== ${HOST}  $(ts)  (interval ${INTERVAL}s) ====${N}"
  logline "${BOLD}Scored services:${N}"
  [[ $MON_SSH   -eq 1 ]] && check_one "SSH(22)"     probe_ssh
  [[ $MON_HTTP  -eq 1 ]] && check_one "HTTP(80)"    probe_http
  [[ $MON_HTTPS -eq 1 ]] && check_one "HTTPS(443)"  probe_https
  [[ $MON_DNS   -eq 1 ]] && check_one "DNS(53)"     probe_dns
  [[ $MON_DB_MYSQL -eq 1 ]] && check_one "MySQL/MariaDB(3306)" probe_mysql
  [[ $MON_DB_PG -eq 1 ]] && check_one "PostgreSQL(5432)" probe_pg
  [[ $MON_FTP   -eq 1 ]] && check_one "FTP(21)"     probe_ftp
  if [[ $((MON_SSH+MON_HTTP+MON_HTTPS+MON_DNS+MON_DB_MYSQL+MON_DB_PG+MON_FTP)) -eq 0 ]]; then
    logline "  ${Y}(no known scored ports detected listening — is a service down already? check 'ss -tulnp')${N}"
  fi
  logline "${BOLD}Tamper / drift watch:${N}"
  check_drift
}

# --- intro -------------------------------------------------------------------
logline "eCitadel watch_services.sh | host=${HOST} | started $(date)"
logline "Monitoring => SSH:${MON_SSH} HTTP:${MON_HTTP} HTTPS:${MON_HTTPS} DNS:${MON_DNS} MySQL:${MON_DB_MYSQL} PG:${MON_DB_PG} FTP:${MON_FTP}"
[[ -n "${BASELINE_DIR}" ]] && logline "Baseline for drift: ${BASELINE_DIR}" || logline "${Y}No baseline yet — run first5_secure.sh to enable tamper detection.${N}"
logline "Log: ${LOG}"
[[ ${EUID} -ne 0 ]] && logline "${Y}(tip: run with sudo to also watch authorized_keys/shadow drift)${N}"

trap 'logline "\n[stopped $(ts)]"; exit 0' INT TERM

if [[ "${ONCE}" -eq 1 ]]; then
  cycle
else
  logline "\nPress Ctrl-C to stop. Looping every ${INTERVAL}s..."
  while true; do
    cycle
    sleep "${INTERVAL}"
  done
fi
