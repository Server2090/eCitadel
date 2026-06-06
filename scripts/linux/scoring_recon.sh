#!/usr/bin/env bash
###############################################################################
# scoring_recon.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   Help you figure out EXACTLY how scoring is behaving against THIS box, using
#   only the box's own logs and live socket table (100% read-only, localhost).
#   It answers three practical questions:
#
#     1. Are my scored services actually being checked AND passing right now?
#        (It finds successful SSH logins / HTTP 2xx-3xx responses / DNS answers
#         that match the scorer's behavior.)
#     2. What is the real scoring CADENCE in minutes? (So you know how long a
#        service can be down before the 5-consecutive-miss SLA penalty — the
#        orientation says ~2-3 min/check, this MEASURES it on your box.)
#     3. Which source IPs are hitting my scored ports, how often, and are they
#        succeeding or failing? (To understand who the scorer/Orange-Team are
#        vs. noise — NOT to build an inbound block list; see the big warning.)
#
#   *** WHY THIS DOES NOT BUILD AN INBOUND IP BLOCKLIST ***
#   The orientation is explicit: the scoring engine REUSES and ROTATES its IP,
#   and it lives in the SAME SUBNET as the Red Team. So you CANNOT safely tell
#   "scorer" from "attacker" by IP — block the wrong one and you lose the check.
#   The correct way to "block everything but scoring and real users" is:
#       * keep scored ports open to everyone (don't IP-filter inbound), and
#       * gate access with strong host hardening + AD auth, and
#       * block C2/exfil on the EGRESS side (defend_redteam.sh egress-lockdown),
#       * and REMOVE the pre-planted malware (hunt_malware.sh).
#   This script gives you the visibility; the egress tool gives you the block.
#   See docs/HOW_SCORING_WORKS.md for the full reasoning.
#
# USAGE
#   sudo ./scoring_recon.sh                 # observe live for 15 min, then report
#   sudo ./scoring_recon.sh --window 30     # observe for 30 minutes
#   sudo ./scoring_recon.sh --logs-only     # just analyze existing logs, no wait
#   sudo ./scoring_recon.sh --once          # one snapshot of current connections
#
# OUTPUT
#   ./reports/scoring_<host>_<timestamp>.log
###############################################################################

set -u
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
TS="$(date +%Y%m%d_%H%M%S)"
REPORT="${KIT_DIR}/reports/scoring_${HOST}_${TS}.log"
mkdir -p "${KIT_DIR}/reports"

WINDOW_MIN=15; MODE="observe"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --window)    WINDOW_MIN="${2:-15}"; shift 2 ;;
    --logs-only) MODE="logs"; shift ;;
    --once)      MODE="once"; shift ;;
    -h|--help)   grep -E '^#( |$)' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
log()  { echo -e "$*" | tee -a "${REPORT}"; }
sect() { log "\n========== $* =========="; }
[[ ${EUID} -ne 0 ]] && log "[i] tip: run with sudo so SSH auth events in the journal are readable."

log "eCitadel scoring_recon.sh | host=${HOST} | $(date)"
log "Report: ${REPORT}"

OS_ID=""; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID:-}"; fi
case "${OS_ID}" in
  debian|ubuntu|linuxmint) OS_FAMILY="debian" ;;
  fedora|rhel|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
esac

###############################################################################
# 0. The DOCUMENTED scoring facts (reference — verify them against measurement).
###############################################################################
print_known_facts() {
  sect "Documented scoring rules (from the orientation) — your yardstick"
  log "  * Cadence: external engine checks at RANDOM ~2-3 min intervals."
  log "  * Points : non-SSH service up+functional = 3 ; SSH up = 1 ; down = 0."
  log "  * SLA    : 5 CONSECUTIVE misses = penalty (15 non-SSH / 5 SSH). Non-"
  log "             overlapping; ONE good check resets the counter to zero."
  log "  * Web    : the check LOGS IN and performs an action (AD auth). A static"
  log "             page or a broken login = 0, even if the homepage loads."
  log "  * Auth   : almost all checks use Active Directory (rrintel.internal)."
  log "             If the DC/DNS is down, many checks cascade to FAIL."
  log "  * IPs    : the scorer REUSES + ROTATES its IP and shares the Red Team's"
  log "             subnet — so do NOT block inbound by IP. (Egress + hardening.)"
  log "  * Reach  : services are scored on your EXTERNAL IP (172.27.76.x)."
}

###############################################################################
# 1. Which scored services does THIS box expose? (no assumptions)
###############################################################################
LISTEN="$(ss -tulnH 2>/dev/null | awk '{print $5}')"
lon() { echo "${LISTEN}" | grep -qE "[:.]$1\$"; }
SCORED_PORTS=()
lon 22  && SCORED_PORTS+=(22)
lon 80  && SCORED_PORTS+=(80)
lon 443 && SCORED_PORTS+=(443)
lon 53  && SCORED_PORTS+=(53)
report_scope() {
  sect "Scored ports detected listening on this box"
  if [[ ${#SCORED_PORTS[@]} -eq 0 ]]; then
    log "  (none of 22/80/443/53 are listening — is a scored service already down?)"
  else
    log "  ${SCORED_PORTS[*]}"
  fi
  log "  (DNS scoring is primarily on the Windows DC 'cabal'; SSH/HTTP are the"
  log "   Linux-scored services this script watches in the logs.)"
}

###############################################################################
# 2. Live connection sampler — who is connecting to scored ports right now.
#    We append every observed remote IP+port to a tally file.
###############################################################################
TALLY="$(mktemp)"            # lines: <epoch> <port> <peer_ip>
sample_connections() {
  local p peer ip filt now
  now="$(date +%s)"
  for p in "${SCORED_PORTS[@]}"; do
    # Established inbound connections whose LOCAL port == the scored port.
    while read -r line; do
      [[ -z "$line" ]] && continue
      peer="$(awk '{print $5}' <<<"$line")"
      ip="${peer%:*}"; ip="${ip#[}"; ip="${ip%]}"
      [[ -n "$ip" ]] && echo "${now} ${p} ${ip}" >> "${TALLY}"
    done < <(ss -tnH state established "( sport = :${p} )" 2>/dev/null)
  done
}

###############################################################################
# 3. Log analysis — successes/failures + timestamps (to infer cadence).
#    SSH from journald (reliable on both distros). HTTP from access logs.
###############################################################################
SSH_OK="$(mktemp)"    # epoch of each successful SSH login
SSH_BAD="$(mktemp)"   # "ip count" of failed SSH logins
HTTP_OK="$(mktemp)"   # epoch of each 2xx/3xx response
analyze_ssh_log() {
  have journalctl || { log "[i] no journalctl; skipping SSH log analysis."; return; }
  local since="$1"
  # Successful logins → timestamps (for cadence) + source IPs.
  journalctl _COMM=sshd --since "${since}" -o short-iso --no-pager 2>/dev/null \
    | grep -E 'Accepted (password|publickey)' \
    | while read -r ln; do
        # ISO timestamp is field 1; source IP follows "from".
        local iso ip
        iso="$(awk '{print $1}' <<<"$ln")"
        ip="$(grep -oE 'from [0-9.]+' <<<"$ln" | awk '{print $2}')"
        date -d "$iso" +%s 2>/dev/null >> "${SSH_OK}"
        [[ -n "$ip" ]] && echo "$ip" >> "${KIT_DIR}/reports/.ssh_ok_ips.$$"
      done
  # Failed logins → per-IP counts (candidate noise / brute force — DO NOT auto-block).
  journalctl _COMM=sshd --since "${since}" --no-pager 2>/dev/null \
    | grep -E 'Failed password|Invalid user|authentication failure' \
    | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn > "${SSH_BAD}"
}

http_access_files() {
  # Echo whichever access logs exist on this box.
  local f
  for f in /var/log/httpd/access_log /var/log/httpd/*access*log \
           /var/log/apache2/access.log /var/log/apache2/*access*.log \
           /var/log/nginx/access.log /var/log/nginx/*access*.log; do
    [[ -f "$f" ]] && echo "$f"
  done | sort -u
}
analyze_http_log() {
  local f line ts ep status ip
  local files; files="$(http_access_files)"
  [[ -z "$files" ]] && { log "[i] no web access log found (web app may log elsewhere)."; return; }
  for f in $files; do
    # Common Log Format: IP ident user [dd/Mon/yyyy:HH:MM:SS +z] "METHOD path HTTP/x" status size
    tail -n 5000 "$f" 2>/dev/null | while IFS= read -r line; do
      ip="$(awk '{print $1}' <<<"$line")"
      status="$(grep -oE '" [0-9]{3} ' <<<"$line" | tr -d '" ' | head -1)"
      ts="$(grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}' <<<"$line" | tr -d '[')"
      [[ -z "$status" ]] && continue
      # Count a successful, functional-looking check as 2xx/3xx.
      if [[ "$status" =~ ^[23] ]]; then
        ep="$(date -d "$(sed -E 's#([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):#\3-\2-\1 #' <<<"$ts")" +%s 2>/dev/null)"
        [[ -n "$ep" ]] && echo "$ep" >> "${HTTP_OK}"
        [[ -n "$ip" ]] && echo "$ip" >> "${KIT_DIR}/reports/.http_ok_ips.$$"
      fi
    done
  done
}

###############################################################################
# 4. Cadence calculator — min/mean/max gap between successes in a timestamp file.
###############################################################################
cadence_of() {  # cadence_of <file-of-epochs> <label>
  local f="$1" label="$2"
  [[ -s "$f" ]] || { log "  ${label}: no successful checks observed yet."; return; }
  sort -n "$f" | awk -v L="$label" '
    NR>1 { d=$1-prev; if(d>0){ sum+=d; n++; if(min==""||d<min)min=d; if(d>max)max=d } }
    { prev=$1 }
    END {
      if(n>0) printf "  %s: %d checks | gap min=%ds mean=%ds max=%ds (~%.1f min mean)\n", L, n+1, min, sum/n, max, (sum/n)/60
      else    printf "  %s: only 1 check seen (need 2+ to measure a gap)\n", L
    }'
}

###############################################################################
# 5. Per-IP summary from the live sampler.
###############################################################################
summarize_sources() {
  sect "Source IPs seen on scored ports (live sampler)"
  if [[ ! -s "${TALLY}" ]]; then
    log "  (no inbound connections captured — checks are brief; try a longer --window)"
    return
  fi
  log "  count  port(s)            source-IP        likely-role (heuristic)"
  # Aggregate by IP: total samples, distinct ports.
  awk '{cnt[$3]++; ports[$3]=ports[$3]" "$2} END{for(ip in cnt) print cnt[ip], ip, ports[ip]}' "${TALLY}" \
    | sort -rn | while read -r cnt ip prts; do
        local uniqp role
        uniqp="$(echo $prts | tr ' ' '\n' | sort -un | tr '\n' ',' | sed 's/,$//; s/^,//')"
        # Heuristic role — explicitly NOT a block recommendation.
        if grep -qxF "$ip" "${KIT_DIR}/reports/.ssh_ok_ips.$$" 2>/dev/null \
           || grep -qxF "$ip" "${KIT_DIR}/reports/.http_ok_ips.$$" 2>/dev/null; then
          role="authenticated OK -> scorer/Orange-Team or you"
        else
          role="connected, no successful auth seen -> watch (do NOT auto-block)"
        fi
        printf "  %-5s  %-18s %-15s  %s\n" "$cnt" "$uniqp" "$ip" "$role" | tee -a "${REPORT}"
      done
  log "\n  Reminder: the scorer rotates IPs and shares Red Team's subnet. Use this to"
  log "  CONFIRM checks are landing and to see cadence — never as an inbound blocklist."
}

###############################################################################
# 6. Failed-auth view (investigate, don't auto-ban).
###############################################################################
show_failed_auth() {
  sect "Failed SSH auth by source (investigate; Red Team uses planted creds, so"
  log   "   floods here are often noise/misconfig — confirm before any action)"
  if [[ -s "${SSH_BAD}" ]]; then
    head -15 "${SSH_BAD}" | sed 's/^/   /' | tee -a "${REPORT}"
    log "   If ONE external IP is clearly hammering you AND you've confirmed it isn't"
    log "   the scorer, the cautious lever is defend_redteam.sh fail2ban (whitelists"
    log "   the scorer ranges) — not a manual inbound IP block."
  else
    log "   (no failed SSH auth in the window — good)"
  fi
}

###############################################################################
# MAIN
###############################################################################
print_known_facts
report_scope

if [[ "${MODE}" == "once" ]]; then
  sample_connections
  summarize_sources
elif [[ "${MODE}" == "logs" ]]; then
  analyze_ssh_log "${WINDOW_MIN} min ago"
  analyze_http_log
  sect "Measured scoring cadence (from existing logs)"
  cadence_of "${SSH_OK}"  "SSH  successful logins"
  cadence_of "${HTTP_OK}" "HTTP 2xx/3xx responses"
  show_failed_auth
else
  # Observe: sample live connections every 5s for the window, in parallel with
  # a one-shot log pull at the end (logs already contain the same window).
  local_end=$(( $(date +%s) + WINDOW_MIN*60 ))
  log "\n[*] Observing live for ${WINDOW_MIN} min (sampling every 5s). Ctrl-C to stop early."
  trap 'log "\n[interrupted — analyzing what we have]"; ANALYZE=1' INT
  ANALYZE=0
  while [[ $(date +%s) -lt ${local_end} && ${ANALYZE} -eq 0 ]]; do
    sample_connections
    sleep 5
  done
  analyze_ssh_log "${WINDOW_MIN} min ago"
  analyze_http_log
  sect "Measured scoring cadence (this window)"
  cadence_of "${SSH_OK}"  "SSH  successful logins"
  cadence_of "${HTTP_OK}" "HTTP 2xx/3xx responses"
  summarize_sources
  show_failed_auth
fi

# --- verdict ------------------------------------------------------------------
sect "VERDICT"
ssh_n=$(wc -l < "${SSH_OK}" 2>/dev/null || echo 0)
http_n=$(wc -l < "${HTTP_OK}" 2>/dev/null || echo 0)
if [[ "${ssh_n}" -gt 0 || "${http_n}" -gt 0 ]]; then
  log "  [✓] Successful checks observed (SSH OK=${ssh_n}, HTTP-2xx/3xx=${http_n})."
  log "      That means the scoring engine is reaching you and your AD auth path works."
else
  log "  [!] No successful SSH/HTTP checks observed in this window."
  log "      Either nothing was scored yet, the service is failing the functional"
  log "      check (e.g. login broken / AD or DB down), or logs live elsewhere."
  log "      Cross-check with: scripts/watch_services.sh --once"
fi
log "\n  Full reasoning + the 'allow scoring, block the rest' method: docs/HOW_SCORING_WORKS.md"

# cleanup temp files
rm -f "${TALLY}" "${SSH_OK}" "${SSH_BAD}" "${HTTP_OK}" \
      "${KIT_DIR}/reports/.ssh_ok_ips.$$" "${KIT_DIR}/reports/.http_ok_ips.$$" 2>/dev/null
