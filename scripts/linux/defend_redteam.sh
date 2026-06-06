#!/usr/bin/env bash
###############################################################################
# defend_redteam.sh  —  eCitadel Team 76  —  Fedora 43 / Debian 13
#
# PURPOSE
#   Block the AUTOMATED Red Team without breaking the scoring engine.
#
#   The competition rules (3.8) explicitly ALLOW firewall rules, TCP resets,
#   IDS/IPS and active response — BUT anything that breaks the scoring engine or
#   the graders' manual checks is YOUR fault and costs YOU points. So this tool
#   is built around one principle:
#
#       *** Never touch the INBOUND path the scoring engine uses. ***
#
#   The scorer connects FROM somewhere TO your external IPs on SSH/HTTP/DNS.
#   The two levers that cannot hurt that path are:
#
#     1. EGRESS blocking — stop YOUR box from talking OUT to a C2 server.
#        A beacon/exfil dies; inbound scoring is untouched. 100% safe.
#     2. Blocking a SPECIFIC confirmed-malicious external IP (in + out).
#        The scorer is a different IP, so its checks keep passing.
#
#   It deliberately does NOT block whole subnets (rule says don't) and refuses
#   to block any private/internal IP or the out-of-scope .1/.2 hosts, so you
#   cannot fat-finger the scorer's network.
#
#   fail2ban is offered too, but as an OPT-IN secondary layer with a cautious
#   config (whitelists the internal/scorer ranges, short bans, lenient retry)
#   because an over-eager jail is the #1 way teams accidentally ban the scorer.
#
# IMPLEMENTATION
#   Uses a DEDICATED nftables table called `ecitadel_block` that sits alongside
#   firewalld (Fedora) or ufw/nftables (Debian) without interfering with them.
#   A drop in this table is authoritative regardless of the other firewall.
#
# USAGE
#   sudo ./defend_redteam.sh init                 # create the (empty) blocklist; blocks nothing yet
#   sudo ./defend_redteam.sh block 203.0.113.7    # block a CONFIRMED-bad external IP (in+out)
#   sudo ./defend_redteam.sh block 1.2.3.4 5.6.7.8
#   sudo ./defend_redteam.sh unblock 203.0.113.7  # remove a block
#   sudo ./defend_redteam.sh list                 # show what's blocked
#   sudo ./defend_redteam.sh fail2ban             # PRINT a cautious config (dry-run, changes nothing)
#   sudo ./defend_redteam.sh fail2ban --apply     # install + apply that config (with warnings)
#   sudo ./defend_redteam.sh fail2ban-status      # show jails + currently banned IPs (spot a banned scorer!)
#   sudo ./defend_redteam.sh unban 198.51.100.9   # immediately unban an IP from fail2ban
###############################################################################

set -u
umask 077
if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run with sudo/root (manages firewall/nftables)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="$(hostname -s 2>/dev/null || echo host)"
REPORT="${KIT_DIR}/reports/defend_${HOST}_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "${KIT_DIR}/reports"
log() { echo -e "$*" | tee -a "${REPORT}"; }
have() { command -v "$1" >/dev/null 2>&1; }

OS_ID=""; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID:-}"; fi
case "${OS_ID}" in
  debian|ubuntu|linuxmint) OS_FAMILY="debian" ;;
  fedora|rhel|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
  *) OS_FAMILY="unknown" ;;
esac

TABLE="ecitadel_block"   # our dedicated nftables table name

# --- safety: refuse to block IPs we must never block -------------------------
# Returns 0 (refuse) if the IP is private/internal/loopback or an out-of-scope
# host. This is what stops you from ever blocking the scorer or your own LAN.
must_not_block() {  # must_not_block <ip>
  local ip="$1"
  case "$ip" in
    127.*|::1|0.0.0.0|169.254.*) echo "loopback/link-local"; return 0 ;;
    10.*|192.168.*) echo "RFC1918 private"; return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) echo "RFC1918 private (includes 172.21 internal & 172.27 scored NAT)"; return 0 ;;
  esac
  # Out-of-scope / do-not-touch hosts from the orientation (upstream router,
  # pfSense WAN transit). Adjust if your packet differs.
  case "$ip" in
    172.21.1.1|172.21.1.2) echo "out-of-scope transit host (rules say do not touch)"; return 0 ;;
  esac
  return 1
}

valid_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

###############################################################################
# nftables blocklist plumbing
###############################################################################
ensure_table() {
  if ! have nft; then
    log "[!] 'nft' (nftables) not found. Installing..."
    if [[ "${OS_FAMILY}" == "debian" ]]; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >>"${REPORT}" 2>&1
    elif [[ "${OS_FAMILY}" == "rhel" ]]; then
      dnf install -y nftables >>"${REPORT}" 2>&1
    fi
  fi
  have nft || { log "[!] nftables unavailable; cannot manage blocklist. Block IPs in pfSense instead."; return 1; }

  # Create the table/set/chains only if absent (idempotent). The set uses
  # 'interval' flags so it can also hold CIDR ranges if you ever need them.
  if ! nft list table inet "${TABLE}" >/dev/null 2>&1; then
    nft add table inet "${TABLE}"
    nft add set inet "${TABLE}" c2_addrs '{ type ipv4_addr; flags interval; }'
    # priority -100 = runs early; policy accept = we ONLY drop set members,
    # so this table never blocks anything except IPs you explicitly add.
    nft add chain inet "${TABLE}" out '{ type filter hook output priority -100; policy accept; }'
    nft add chain inet "${TABLE}" in  '{ type filter hook input  priority -100; policy accept; }'
    nft add rule  inet "${TABLE}" out ip daddr @c2_addrs counter drop
    nft add rule  inet "${TABLE}" in  ip saddr @c2_addrs counter drop
    log "[✓] Created nftables table '${TABLE}' (egress+ingress drop for listed IPs). Currently empty."
  fi
  return 0
}

# ensure_nft_present : make sure nftables is installed, but DON'T create the
# blocklist table (the egress lockdown manages its own separate table).
ensure_nft_present() {
  if ! have nft; then
    log "[!] 'nft' (nftables) not found. Installing..."
    if [[ "${OS_FAMILY}" == "debian" ]]; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >>"${REPORT}" 2>&1
    elif [[ "${OS_FAMILY}" == "rhel" ]]; then
      dnf install -y nftables >>"${REPORT}" 2>&1
    fi
  fi
  have nft || { log "[!] nftables unavailable; do egress filtering on pfSense instead."; return 1; }
  return 0
}

cmd_init() {
  ensure_table || exit 1
  log "[i] Blocklist ready. Nothing is blocked yet. Add a confirmed-bad IP with:"
  log "      sudo $0 block <ip>"
}

cmd_block() {
  [[ $# -ge 1 ]] || { log "Usage: $0 block <ip> [ip...]"; exit 1; }
  ensure_table || exit 1
  for ip in "$@"; do
    if ! valid_ipv4 "$ip"; then log "[!] '${ip}' is not a valid IPv4 — skipped."; continue; fi
    local why; why="$(must_not_block "$ip" || true)"
    if [[ -n "$why" ]]; then
      log "[REFUSED] ${ip} — ${why}. (This protects the scorer/your LAN. Block in pfSense if truly needed.)"
      continue
    fi
    nft add element inet "${TABLE}" c2_addrs "{ ${ip} }" 2>>"${REPORT}" \
      && log "[✓] BLOCKED ${ip} (egress + ingress). Beacon/exfil to this host now dies; inbound scoring unaffected." \
      || log "[!] Failed to add ${ip} (already blocked?)."
  done
  log "    Review: sudo $0 list"
}

cmd_unblock() {
  [[ $# -ge 1 ]] || { log "Usage: $0 unblock <ip> [ip...]"; exit 1; }
  ensure_table || exit 1
  for ip in "$@"; do
    nft delete element inet "${TABLE}" c2_addrs "{ ${ip} }" 2>>"${REPORT}" \
      && log "[✓] Unblocked ${ip}." || log "[!] ${ip} was not in the blocklist."
  done
}

cmd_list() {
  if have nft && nft list table inet "${TABLE}" >/dev/null 2>&1; then
    log "Currently blocked IPs (table inet ${TABLE}):"
    nft list set inet "${TABLE}" c2_addrs 2>/dev/null | sed 's/^/    /' | tee -a "${REPORT}"
    log "\nDrop counters (how many packets each rule has stopped):"
    nft list chain inet "${TABLE}" out 2>/dev/null | grep -E 'counter' | sed 's/^/    out: /'
    nft list chain inet "${TABLE}" in  2>/dev/null | grep -E 'counter' | sed 's/^/    in:  /'
  else
    log "[i] Blocklist table not created yet. Run: sudo $0 init"
  fi
}

###############################################################################
# EGRESS LOCKDOWN — "block everything OUT except what scoring & real users need."
#
#   This is the SAFEST possible anti-Red-Team lever. It does not touch the
#   inbound path at all, so the scoring engine and Orange-Team users (who connect
#   IN to you) are completely unaffected — their reply traffic is allowed by the
#   established/related rule. What it DOES is stop YOUR box from initiating new
#   outbound connections to the internet, which kills:
#       * C2 beacons (Realm/Sliver calling home),
#       * password/data exfil to webhooks (the recompiled-PAM trick),
#       * the "phone home" half of most pre-planted malware.
#
#   What stays allowed (so nothing scored breaks):
#       * loopback,
#       * established/related (replies to the scorer / Orange Team / your SSH),
#       * everything to the INTERNAL subnet 172.21.0.0/24 — that's your DC
#         (AD / Kerberos / LDAP / DNS) and your database, which the web auth and
#         service checks depend on,
#       * DNS (port 53) to your configured resolvers only,
#       * ICMP (ping / path-MTU).
#
#   TRADE-OFF: it also blocks outbound to the internet, so `dnf`/`apt` package
#   updates won't work while locked down. Recommended workflow:
#       1) run your updates first (or run `egress-restore`, update, then re-lock),
#       2) `egress-lockdown`,
#       3) keep it on for the rest of the round.
#   Fully reversible: `egress-restore` deletes the table instantly.
###############################################################################
ETABLE="ecitadel_egress"
INTERNAL_SUBNET="172.21.0.0/24"   # RR Intel internal LAN (DC + DB live here)

cmd_egress_lockdown() {
  ensure_nft_present || exit 1

  # Gather the DNS resolvers actually in use so name resolution keeps working
  # even if they're external. (If they're the internal DC, they're covered by
  # the internal-subnet rule too — allowing twice is harmless.)
  local resolvers
  resolvers="$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | sort -u)"
  # systemd-resolved stub (127.0.0.53) is covered by loopback; collect real ones.
  local dns_rules=""
  local r
  for r in ${resolvers}; do
    case "$r" in
      127.*|::1) continue ;;                       # loopback handled separately
    esac
    if [[ "$r" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      dns_rules+="        ip daddr ${r} udp dport 53 accept
        ip daddr ${r} tcp dport 53 accept
"
    fi
  done

  log "[*] Resolvers detected: ${resolvers:-none (will rely on internal subnet)}"
  log "[*] Building egress allow-list: lo + established/related + ${INTERNAL_SUBNET} + DNS-to-resolvers + icmp; DROP the rest."

  # Build the table atomically with `nft -f` so we are never half-applied.
  local tmpf; tmpf="$(mktemp)"
  cat > "${tmpf}" <<EOF
table inet ${ETABLE} {
    chain out {
        type filter hook output priority -50; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr ${INTERNAL_SUBNET} accept
${dns_rules}        ip protocol icmp accept
        counter comment "ecitadel egress: dropped (no C2/exfil allowed)"
    }
}
EOF
  # Replace any previous version of just our table (leave other firewalls alone).
  nft delete table inet "${ETABLE}" 2>/dev/null || true
  if nft -f "${tmpf}" 2>>"${REPORT}"; then
    log "[✓] Egress LOCKED. Outbound C2/exfil to the internet is now dropped."
    log "    Inbound scoring is UNAFFECTED (replies allowed via established/related)."
    log "    Remember: package updates are blocked until you run: sudo $0 egress-restore"
  else
    log "[!] Failed to apply egress lockdown (see ${REPORT}). No changes left behind."
    nft delete table inet "${ETABLE}" 2>/dev/null || true
  fi
  rm -f "${tmpf}"
  log "    Watch what it stops: sudo $0 egress-status"
}

cmd_egress_restore() {
  have nft || { log "[i] nft not present; nothing to restore."; return 0; }
  if nft list table inet "${ETABLE}" >/dev/null 2>&1; then
    nft delete table inet "${ETABLE}" 2>>"${REPORT}" \
      && log "[✓] Egress lockdown REMOVED. Outbound traffic is unrestricted again (updates will work)." \
      || log "[!] Could not delete the egress table; check 'nft list ruleset'."
  else
    log "[i] Egress lockdown is not currently active."
  fi
}

cmd_egress_status() {
  have nft || { log "[i] nft not present."; return 0; }
  if nft list table inet "${ETABLE}" >/dev/null 2>&1; then
    log "Egress lockdown is ACTIVE. Current rules + drop counter:"
    nft list table inet "${ETABLE}" 2>/dev/null | sed 's/^/    /' | tee -a "${REPORT}"
    log "\nA rising drop counter while a service stays green = you are killing C2 without hurting scoring."
  else
    log "Egress lockdown is NOT active. Enable with: sudo $0 egress-lockdown"
  fi
}

###############################################################################
# fail2ban — OPTIONAL, cautious. Whitelists internal+scored ranges, short bans.
###############################################################################
F2B_JAIL="/etc/fail2ban/jail.local"
print_f2b_config() {
  # 172.16.0.0/12 covers BOTH 172.21.0.0/24 (internal) and 172.27.0.0/16
  # (scored external NAT), so the scoring engine — whichever side it comes
  # from — is whitelisted and can never be banned by these jails.
  local banaction_line=""
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    banaction_line="banaction = nftables-multiport   # Debian 13 default backend is nftables"
  else
    banaction_line="# banaction defaults to firewalld on Fedora — leave as-is"
  fi
  cat <<EOF
# ${F2B_JAIL}  — eCitadel Team 76 cautious config
[DEFAULT]
# Read auth events from the systemd journal (auth.log may not exist on either box).
backend = systemd
# NEVER ban these — internal range + scored NAT range + loopback.
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
# Lenient on purpose: a legit scorer using correct creds never fails auth, but
# this guarantees we don't ban on a transient hiccup. Short ban so any mistake
# self-heals fast (one good check resets SLA anyway).
maxretry = 8
findtime = 10m
bantime  = 10m
${banaction_line}

[sshd]
enabled  = true
# 'mode = aggressive' would catch more, but we keep the default to avoid
# false positives that could touch a scored SSH check.
EOF
}

cmd_fail2ban() {
  local apply=0
  [[ "${1:-}" == "--apply" ]] && apply=1

  log "===== Cautious fail2ban config (designed NOT to ban the scoring engine) ====="
  print_f2b_config | tee -a "${REPORT}"
  log "==========================================================================="

  if [[ "${apply}" -eq 0 ]]; then
    log "\n[DRY RUN] Nothing was changed. Re-run with '--apply' to install + activate."
    log "Reminder: egress blocking ('block <ip>') is the safer primary lever; fail2ban is a backstop."
    return 0
  fi

  log "\n[!] Applying fail2ban. Watch the banned list during the round:"
  log "    sudo $0 fail2ban-status     (and 'unban <ip>' instantly if the scorer ever appears)"

  # Install fail2ban (+ python3-systemd on Debian for the journald backend).
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban python3-systemd nftables >>"${REPORT}" 2>&1
  elif [[ "${OS_FAMILY}" == "rhel" ]]; then
    dnf install -y fail2ban >>"${REPORT}" 2>&1
  fi
  have fail2ban-client || { log "[!] fail2ban failed to install (no network?). Skipping."; return 1; }

  # Back up an existing jail.local, then write ours.
  [[ -f "${F2B_JAIL}" ]] && cp -a "${F2B_JAIL}" "${F2B_JAIL}.bak.$(date +%s)"
  print_f2b_config > "${F2B_JAIL}"
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban >/dev/null 2>&1
  sleep 1
  if systemctl is-active --quiet fail2ban; then
    log "[✓] fail2ban active with cautious config. ignoreip protects 172.16/12 (scorer ranges)."
  else
    log "[!] fail2ban did not start. Check: systemctl status fail2ban ; journalctl -u fail2ban"
    log "    If banaction is the problem on Debian, try 'banaction = nftables-allports' in ${F2B_JAIL}."
  fi
}

cmd_fail2ban_status() {
  have fail2ban-client || { log "[i] fail2ban not installed."; return 0; }
  log "Jails:"; fail2ban-client status 2>/dev/null | sed 's/^/    /' | tee -a "${REPORT}"
  # Show banned IPs per jail so you can immediately spot a banned scorer.
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do
    log "  [jail ${j}] banned IPs:"
    fail2ban-client status "${j}" 2>/dev/null | grep -i 'Banned IP list' | sed 's/^/      /' | tee -a "${REPORT}"
  done
  log "If you EVER see a scoring-engine IP here, unban it immediately:  sudo $0 unban <ip>"
}

cmd_unban() {
  [[ $# -ge 1 ]] || { log "Usage: $0 unban <ip>"; exit 1; }
  have fail2ban-client || { log "[i] fail2ban not installed."; return 0; }
  for ip in "$@"; do
    fail2ban-client unban "$ip" >/dev/null 2>&1 \
      && log "[✓] Unbanned ${ip} from fail2ban." \
      || log "[!] Could not unban ${ip} (maybe not banned)."
  done
}

###############################################################################
# dispatch
###############################################################################
CMD="${1:-}"; shift || true
case "${CMD}" in
  init)             cmd_init "$@" ;;
  block)            cmd_block "$@" ;;
  unblock)          cmd_unblock "$@" ;;
  list)             cmd_list "$@" ;;
  egress-lockdown)  cmd_egress_lockdown "$@" ;;
  egress-restore)   cmd_egress_restore "$@" ;;
  egress-status)    cmd_egress_status "$@" ;;
  fail2ban)         cmd_fail2ban "$@" ;;
  fail2ban-status)  cmd_fail2ban_status "$@" ;;
  unban)            cmd_unban "$@" ;;
  *)
    grep -E '^#( |$)' "$0" | sed -E 's/^# ?//' | sed -n '1,60p'
    echo
    echo "Commands:"
    echo "  init | block <ip>... | unblock <ip>... | list      (specific-IP blocklist)"
    echo "  egress-lockdown | egress-restore | egress-status   (block C2/exfil OUT, keep scoring)"
    echo "  fail2ban [--apply] | fail2ban-status | unban <ip>   (cautious brute-force jail)"
    ;;
esac
