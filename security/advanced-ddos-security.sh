#!/usr/bin/env bash
# =============================================================================
# Advanced DDoS Security & Mitigation Script for Debian Linux
# Repository: https://github.com/immutabletux/ddos-security
#
# Target:   Debian 11 (Bullseye) / Debian 12 (Bookworm) / Ubuntu 20.04+
# Usage:    sudo bash advanced-ddos-security.sh [OPTIONS]
#
# OPTIONS:
#   --install        Full install: packages, rules, services, crons
#   --rules-only     Apply iptables/nftables rules only
#   --sysctl-only    Apply kernel sysctl tuning only
#   --status         Show current protection status
#   --flush          Remove all DDoS rules (rollback)
#   --report         Generate DDoS activity report
#   --uninstall      Remove all changes made by this script
#
# FEATURES:
#   - SYN flood protection (iptables + SYN cookies)
#   - UDP flood mitigation
#   - ICMP flood limiting
#   - HTTP/HTTPS Layer-7 rate limiting
#   - Connection tracking abuse prevention
#   - IP reputation blacklisting (ipset)
#   - Geographic IP blocking (optional)
#   - fail2ban jail configuration
#   - Suricata IDS integration (optional)
#   - Traffic shaping with tc/iproute2
#   - Kernel parameter tuning (sysctl)
#   - Real-time alerting (email/Slack)
#   - Auto-ban via cron
#   - Rollback/cleanup support
#   - Comprehensive logging
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# GLOBAL CONSTANTS & DEFAULTS
# =============================================================================

SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="advanced-ddos-security"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/ddos-security"
LOG_FILE="${LOG_DIR}/ddos-security.log"
BACKUP_DIR="/etc/ddos-security/backups"
CONFIG_FILE="/etc/ddos-security/ddos.conf"
IPSET_BLOCKLIST="ddos_blocklist"
IPSET_WHITELIST="ddos_whitelist"
IPSET_RATELIMIT="ddos_ratelimit"
IPTABLES_CHAIN_INPUT="DDOS_INPUT"
IPTABLES_CHAIN_FORWARD="DDOS_FORWARD"
IPTABLES_CHAIN_SYNFLOOD="DDOS_SYNFLOOD"
IPTABLES_CHAIN_UDPFLOOD="DDOS_UDPFLOOD"
IPTABLES_CHAIN_ICMP="DDOS_ICMP"
IPTABLES_CHAIN_HTTP="DDOS_HTTP"
IPTABLES_CHAIN_PORTKNOCK="DDOS_PORTKNOCK"
CRON_AUTOBAN="/etc/cron.d/ddos-autoban"
CRON_REPORT="/etc/cron.d/ddos-report"
SYSCTL_FILE="/etc/sysctl.d/99-ddos-protection.conf"
FAIL2BAN_FILTER="/etc/fail2ban/filter.d/ddos-protection.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/ddos-protection.conf"

# Default tuneable limits (can be overridden via ddos.conf)
SYN_RATE="200/s"
SYN_BURST="50"
UDP_RATE="100/s"
UDP_BURST="30"
ICMP_RATE="10/s"
ICMP_BURST="5"
HTTP_RATE="100/min"
HTTP_BURST="50"
CONN_LIMIT="100"          # max simultaneous connections per IP
NEW_CONN_RATE="60/min"    # new TCP connections per IP per minute
BAN_DURATION="3600"       # seconds (1 hour default)
WHITELIST_IPS=()
BLACKLIST_IPS=()
ALERT_EMAIL=""
ALERT_SLACK_WEBHOOK=""
COUNTRY_BLOCK=""          # e.g. "CN,RU,KP" — requires geoip-bin

# =============================================================================
# COLOURS & OUTPUT HELPERS
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC}  %-64s${CYAN}║${NC}\n" "$1"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
}

section() {
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────${NC}"
    echo -e "${BLUE}│${NC}  ${BOLD}$1${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────${NC}"
}

info()    { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $1"; echo -e "  ${GREEN}[INFO]${NC}  $1"; echo "$msg" >> "$LOG_FILE" 2>/dev/null || true; }
warn()    { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $1"; echo -e "  ${YELLOW}[WARN]${NC}  $1"; echo "$msg" >> "$LOG_FILE" 2>/dev/null || true; }
err()     { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"; echo -e "  ${RED}[ERR ]${NC}  $1" >&2; echo "$msg" >> "$LOG_FILE" 2>/dev/null || true; }
ok()      { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    $1"; echo -e "  ${GREEN}[OK]${NC}    $1"; echo "$msg" >> "$LOG_FILE" 2>/dev/null || true; }
skip()    { echo -e "  ${YELLOW}[SKIP]${NC}  $1"; }
debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "  ${DIM}[DBG ]${NC}  $1" || true; }

ask() {
    local prompt="$1"
    local default="${2:-y}"
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "  ${BOLD}${prompt} [Y/n]:${NC} ")" yn
        yn="${yn:-y}"
    else
        read -rp "$(echo -e "  ${BOLD}${prompt} [y/N]:${NC} ")" yn
        yn="${yn:-n}"
    fi
    [[ "${yn,,}" == "y" ]]
}

die() { err "$1"; exit 1; }

# =============================================================================
# PRINT BANNER
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ██████╗  ██████╗ ███████╗    ███████╗███████╗ ██████╗"
    echo "  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔════╝"
    echo "  ██║  ██║██║  ██║██║   ██║███████╗    ███████╗█████╗  ██║"
    echo "  ██║  ██║██║  ██║██║   ██║╚════██║    ╚════██║██╔══╝  ██║"
    echo "  ██████╔╝██████╔╝╚██████╔╝███████║    ███████║███████╗╚██████╗"
    echo "  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝╚══════╝ ╚═════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}Advanced DDoS Security & Mitigation Script${NC}  ${DIM}v${SCRIPT_VERSION}${NC}"
    echo -e "  ${DIM}Target: Debian Linux | Author: immutabletux${NC}"
    echo ""
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root. Use: sudo bash $0"
    fi
}

check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        die "This script is designed for Debian-based systems only."
    fi
    OS_VERSION=$(cat /etc/debian_version)
    DISTRO="Debian"
    if [[ -f /etc/lsb-release ]]; then
        source /etc/lsb-release
        DISTRO="${DISTRIB_ID:-Debian}"
        OS_VERSION="${DISTRIB_RELEASE:-$OS_VERSION}"
    fi
    info "Detected OS: ${DISTRO} ${OS_VERSION}"
}

check_dependencies() {
    section "Checking Dependencies"
    local missing=()
    local required_cmds=("iptables" "ip6tables" "sysctl" "ss" "ip" "awk" "sed" "grep" "curl" "date")
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing commands: ${missing[*]}"
        warn "Run with --install to install required packages."
        return 1
    fi
    ok "All required commands found."
    return 0
}

# =============================================================================
# LOGGING SETUP
# =============================================================================

setup_logging() {
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    # Rotate if > 50 MB
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 52428800 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d%H%M%S).old"
        touch "$LOG_FILE"
        info "Log rotated (exceeded 50 MB)."
    fi
    info "Logging to: $LOG_FILE"
}

# =============================================================================
# LOAD / WRITE CONFIGURATION
# =============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        info "Loading config from $CONFIG_FILE"
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    else
        info "No config file found — using defaults."
    fi
}

write_default_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
# =============================================================================
# DDoS Security Configuration — /etc/ddos-security/ddos.conf
# Generated: $(date)
# =============================================================================

# Rate limits
SYN_RATE="${SYN_RATE}"
SYN_BURST="${SYN_BURST}"
UDP_RATE="${UDP_RATE}"
UDP_BURST="${UDP_BURST}"
ICMP_RATE="${ICMP_RATE}"
ICMP_BURST="${ICMP_BURST}"
HTTP_RATE="${HTTP_RATE}"
HTTP_BURST="${HTTP_BURST}"

# Connection limits per source IP
CONN_LIMIT="${CONN_LIMIT}"
NEW_CONN_RATE="${NEW_CONN_RATE}"

# Auto-ban duration (seconds)
BAN_DURATION="${BAN_DURATION}"

# Whitelist IPs (space-separated CIDR blocks)
WHITELIST_IPS=(${WHITELIST_IPS[*]+"${WHITELIST_IPS[*]}"})

# Static blacklist IPs (space-separated CIDR blocks)
BLACKLIST_IPS=(${BLACKLIST_IPS[*]+"${BLACKLIST_IPS[*]}"})

# Alert email (leave blank to disable)
ALERT_EMAIL="${ALERT_EMAIL}"

# Slack webhook URL (leave blank to disable)
ALERT_SLACK_WEBHOOK="${ALERT_SLACK_WEBHOOK}"

# Comma-separated ISO country codes to block (requires geoip-bin + xtables-addons)
# Example: COUNTRY_BLOCK="CN,RU,KP,IR"
COUNTRY_BLOCK="${COUNTRY_BLOCK}"
EOF
    ok "Config written to $CONFIG_FILE"
}

# =============================================================================
# PACKAGE INSTALLATION
# =============================================================================

install_packages() {
    section "Installing Required Packages"
    apt-get update -qq

    local pkgs=(
        iptables
        iptables-persistent
        ipset
        iproute2
        fail2ban
        netfilter-persistent
        conntrack
        tcpdump
        nmap
        curl
        wget
        jq
        net-tools
        sysstat
        htop
        logrotate
    )

    local optional_pkgs=(
        suricata
        geoip-bin
        xtables-addons-dkms
        xtables-addons-common
        libtext-csv-xs-perl
    )

    info "Installing core packages..."
    apt-get install -y "${pkgs[@]}" 2>&1 | grep -E "(installed|upgraded|already)" | while read -r line; do info "$line"; done || true
    ok "Core packages installed."

    info "Installing optional packages (non-fatal)..."
    for pkg in "${optional_pkgs[@]}"; do
        if apt-get install -y "$pkg" &>/dev/null; then
            ok "Installed optional: $pkg"
        else
            warn "Could not install optional: $pkg (skipping)"
        fi
    done
}

# =============================================================================
# BACKUP EXISTING RULES
# =============================================================================

backup_rules() {
    section "Backing Up Existing Firewall Rules"
    mkdir -p "$BACKUP_DIR"
    local ts; ts=$(date +%Y%m%d%H%M%S)

    if command -v iptables-save &>/dev/null; then
        iptables-save > "${BACKUP_DIR}/iptables-${ts}.bak" 2>/dev/null || true
        ok "iptables rules backed up to ${BACKUP_DIR}/iptables-${ts}.bak"
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > "${BACKUP_DIR}/ip6tables-${ts}.bak" 2>/dev/null || true
        ok "ip6tables rules backed up."
    fi
    if command -v ipset &>/dev/null; then
        ipset save > "${BACKUP_DIR}/ipset-${ts}.bak" 2>/dev/null || true
        ok "ipset rules backed up."
    fi
    if [[ -f /etc/sysctl.d/99-ddos-protection.conf ]]; then
        cp /etc/sysctl.d/99-ddos-protection.conf "${BACKUP_DIR}/sysctl-${ts}.bak"
        ok "sysctl config backed up."
    fi
}

# =============================================================================
# IPSET SETUP
# =============================================================================

setup_ipsets() {
    section "Setting Up IP Sets"

    # Destroy and recreate sets
    for setname in "$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_RATELIMIT"; do
        if ipset list "$setname" &>/dev/null; then
            ipset flush "$setname"
            ok "Flushed existing ipset: $setname"
        else
            case "$setname" in
                "$IPSET_BLOCKLIST")  ipset create "$setname" hash:net hashsize 4096 maxelem 1000000 ;;
                "$IPSET_WHITELIST")  ipset create "$setname" hash:net hashsize 256  maxelem 65536   ;;
                "$IPSET_RATELIMIT")  ipset create "$setname" hash:ip  hashsize 2048 maxelem 500000  \
                                         timeout 3600 ;;
            esac
            ok "Created ipset: $setname"
        fi
    done

    # Load static whitelist
    for cidr in "${WHITELIST_IPS[@]+"${WHITELIST_IPS[@]}"}"; do
        [[ -z "$cidr" ]] && continue
        ipset add "$IPSET_WHITELIST" "$cidr" 2>/dev/null || true
        info "Whitelisted: $cidr"
    done

    # Load static blacklist
    for cidr in "${BLACKLIST_IPS[@]+"${BLACKLIST_IPS[@]}"}"; do
        [[ -z "$cidr" ]] && continue
        ipset add "$IPSET_BLOCKLIST" "$cidr" 2>/dev/null || true
        info "Blacklisted: $cidr"
    done

    ok "IP sets configured."
}

# =============================================================================
# IPSET — DOWNLOAD KNOWN BAD IP FEEDS
# =============================================================================

update_blocklist_feeds() {
    section "Updating IP Reputation Blocklist Feeds"
    local tmp_file
    tmp_file=$(mktemp /tmp/ddos_feed.XXXXXXXX)

    declare -A FEEDS=(
        ["Emerging Threats"]="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ["CINS Army"]="https://cinsscore.com/list/ci-badguys.txt"
        ["Spamhaus DROP"]="https://www.spamhaus.org/drop/drop.txt"
        ["Spamhaus EDROP"]="https://www.spamhaus.org/drop/edrop.txt"
    )

    local count=0
    for feed_name in "${!FEEDS[@]}"; do
        local url="${FEEDS[$feed_name]}"
        info "Fetching: $feed_name"
        if curl -sSf --max-time 30 "$url" -o "$tmp_file" 2>/dev/null; then
            while IFS= read -r line; do
                # Strip comments and blank lines
                line="${line%%#*}"
                line="${line// /}"
                [[ -z "$line" ]] && continue
                # Validate CIDR or IP
                if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$ ]]; then
                    if ipset add "$IPSET_BLOCKLIST" "$line" 2>/dev/null; then
                        count=$((count + 1))
                    fi
                fi
            done < "$tmp_file"
            ok "Loaded $feed_name"
        else
            warn "Failed to fetch $feed_name (skipping)"
        fi
    done

    rm -f "$tmp_file"
    ok "Blocklist feeds updated. Added ~${count} entries."
}

# =============================================================================
# IPTABLES — FLUSH & INITIALIZE CUSTOM CHAINS
# =============================================================================

flush_ddos_rules() {
    info "Flushing existing DDoS chains..."
    for chain in "$IPTABLES_CHAIN_INPUT" "$IPTABLES_CHAIN_FORWARD" \
                 "$IPTABLES_CHAIN_SYNFLOOD" "$IPTABLES_CHAIN_UDPFLOOD" \
                 "$IPTABLES_CHAIN_ICMP" "$IPTABLES_CHAIN_HTTP" \
                 "$IPTABLES_CHAIN_PORTKNOCK"; do
        # Remove jump rules from built-in chains
        iptables -D INPUT   -j "$chain" 2>/dev/null || true
        iptables -D FORWARD -j "$chain" 2>/dev/null || true
        # Flush and delete custom chain
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done
    ok "DDoS iptables chains removed."
}

init_chains() {
    info "Initializing DDoS iptables chains..."
    for chain in "$IPTABLES_CHAIN_INPUT" "$IPTABLES_CHAIN_FORWARD" \
                 "$IPTABLES_CHAIN_SYNFLOOD" "$IPTABLES_CHAIN_UDPFLOOD" \
                 "$IPTABLES_CHAIN_ICMP" "$IPTABLES_CHAIN_HTTP" \
                 "$IPTABLES_CHAIN_PORTKNOCK"; do
        iptables -N "$chain" 2>/dev/null || iptables -F "$chain"
    done

    # Jump into DDoS chains from built-in chains
    # Only insert if not already present
    if ! iptables -C INPUT   -j "$IPTABLES_CHAIN_INPUT"   2>/dev/null; then
        iptables -I INPUT   1 -j "$IPTABLES_CHAIN_INPUT"
    fi
    if ! iptables -C FORWARD -j "$IPTABLES_CHAIN_FORWARD" 2>/dev/null; then
        iptables -I FORWARD 1 -j "$IPTABLES_CHAIN_FORWARD"
    fi
    ok "Custom chains created."
}

# =============================================================================
# IPTABLES — BASIC ALLOW / LOOPBACK / ESTABLISHED
# =============================================================================

apply_base_rules() {
    section "Applying Base iptables Rules"

    # Allow loopback
    iptables -A "$IPTABLES_CHAIN_INPUT" -i lo -j RETURN
    # Allow established / related
    iptables -A "$IPTABLES_CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    # Allow from whitelist — skip all further checks
    iptables -A "$IPTABLES_CHAIN_INPUT" -m set --match-set "$IPSET_WHITELIST" src -j RETURN
    # Drop invalid packets
    iptables -A "$IPTABLES_CHAIN_INPUT" -m conntrack --ctstate INVALID -j DROP
    # Jump sub-chains for further inspection (RETURN = allow; DROP = block)
    iptables -A "$IPTABLES_CHAIN_INPUT" -j "$IPTABLES_CHAIN_SYNFLOOD"
    iptables -A "$IPTABLES_CHAIN_INPUT" -j "$IPTABLES_CHAIN_UDPFLOOD"
    iptables -A "$IPTABLES_CHAIN_INPUT" -j "$IPTABLES_CHAIN_ICMP"
    iptables -A "$IPTABLES_CHAIN_INPUT" -j "$IPTABLES_CHAIN_HTTP"
    ok "Base rules applied."
}

# =============================================================================
# IPTABLES — BLOCKLIST / BLACKHOLE
# =============================================================================

apply_blocklist_rules() {
    section "Applying IP Reputation Block Rules"

    # Drop packets from blacklisted/rate-limited IPs inside DDOS_INPUT so that
    # the whitelist RETURN (added in apply_base_rules) always takes priority.
    # Inserting directly into the raw INPUT chain (as before) caused whitelisted
    # IPs to be dropped if they appeared in any blocklist set.
    if ! iptables -C "$IPTABLES_CHAIN_INPUT" -m set --match-set "$IPSET_BLOCKLIST" src \
            -j DROP 2>/dev/null; then
        iptables -I "$IPTABLES_CHAIN_INPUT" 4 \
            -m set --match-set "$IPSET_BLOCKLIST" src \
            -m comment --comment "DDoS: IP reputation block" -j DROP
    fi

    if ! iptables -C "$IPTABLES_CHAIN_INPUT" -m set --match-set "$IPSET_RATELIMIT" src \
            -j DROP 2>/dev/null; then
        iptables -I "$IPTABLES_CHAIN_INPUT" 5 \
            -m set --match-set "$IPSET_RATELIMIT" src \
            -m comment --comment "DDoS: auto-banned IPs" -j DROP
    fi

    ok "IP reputation block rules applied."
}

# =============================================================================
# IPTABLES — SYN FLOOD PROTECTION
# =============================================================================

apply_syn_rules() {
    section "Applying SYN Flood Protection Rules"

    # Allow whitelisted IPs through
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -m set --match-set "$IPSET_WHITELIST" src -j RETURN

    # Drop TCP packets with invalid flag combinations (Christmas tree, NULL, etc.)
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ALL FIN,URG,PSH \
        -m comment --comment "DDoS: Xmas scan" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ALL NONE \
        -m comment --comment "DDoS: NULL scan" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags SYN,RST SYN,RST \
        -m comment --comment "DDoS: SYN/RST" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags SYN,FIN SYN,FIN \
        -m comment --comment "DDoS: SYN/FIN" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags FIN,RST FIN,RST \
        -m comment --comment "DDoS: FIN/RST" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ALL FIN \
        -m comment --comment "DDoS: FIN scan" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ACK,FIN FIN \
        -m comment --comment "DDoS: FIN ACK" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ACK,PSH PSH \
        -m comment --comment "DDoS: PSH scan" -j DROP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --tcp-flags ACK,URG URG \
        -m comment --comment "DDoS: URG scan" -j DROP

    # Rate-limit new SYN connections per IP
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --syn \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "${SYN_RATE}" \
        --hashlimit-burst "${SYN_BURST}" \
        --hashlimit-name syn_flood \
        --hashlimit-htable-expire 60000 \
        -m comment --comment "DDoS: SYN flood rate limit" \
        -j SET --add-set "$IPSET_RATELIMIT" src --exist

    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --syn \
        -m set --match-set "$IPSET_RATELIMIT" src -j DROP

    # Per-IP new connection rate limit (using connlimit as secondary defense)
    iptables -A "$IPTABLES_CHAIN_SYNFLOOD" -p tcp --syn \
        -m connlimit --connlimit-above "${CONN_LIMIT}" --connlimit-mask 32 \
        -m comment --comment "DDoS: per-IP connection limit" -j REJECT --reject-with tcp-reset

    ok "SYN flood rules applied (limit: ${SYN_RATE}, burst: ${SYN_BURST})."
}

# =============================================================================
# IPTABLES — UDP FLOOD PROTECTION
# =============================================================================

apply_udp_rules() {
    section "Applying UDP Flood Protection Rules"

    # Allow DNS responses (established/related already handled above)
    iptables -A "$IPTABLES_CHAIN_UDPFLOOD" -p udp -m multiport --sports 53,67,68,123 -j RETURN

    # Rate-limit UDP traffic per source IP
    iptables -A "$IPTABLES_CHAIN_UDPFLOOD" -p udp \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "${UDP_RATE}" \
        --hashlimit-burst "${UDP_BURST}" \
        --hashlimit-name udp_flood \
        --hashlimit-htable-expire 30000 \
        -m comment --comment "DDoS: UDP flood rate limit" \
        -j SET --add-set "$IPSET_RATELIMIT" src --exist

    iptables -A "$IPTABLES_CHAIN_UDPFLOOD" -p udp \
        -m set --match-set "$IPSET_RATELIMIT" src -j DROP

    # Block UDP amplification vectors (commonly abused ports)
    local amp_ports="19,53,111,137,161,389,520,1900,5353,11211"
    iptables -A "$IPTABLES_CHAIN_UDPFLOOD" -p udp \
        -m multiport --dports "$amp_ports" \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "5/s" \
        --hashlimit-burst "10" \
        --hashlimit-name udp_amp \
        -m comment --comment "DDoS: UDP amplification block" -j DROP

    ok "UDP flood rules applied (limit: ${UDP_RATE}, burst: ${UDP_BURST})."
}

# =============================================================================
# IPTABLES — ICMP FLOOD PROTECTION
# =============================================================================

apply_icmp_rules() {
    section "Applying ICMP Flood Protection Rules"

    # Allow ICMP type 3 (unreachable) and type 11 (time exceeded) — needed for PMTUD/traceroute
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp --icmp-type 3  -j RETURN
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp --icmp-type 11 -j RETURN

    # Rate-limit ICMP echo requests
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp --icmp-type echo-request \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "${ICMP_RATE}" \
        --hashlimit-burst "${ICMP_BURST}" \
        --hashlimit-name icmp_flood \
        --hashlimit-htable-expire 60000 \
        -m comment --comment "DDoS: ICMP flood rate limit" -j DROP

    # Drop ICMP redirect messages (can be used for routing attacks)
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp --icmp-type redirect \
        -m comment --comment "DDoS: ICMP redirect" -j DROP

    # Limit total ICMP globally
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp \
        -m limit --limit 50/s --limit-burst 100 -j RETURN
    iptables -A "$IPTABLES_CHAIN_ICMP" -p icmp -j DROP

    ok "ICMP flood rules applied (limit: ${ICMP_RATE}, burst: ${ICMP_BURST})."
}

# =============================================================================
# IPTABLES — HTTP/HTTPS LAYER-4 RATE LIMITING
# =============================================================================

apply_http_rules() {
    section "Applying HTTP/HTTPS Rate-Limit Rules"

    # Rate-limit new HTTP/HTTPS connections per source IP
    iptables -A "$IPTABLES_CHAIN_HTTP" -p tcp -m multiport --dports 80,443,8080,8443 \
        -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "${HTTP_RATE}" \
        --hashlimit-burst "${HTTP_BURST}" \
        --hashlimit-name http_flood \
        --hashlimit-htable-expire 120000 \
        -m comment --comment "DDoS: HTTP flood rate limit" \
        -j SET --add-set "$IPSET_RATELIMIT" src --exist

    iptables -A "$IPTABLES_CHAIN_HTTP" -p tcp -m multiport --dports 80,443,8080,8443 \
        -m set --match-set "$IPSET_RATELIMIT" src -j DROP

    # Limit simultaneous HTTP connections per IP
    iptables -A "$IPTABLES_CHAIN_HTTP" -p tcp -m multiport --dports 80,443 \
        -m connlimit --connlimit-above 50 --connlimit-mask 32 \
        -m comment --comment "DDoS: HTTP connlimit" -j REJECT --reject-with tcp-reset

    ok "HTTP/HTTPS rate-limit rules applied."
}

# =============================================================================
# IPTABLES — PORT SCAN DETECTION
# =============================================================================

apply_portscan_rules() {
    section "Applying Port Scan Detection Rules"

    # Create temporary "scanner" set if not present
    if ! ipset list ddos_scanners &>/dev/null; then
        ipset create ddos_scanners hash:ip timeout 3600 hashsize 1024
        ok "Created ipset: ddos_scanners"
    else
        ok "Using existing ipset: ddos_scanners"
    fi

    # Mark IPs hitting closed/filtered ports too quickly as port scanners
    iptables -I INPUT 4 -m set --match-set ddos_scanners src \
        -m comment --comment "DDoS: port scanner block" -j DROP

    # Detect: hit on TCP port 0 (always bogus).
    # Two rules: first SET (non-terminating, adds to ipset), then DROP same traffic.
    iptables -I INPUT 5 -p tcp --dport 0 \
        -m comment --comment "DDoS: port 0 probe" \
        -j SET --add-set ddos_scanners src
    iptables -I INPUT 6 -p tcp --dport 0 \
        -m comment --comment "DDoS: port 0 probe" -j DROP

    # Detect: SYN to common honeypot ports with no prior connection.
    # Two rules: SET then DROP so the triggering packet is also blocked.
    local honeypot_ports="23,2323,4444,5554,6667,7547,8888,9200"
    iptables -I INPUT 7 -p tcp -m multiport --dports "$honeypot_ports" \
        --syn -m conntrack --ctstate NEW \
        -m comment --comment "DDoS: honeypot port probe" \
        -j SET --add-set ddos_scanners src
    iptables -I INPUT 8 -p tcp -m multiport --dports "$honeypot_ports" \
        --syn -m conntrack --ctstate NEW \
        -m comment --comment "DDoS: honeypot port probe" -j DROP

    ok "Port scan detection rules applied."
}

# =============================================================================
# IPTABLES — ANTI-SPOOFING (BOGON FILTERING)
# =============================================================================

apply_antispoofing_rules() {
    section "Applying Anti-Spoofing / Bogon Filter Rules"

    local bogons=(
        "0.0.0.0/8"
        "10.0.0.0/8"
        "100.64.0.0/10"
        "127.0.0.0/8"
        "169.254.0.0/16"
        "172.16.0.0/12"
        "192.0.0.0/24"
        "192.168.0.0/16"
        "198.18.0.0/15"
        "198.51.100.0/24"
        "203.0.113.0/24"
        "224.0.0.0/4"
        "240.0.0.0/4"
        "255.255.255.255/32"
    )

    # Detect the primary public-facing interface
    local pub_iface
    pub_iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    if [[ -z "$pub_iface" ]]; then
        warn "Could not detect public interface — skipping anti-spoofing on specific interface."
        pub_iface=""
    fi

    if ! ipset list ddos_bogons &>/dev/null; then
        ipset create ddos_bogons hash:net hashsize 1024
    else
        ipset flush ddos_bogons
    fi

    for bogon in "${bogons[@]}"; do
        ipset add ddos_bogons "$bogon" 2>/dev/null || true
    done

    if [[ -n "$pub_iface" ]]; then
        if ! iptables -C INPUT -i "$pub_iface" -m set --match-set ddos_bogons src \
             -j DROP 2>/dev/null; then
            iptables -I INPUT 7 -i "$pub_iface" \
                -m set --match-set ddos_bogons src \
                -m comment --comment "DDoS: bogon source filter" -j DROP
        fi
        ok "Bogon filtering applied on interface: $pub_iface"
    else
        if ! iptables -C INPUT -m set --match-set ddos_bogons src -j DROP 2>/dev/null; then
            iptables -I INPUT 7 \
                -m set --match-set ddos_bogons src \
                -m comment --comment "DDoS: bogon source filter" -j DROP
        fi
        ok "Bogon filtering applied (all interfaces)."
    fi
}

# =============================================================================
# IPTABLES — FRAGMENT / MALFORMED PACKET PROTECTION
# =============================================================================

apply_fragment_rules() {
    section "Applying Fragment & Malformed Packet Rules"

    # Drop fragmented packets (can be used to evade IDS and reassemble exploits)
    iptables -I INPUT 8 -f \
        -m comment --comment "DDoS: fragmented packet" -j DROP

    # Drop packets with both SYN and RST set
    iptables -I INPUT 9 -p tcp --tcp-flags SYN,RST SYN,RST \
        -m comment --comment "DDoS: SYN+RST" -j DROP

    # Drop NEW connections that are not SYN
    iptables -I INPUT 10 -p tcp ! --syn \
        -m conntrack --ctstate NEW \
        -m comment --comment "DDoS: NEW non-SYN" -j DROP

    ok "Fragment and malformed packet rules applied."
}

# =============================================================================
# IPTABLES — GEO-BLOCKING (optional, requires xtables-addons + geoip)
# =============================================================================

apply_geoblock_rules() {
    if [[ -z "${COUNTRY_BLOCK:-}" ]]; then
        skip "Geographic blocking disabled (COUNTRY_BLOCK not set)."
        return 0
    fi

    section "Applying Geographic IP Block Rules"

    # Check if xtables geoip module is available
    if ! modprobe xt_geoip &>/dev/null; then
        warn "xt_geoip module not available — skipping geo-blocking."
        warn "Install: apt install xtables-addons-dkms xtables-addons-common"
        return 0
    fi

    # Ensure geoip database exists
    if [[ ! -d /usr/share/xt_geoip ]]; then
        warn "GeoIP database not found at /usr/share/xt_geoip — attempting build..."
        if command -v xt_geoip_build &>/dev/null && command -v xt_geoip_fetch &>/dev/null; then
            mkdir -p /tmp/geoip_dl
            xt_geoip_fetch -D /tmp/geoip_dl &>/dev/null || true
            mkdir -p /usr/share/xt_geoip
            xt_geoip_build -D /usr/share/xt_geoip /tmp/geoip_dl/*.csv &>/dev/null || true
            ok "GeoIP database built."
        else
            warn "xt_geoip tools not found — skipping geo-blocking."
            return 0
        fi
    fi

    IFS=',' read -ra countries <<< "$COUNTRY_BLOCK"
    for cc in "${countries[@]}"; do
        cc="${cc// /}"
        [[ -z "$cc" ]] && continue
        if ! iptables -C INPUT -m geoip --src-cc "$cc" -j DROP 2>/dev/null; then
            iptables -I INPUT 11 -m geoip --src-cc "$cc" \
                -m comment --comment "DDoS: geo-block $cc" -j DROP
            ok "Geo-blocked country: $cc"
        fi
    done
}

# =============================================================================
# IPv6 RULES
# =============================================================================

apply_ipv6_rules() {
    section "Applying IPv6 DDoS Protection Rules"

    # Allow loopback
    ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    # Allow established
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    # Drop invalid
    ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || true

    # ICMPv6 — required for IPv6 to function correctly
    local allowed_icmpv6_types=("destination-unreachable" "packet-too-big" "time-exceeded"
                                 "echo-request" "echo-reply"
                                 "router-solicitation" "router-advertisement"
                                 "neighbour-solicitation" "neighbour-advertisement")
    for icmp_type in "${allowed_icmpv6_types[@]}"; do
        ip6tables -A INPUT -p icmpv6 --icmpv6-type "$icmp_type" \
            -m limit --limit 100/s --limit-burst 200 -j ACCEPT 2>/dev/null || true
    done
    ip6tables -A INPUT -p icmpv6 -j DROP 2>/dev/null || true

    # Rate-limit SYN on IPv6
    ip6tables -A INPUT -p tcp --syn \
        -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "${SYN_RATE}" \
        --hashlimit-burst "${SYN_BURST}" \
        --hashlimit-name syn6_flood \
        -m comment --comment "DDoS: IPv6 SYN flood" -j DROP 2>/dev/null || true

    # Drop fragmented IPv6 packets
    ip6tables -A INPUT -m frag --fragmore \
        -m comment --comment "DDoS: IPv6 fragments" -j DROP 2>/dev/null || true

    ok "IPv6 rules applied."
}

# =============================================================================
# KERNEL SYSCTL TUNING
# =============================================================================

apply_sysctl_tuning() {
    section "Applying Kernel Sysctl DDoS Mitigations"

    cat > "$SYSCTL_FILE" <<'SYSCTL_EOF'
# =============================================================================
# DDoS Protection Kernel Parameters
# Managed by: advanced-ddos-security.sh
# =============================================================================

# --- SYN Cookies ---
# Enable SYN cookies to defend against SYN floods without dropping legitimate connections
net.ipv4.tcp_syncookies = 1

# --- SYN Backlog Queue ---
# Increase the queue for incomplete connections
net.ipv4.tcp_max_syn_backlog = 65536

# --- SYN Retries ---
# Reduce SYN-ACK retransmissions before giving up
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# --- TCP TIME_WAIT Protection ---
# Reuse TIME_WAIT sockets for new connections (reduces resource exhaustion)
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# --- TCP Keepalive ---
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# --- TCP Max Orphans ---
# Drop connections that have no associated socket (prevents orphan floods)
net.ipv4.tcp_max_orphans = 65536

# --- Connection Tracking ---
# Increase the conntrack table to avoid exhaustion under flood
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_icmp_timeout = 10
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# --- Network Buffer Sizes ---
# Increase socket receive/send buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# --- Backlog / Queue ---
# Increase the accept and backlog queues
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000

# --- Source Address Verification (RP Filter) ---
# Prevent IP spoofing on all interfaces
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- ICMP Protection ---
# Ignore ICMP broadcast echo (smurf amplification)
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Routing & Redirects ---
# Do not accept or send ICMP redirects (man-in-the-middle prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not accept source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# --- Log Martian Packets ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- UDP Memory ---
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# --- File Descriptor Limits ---
fs.file-max = 2097152

# --- Virtual Memory ---
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# --- Misc Hardening ---
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_timestamps = 0
SYSCTL_EOF

    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
    ok "Kernel sysctl parameters applied from $SYSCTL_FILE"

    # Load conntrack module if needed
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true
    ok "Conntrack modules loaded."
}

# =============================================================================
# TRAFFIC SHAPING — tc / iproute2
# =============================================================================

apply_tc_shaping() {
    section "Applying Traffic Shaping (tc) Rules"

    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    if [[ -z "$iface" ]]; then
        warn "Cannot detect default interface — skipping tc shaping."
        return 0
    fi

    info "Applying tc rules on interface: $iface"

    # Remove existing qdisc
    tc qdisc del dev "$iface" root 2>/dev/null || true
    tc qdisc del dev "$iface" ingress 2>/dev/null || true

    # Add HTB root qdisc
    tc qdisc add dev "$iface" root handle 1: htb default 30 r2q 10

    # Main class — total bandwidth (adjust to your uplink)
    tc class add dev "$iface" parent 1:  classid 1:1  htb rate 1gbit  ceil 1gbit
    # High-priority class (SSH, DNS, ICMP)
    tc class add dev "$iface" parent 1:1 classid 1:10 htb rate 100mbit ceil 1gbit prio 1
    # Normal traffic class
    tc class add dev "$iface" parent 1:1 classid 1:20 htb rate 400mbit ceil 900mbit prio 2
    # Default/bulk class
    tc class add dev "$iface" parent 1:1 classid 1:30 htb rate 50mbit  ceil 500mbit prio 3

    # SFQ for fair queuing within each class
    tc qdisc add dev "$iface" parent 1:10 handle 10: sfq perturb 10
    tc qdisc add dev "$iface" parent 1:20 handle 20: sfq perturb 10
    tc qdisc add dev "$iface" parent 1:30 handle 30: sfq perturb 10

    # Filters — classify traffic
    # SSH (port 22) → high priority
    tc filter add dev "$iface" parent 1:0 protocol ip u32 \
        match ip dport 22 0xffff flowid 1:10
    # DNS (port 53) → high priority
    tc filter add dev "$iface" parent 1:0 protocol ip u32 \
        match ip dport 53 0xffff flowid 1:10
    # HTTP/HTTPS → normal
    tc filter add dev "$iface" parent 1:0 protocol ip u32 \
        match ip dport 80 0xffff flowid 1:20
    tc filter add dev "$iface" parent 1:0 protocol ip u32 \
        match ip dport 443 0xffff flowid 1:20

    ok "Traffic shaping applied on $iface."
}

# =============================================================================
# FAIL2BAN CONFIGURATION
# =============================================================================

configure_fail2ban() {
    section "Configuring fail2ban DDoS Jails"

    if ! command -v fail2ban-server &>/dev/null; then
        warn "fail2ban not installed — skipping."
        return 0
    fi

    # Custom filter for log-based DDoS detection
    mkdir -p /etc/fail2ban/filter.d
    cat > "$FAIL2BAN_FILTER" <<'F2B_FILTER'
[INCLUDES]
before = common.conf

[Definition]
# Match lines like: kernel: DDoS: SYN flood from 1.2.3.4
_daemon = kernel
failregex = ^%(__prefix_line)sDDoS:.+from <HOST>.*$
            ^%(__prefix_line)s.*Possible SYN flooding on port.+\. Sending cookies\.<HOST>.*$
            ^%(__prefix_line)sSYN flood detected from <HOST>.*$

ignoreregex =
F2B_FILTER

    # Jail configuration
    mkdir -p /etc/fail2ban/jail.d
    cat > "$FAIL2BAN_JAIL" <<F2B_JAIL
[ddos-protection]
enabled     = true
filter      = ddos-protection
logpath     = /var/log/kern.log
              /var/log/syslog
              ${LOG_DIR}/ddos-security.log
maxretry    = 3
findtime    = 60
bantime     = ${BAN_DURATION}
action      = iptables-allports[name=DDoS, protocol=all]

[ddos-nginx-limit]
enabled     = true
filter      = nginx-limit-req
logpath     = /var/log/nginx/error.log
maxretry    = 5
findtime    = 60
bantime     = ${BAN_DURATION}
action      = iptables-multiport[name=nginx-ddos, port="80,443"]

[ddos-apache]
enabled     = false
filter      = apache-overflows
logpath     = /var/log/apache2/error.log
maxretry    = 3
findtime    = 60
bantime     = ${BAN_DURATION}
action      = iptables-multiport[name=apache-ddos, port="80,443"]

[ddos-ssh-flood]
enabled     = true
filter      = sshd
logpath     = /var/log/auth.log
maxretry    = 5
findtime    = 30
bantime     = 86400
action      = iptables-allports[name=ssh-flood, protocol=all]
F2B_JAIL

    systemctl enable fail2ban &>/dev/null || true
    systemctl restart fail2ban &>/dev/null || true
    ok "fail2ban configured and restarted."
}

# =============================================================================
# NGINX RATE-LIMITING SNIPPET (OPTIONAL)
# =============================================================================

configure_nginx_ratelimit() {
    if ! command -v nginx &>/dev/null; then
        skip "Nginx not installed — skipping nginx rate-limit config."
        return 0
    fi

    section "Configuring Nginx DDoS Rate-Limit Snippet"

    local nginx_conf="/etc/nginx/conf.d/ddos-ratelimit.conf"
    cat > "$nginx_conf" <<'NGINX_EOF'
# DDoS Rate Limiting — managed by advanced-ddos-security.sh

# Define rate-limit zones
limit_req_zone  $binary_remote_addr zone=req_global:20m rate=100r/m;
limit_req_zone  $binary_remote_addr zone=req_api:10m    rate=30r/m;
limit_conn_zone $binary_remote_addr zone=conn_per_ip:20m;

# Apply globally in http { } block via include, or per-server:
# limit_req        zone=req_global burst=50 nodelay;
# limit_conn       conn_per_ip 20;
# limit_req_status 429;

# Slowloris / low-and-slow attack mitigations
client_body_timeout   10s;
client_header_timeout 10s;
keepalive_timeout     5s 5s;
send_timeout          10s;
client_max_body_size  10m;

# Hide nginx version
server_tokens off;
NGINX_EOF

    if nginx -t &>/dev/null; then
        systemctl reload nginx &>/dev/null || true
        ok "Nginx rate-limit config applied and reloaded."
    else
        warn "Nginx config test failed — snippet written but nginx not reloaded."
        warn "Check: nginx -t"
    fi
}

# =============================================================================
# SURICATA IDS INTEGRATION (OPTIONAL)
# =============================================================================

configure_suricata() {
    if ! command -v suricata &>/dev/null; then
        skip "Suricata not installed — skipping IDS configuration."
        return 0
    fi

    section "Configuring Suricata IDS for DDoS Detection"

    local suricata_rules="/etc/suricata/rules/ddos-local.rules"
    mkdir -p /etc/suricata/rules

    cat > "$suricata_rules" <<'SURICATA_EOF'
# Custom DDoS detection rules — managed by advanced-ddos-security.sh

# SYN flood detection (>100 SYN/sec from single IP)
alert tcp any any -> $HOME_NET any (msg:"DDoS SYN Flood detected"; flags:S; \
    threshold: type both, track by_src, count 100, seconds 1; \
    classtype:attempted-dos; sid:9000001; rev:1;)

# UDP flood detection
alert udp any any -> $HOME_NET any (msg:"DDoS UDP Flood detected"; \
    threshold: type both, track by_src, count 500, seconds 1; \
    classtype:attempted-dos; sid:9000002; rev:1;)

# ICMP flood detection
alert icmp any any -> $HOME_NET any (msg:"DDoS ICMP Flood detected"; \
    itype:8; threshold: type both, track by_src, count 50, seconds 1; \
    classtype:attempted-dos; sid:9000003; rev:1;)

# HTTP flood (slowloris-like)
alert http any any -> $HOME_NET $HTTP_PORTS (msg:"DDoS HTTP Flood"; \
    threshold: type both, track by_src, count 200, seconds 10; \
    classtype:attempted-dos; sid:9000004; rev:1;)

# DNS amplification attempt
alert udp any any -> $HOME_NET 53 (msg:"DDoS DNS Amplification"; \
    threshold: type both, track by_src, count 100, seconds 1; \
    classtype:attempted-dos; sid:9000005; rev:1;)

# NTP amplification (port 123)
alert udp any any -> $HOME_NET 123 (msg:"DDoS NTP Amplification"; \
    threshold: type both, track by_src, count 50, seconds 1; \
    classtype:attempted-dos; sid:9000006; rev:1;)

# SSDP amplification (port 1900)
alert udp any any -> $HOME_NET 1900 (msg:"DDoS SSDP Amplification"; \
    threshold: type both, track by_src, count 50, seconds 1; \
    classtype:attempted-dos; sid:9000007; rev:1;)

# Memcached amplification (port 11211)
alert udp any any -> $HOME_NET 11211 (msg:"DDoS Memcached Amplification"; \
    threshold: type both, track by_src, count 20, seconds 1; \
    classtype:attempted-dos; sid:9000008; rev:1;)
SURICATA_EOF

    # Add include in suricata.yaml if not already present
    if [[ -f /etc/suricata/suricata.yaml ]]; then
        if ! grep -q "ddos-local.rules" /etc/suricata/suricata.yaml; then
            # Append under rule-files section
            sed -i '/^rule-files:/a\  - ddos-local.rules' /etc/suricata/suricata.yaml
            ok "Added ddos-local.rules to suricata.yaml"
        fi
        systemctl restart suricata &>/dev/null || true
        ok "Suricata restarted with DDoS rules."
    else
        warn "suricata.yaml not found — rules written but not activated."
    fi
}

# =============================================================================
# AUTO-BAN SCRIPT
# =============================================================================

install_autoban_script() {
    section "Installing Auto-Ban Script"

    local autoban="/usr/local/sbin/ddos-autoban.sh"
    cat > "$autoban" <<AUTOBAN_EOF
#!/usr/bin/env bash
# Auto-ban IPs exceeding connection thresholds
# Managed by: advanced-ddos-security.sh

THRESHOLD=100
BAN_DURATION=${BAN_DURATION}
IPSET_RATELIMIT="${IPSET_RATELIMIT}"
LOG_FILE="${LOG_FILE}"
WHITELIST_IPSET="${IPSET_WHITELIST}"

log() { echo "[\\$(date '+%Y-%m-%d %H:%M:%S')] [AUTOBAN] \\$1" >> "\\$LOG_FILE"; }

# Check if ipset is available
command -v ipset &>/dev/null || exit 0

# Find top talkers from conntrack
if command -v conntrack &>/dev/null; then
    mapfile -t top_ips < <(
        conntrack -L 2>/dev/null \
        | awk '/tcp/{print \$5}' \
        | grep -oP 'src=\\K[0-9.]+' \
        | sort | uniq -c | sort -rn \
        | awk -v threshold="\\$THRESHOLD" '\\$1 > threshold {print \\$2}'
    )
else
    # Fallback: use ss
    mapfile -t top_ips < <(
        ss -tn state established 2>/dev/null \
        | awk 'NR>1{print \\$5}' \
        | grep -oP '^[0-9.]+' \
        | sort | uniq -c | sort -rn \
        | awk -v threshold="\\$THRESHOLD" '\\$1 > threshold {print \\$2}'
    )
fi

for ip in "\\${top_ips[@]}"; do
    [[ -z "\\$ip" ]] && continue
    # Skip whitelisted IPs
    if ipset test "\\$WHITELIST_IPSET" "\\$ip" 2>/dev/null; then
        log "Skipping whitelisted IP: \\$ip"
        continue
    fi
    if ! ipset test "\\$IPSET_RATELIMIT" "\\$ip" 2>/dev/null; then
        ipset add "\\$IPSET_RATELIMIT" "\\$ip" timeout "\\$BAN_DURATION" 2>/dev/null || true
        log "Auto-banned: \\$ip (>\\$THRESHOLD connections, ban: \\${BAN_DURATION}s)"
    fi
done
AUTOBAN_EOF

    chmod +x "$autoban"
    ok "Auto-ban script installed: $autoban"

    # Install cron job
    cat > "$CRON_AUTOBAN" <<CRON_EOF
# DDoS Auto-Ban — runs every 2 minutes
*/2 * * * * root ${autoban} >/dev/null 2>&1
CRON_EOF
    ok "Auto-ban cron installed: every 2 minutes."
}

# =============================================================================
# REPORT SCRIPT & CRON
# =============================================================================

install_report_script() {
    section "Installing DDoS Report Script"

    local report_script="/usr/local/sbin/ddos-report.sh"
    cat > "$report_script" <<REPORT_EOF
#!/usr/bin/env bash
# DDoS Activity Report
# Managed by: advanced-ddos-security.sh

LOG_FILE="${LOG_FILE}"
IPSET_RATELIMIT="${IPSET_RATELIMIT}"
IPSET_BLOCKLIST="${IPSET_BLOCKLIST}"
REPORT_DIR="${LOG_DIR}/reports"
ALERT_EMAIL="${ALERT_EMAIL}"
ALERT_SLACK="${ALERT_SLACK_WEBHOOK}"

mkdir -p "\\$REPORT_DIR"
REPORT_FILE="\\${REPORT_DIR}/ddos-report-\\$(date +%Y%m%d-%H%M%S).txt"

{
    echo "============================================================"
    echo "  DDoS Security Activity Report"
    echo "  Generated: \\$(date)"
    echo "  Hostname:  \\$(hostname -f)"
    echo "============================================================"
    echo ""

    echo "--- Currently Banned IPs (rate-limit set) ---"
    ipset list "\\$IPSET_RATELIMIT" 2>/dev/null | grep -E '^[0-9]' | head -50 || echo "(none)"
    echo ""

    echo "--- Blocklist Size ---"
    echo "  Entries: \\$(ipset list \\$IPSET_BLOCKLIST 2>/dev/null | grep -c '^[0-9]' || echo 0)"
    echo ""

    echo "--- Top Offenders (last 24h from iptables log) ---"
    if [[ -f /var/log/kern.log ]]; then
        grep -oP 'SRC=\\K[0-9.]+' /var/log/kern.log 2>/dev/null \
            | sort | uniq -c | sort -rn | head -20 || echo "(none)"
    fi
    echo ""

    echo "--- Active Connections (top IPs) ---"
    ss -tn state established 2>/dev/null \
        | awk 'NR>1{print \\$5}' \
        | grep -oP '^[0-9.]+' \
        | sort | uniq -c | sort -rn | head -20 || echo "(none)"
    echo ""

    echo "--- iptables DROP counters ---"
    iptables -nvL INPUT 2>/dev/null | awk '\\$1+0 > 0 && /DROP/' | head -20 || true
    echo ""

    echo "--- Recent DDoS Events (last 50 log lines) ---"
    [[ -f "\\$LOG_FILE" ]] && tail -50 "\\$LOG_FILE" || echo "(no log)"
    echo ""
    echo "============================================================"
} > "\\$REPORT_FILE"

echo "Report written to: \\$REPORT_FILE"

# Email alert
if [[ -n "\\$ALERT_EMAIL" ]] && command -v mail &>/dev/null; then
    mail -s "DDoS Report \\$(hostname -s) \\$(date +%Y-%m-%d)" "\\$ALERT_EMAIL" < "\\$REPORT_FILE"
    echo "Report emailed to: \\$ALERT_EMAIL"
fi

# Slack alert (summary only)
if [[ -n "\\$ALERT_SLACK" ]]; then
    BANNED_COUNT=\\$(ipset list "\\$IPSET_RATELIMIT" 2>/dev/null | grep -c '^[0-9]' || echo 0)
    curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\":shield: DDoS Report [\\$(hostname -s)] - Banned IPs: \\${BANNED_COUNT} - \\$(date)\"}" \
        "\\$ALERT_SLACK" &>/dev/null || true
fi
REPORT_EOF

    chmod +x "$report_script"
    ok "Report script installed: $report_script"

    # Daily cron
    cat > "$CRON_REPORT" <<CRON_EOF
# DDoS Report — runs daily at 06:00
0 6 * * * root ${report_script} >/dev/null 2>&1
CRON_EOF
    ok "Report cron installed: daily at 06:00."
}

# =============================================================================
# CONNTRACK TUNING
# =============================================================================

tune_conntrack() {
    section "Tuning Connection Tracking"

    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true

    # Increase hash table size
    local nf_hash="/sys/module/nf_conntrack/parameters/hashsize"
    if [[ -w "$nf_hash" ]]; then
        echo 524288 > "$nf_hash"
        ok "Conntrack hash size set to 524288."
    fi

    # Ensure modules persist on reboot
    if [[ -f /etc/modules ]]; then
        grep -q "nf_conntrack" /etc/modules || echo "nf_conntrack" >> /etc/modules
    fi

    ok "Connection tracking tuned."
}

# =============================================================================
# LOG ROTATION SETUP
# =============================================================================

setup_logrotate() {
    section "Setting Up Log Rotation"

    cat > /etc/logrotate.d/ddos-security <<LOGROTATE_EOF
${LOG_DIR}/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        # Nothing to signal — file is opened fresh each run
        true
    endscript
}
LOGROTATE_EOF

    ok "Log rotation configured (14 days, daily)."
}

# =============================================================================
# PERSIST RULES ACROSS REBOOTS
# =============================================================================

persist_rules() {
    section "Persisting Firewall Rules"

    # Save iptables rules
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null && ok "Rules saved via netfilter-persistent."
    elif command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save  > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        ok "iptables rules saved to /etc/iptables/rules.v4 and rules.v6"
    fi

    # Save ipset
    if command -v ipset-persistent &>/dev/null; then
        ipset-persistent save &>/dev/null || true
    else
        mkdir -p /etc/ipset
        ipset save > /etc/ipset/ipsets.conf
        ok "ipset saved to /etc/ipset/ipsets.conf"
    fi

    # Create ipset restore script called by rc.local / systemd
    local restore_script="/usr/local/sbin/ddos-restore.sh"
    cat > "$restore_script" <<'RESTORE_EOF'
#!/usr/bin/env bash
# Restore DDoS ipset rules on boot
# Managed by advanced-ddos-security.sh
[[ -f /etc/ipset/ipsets.conf ]] && ipset restore < /etc/ipset/ipsets.conf 2>/dev/null || true
[[ -f /etc/iptables/rules.v4 ]] && iptables-restore  < /etc/iptables/rules.v4 2>/dev/null || true
[[ -f /etc/iptables/rules.v6 ]] && ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null || true
RESTORE_EOF
    chmod +x "$restore_script"

    # Systemd unit
    cat > /etc/systemd/system/ddos-restore.service <<SYSTEMD_EOF
[Unit]
Description=Restore DDoS Protection Rules
After=network.target
Before=fail2ban.service

[Service]
Type=oneshot
ExecStart=${restore_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

    systemctl daemon-reload &>/dev/null
    systemctl enable ddos-restore.service &>/dev/null
    ok "ddos-restore.service enabled (rules restored on boot)."
}

# =============================================================================
# STATUS DISPLAY
# =============================================================================

show_status() {
    clear
    print_banner
    section "DDoS Protection Status"

    echo ""
    echo -e "  ${BOLD}System${NC}"
    echo -e "  Hostname:       $(hostname -f)"
    echo -e "  Kernel:         $(uname -r)"
    echo -e "  Uptime:         $(uptime -p 2>/dev/null || uptime)"
    echo ""

    echo -e "  ${BOLD}iptables Chains${NC}"
    for chain in "$IPTABLES_CHAIN_INPUT" "$IPTABLES_CHAIN_SYNFLOOD" \
                 "$IPTABLES_CHAIN_UDPFLOOD" "$IPTABLES_CHAIN_ICMP" \
                 "$IPTABLES_CHAIN_HTTP"; do
        if iptables -L "$chain" &>/dev/null; then
            local rules; rules=$(iptables -L "$chain" 2>/dev/null | grep -c '^[A-Z]' || echo 0)
            echo -e "  ${GREEN}[ACTIVE]${NC} $chain (${rules} rules)"
        else
            echo -e "  ${RED}[MISSING]${NC} $chain"
        fi
    done
    echo ""

    echo -e "  ${BOLD}IP Sets${NC}"
    for setname in "$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_RATELIMIT" \
                   ddos_scanners ddos_bogons; do
        if ipset list "$setname" &>/dev/null; then
            local cnt; cnt=$(ipset list "$setname" 2>/dev/null | grep -c "^[0-9]" || echo 0)
            echo -e "  ${GREEN}[ACTIVE]${NC} $setname (${cnt} entries)"
        else
            echo -e "  ${YELLOW}[ABSENT]${NC} $setname"
        fi
    done
    echo ""

    echo -e "  ${BOLD}SYN Cookies${NC}"
    local sc; sc=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")
    [[ "$sc" == "1" ]] \
        && echo -e "  ${GREEN}[ON]${NC}  net.ipv4.tcp_syncookies = 1" \
        || echo -e "  ${RED}[OFF]${NC} net.ipv4.tcp_syncookies = $sc"
    echo ""

    echo -e "  ${BOLD}fail2ban${NC}"
    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "  ${GREEN}[ACTIVE]${NC} fail2ban is running"
        fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/^/  /' || true
    else
        echo -e "  ${YELLOW}[INACTIVE]${NC} fail2ban not running"
    fi
    echo ""

    echo -e "  ${BOLD}Active Connections${NC}"
    local conn_count; conn_count=$(ss -s 2>/dev/null | awk '/TCP:/{print $2}' | head -1 || echo "?")
    echo -e "  Total TCP connections: ${conn_count}"
    echo ""

    echo -e "  ${BOLD}Top Connecting IPs (top 5)${NC}"
    ss -tn state established 2>/dev/null \
        | awk 'NR>1{print $5}' \
        | grep -oP '^[0-9.]+' \
        | sort | uniq -c | sort -rn | head -5 \
        | awk '{printf "  %-8s %s\n", $1, $2}' || echo "  (none)"
    echo ""

    echo -e "  ${BOLD}Recently Banned IPs (last 10)${NC}"
    ipset list "$IPSET_RATELIMIT" 2>/dev/null \
        | grep "^[0-9]" | tail -10 \
        | awk '{printf "  %s\n", $1}' || echo "  (none)"
    echo ""

    echo -e "  ${DIM}Run 'tail -f ${LOG_FILE}' to watch live events.${NC}"
    echo ""
}

# =============================================================================
# GENERATE REPORT (INTERACTIVE)
# =============================================================================

generate_report() {
    local script="/usr/local/sbin/ddos-report.sh"
    if [[ -x "$script" ]]; then
        bash "$script"
    else
        warn "Report script not installed. Run with --install first."
    fi
}

# =============================================================================
# ROLLBACK / FLUSH
# =============================================================================

do_flush() {
    section "Rolling Back DDoS Protection Rules"

    if ! ask "Remove all DDoS iptables rules and ipsets?" "n"; then
        info "Rollback cancelled."
        return 0
    fi

    flush_ddos_rules

    # Remove custom ipsets
    for setname in "$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_RATELIMIT" \
                   ddos_scanners ddos_bogons; do
        ipset flush "$setname" 2>/dev/null || true
        ipset destroy "$setname" 2>/dev/null || true
        info "Removed ipset: $setname"
    done

    # Remove geo-block and portscan/bogon rules inserted directly into INPUT.
    # Use targeted deletion by comment to avoid wiping rules from other services
    # (fail2ban, docker, ufw). iptables -F INPUT would nuke everything.
    while iptables -D INPUT -m comment --comment "DDoS: geo-block" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: bogon source filter" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: port scanner block" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: port 0 probe" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: honeypot port probe" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: fragmented packet" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: SYN+RST" 2>/dev/null \
          || iptables -D INPUT -m comment --comment "DDoS: NEW non-SYN" 2>/dev/null; do
        :
    done
    info "Removed DDoS-specific INPUT chain rules (other services unaffected)."

    # Remove cron jobs
    rm -f "$CRON_AUTOBAN" "$CRON_REPORT"
    info "Cron jobs removed."

    # Restore sysctl defaults
    rm -f "$SYSCTL_FILE"
    sysctl --system &>/dev/null || true
    info "Custom sysctl file removed."

    # Disable systemd restore service
    systemctl disable ddos-restore.service &>/dev/null || true
    rm -f /etc/systemd/system/ddos-restore.service
    systemctl daemon-reload &>/dev/null || true
    info "ddos-restore.service disabled."

    ok "Rollback complete. All DDoS rules removed."
}

# =============================================================================
# FULL UNINSTALL
# =============================================================================

do_uninstall() {
    section "Uninstalling DDoS Security Script"

    if ! ask "Completely uninstall ddos-security (rules, configs, crons, scripts)?" "n"; then
        info "Uninstall cancelled."
        return 0
    fi

    # Call underlying cleanup directly — do_flush() has its own interactive ask()
    # prompt which would double-prompt the user and could leave dangling iptables
    # rules referencing destroyed ipsets if the user answered "no" to that prompt.
    flush_ddos_rules 2>/dev/null || true
    for setname in "$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_RATELIMIT" \
                   ddos_scanners ddos_bogons; do
        ipset flush "$setname" 2>/dev/null || true
        ipset destroy "$setname" 2>/dev/null || true
    done
    rm -f "$SYSCTL_FILE"
    sysctl --system &>/dev/null || true
    rm -f "$CRON_AUTOBAN" "$CRON_REPORT"
    systemctl disable ddos-restore.service &>/dev/null || true
    rm -f /etc/systemd/system/ddos-restore.service
    systemctl daemon-reload &>/dev/null || true

    rm -f /usr/local/sbin/ddos-autoban.sh
    rm -f /usr/local/sbin/ddos-report.sh
    rm -f /usr/local/sbin/ddos-restore.sh
    rm -f "$FAIL2BAN_FILTER" "$FAIL2BAN_JAIL"
    rm -f /etc/nginx/conf.d/ddos-ratelimit.conf 2>/dev/null || true
    rm -rf /etc/ddos-security
    rm -f /etc/logrotate.d/ddos-security
    rm -f /etc/suricata/rules/ddos-local.rules 2>/dev/null || true

    systemctl restart fail2ban &>/dev/null || true
    nginx -t &>/dev/null && systemctl reload nginx &>/dev/null || true

    ok "Uninstall complete."
}

# =============================================================================
# FULL INSTALL
# =============================================================================

do_install() {
    print_banner
    section "Full DDoS Security Installation"

    check_root
    check_os
    setup_logging
    write_default_config
    load_config
    backup_rules
    install_packages
    setup_ipsets
    update_blocklist_feeds
    tune_conntrack
    apply_sysctl_tuning
    init_chains
    apply_base_rules
    apply_blocklist_rules
    apply_syn_rules
    apply_udp_rules
    apply_icmp_rules
    apply_http_rules
    apply_portscan_rules
    apply_antispoofing_rules
    apply_fragment_rules
    apply_geoblock_rules
    apply_ipv6_rules
    configure_fail2ban
    configure_nginx_ratelimit
    configure_suricata
    install_autoban_script
    install_report_script
    setup_logrotate
    apply_tc_shaping
    persist_rules

    echo ""
    ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ok "  DDoS Security installation COMPLETE"
    ok "  Config:   $CONFIG_FILE"
    ok "  Logs:     $LOG_FILE"
    ok "  Status:   bash $0 --status"
    ok "  Report:   bash $0 --report"
    ok "  Rollback: bash $0 --flush"
    ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# =============================================================================
# RULES-ONLY MODE
# =============================================================================

do_rules_only() {
    check_root
    setup_logging
    load_config
    setup_ipsets
    init_chains
    apply_base_rules
    apply_blocklist_rules
    apply_syn_rules
    apply_udp_rules
    apply_icmp_rules
    apply_http_rules
    apply_portscan_rules
    apply_antispoofing_rules
    apply_fragment_rules
    apply_geoblock_rules
    apply_ipv6_rules
    ok "iptables/ipset rules applied."
}

# =============================================================================
# SYSCTL-ONLY MODE
# =============================================================================

do_sysctl_only() {
    check_root
    setup_logging
    load_config
    apply_sysctl_tuning
    ok "Kernel sysctl tuning applied."
}

# =============================================================================
# ARGUMENT PARSING & ENTRY POINT
# =============================================================================

usage() {
    echo ""
    echo -e "  ${BOLD}Usage:${NC} sudo bash $0 [OPTION]"
    echo ""
    echo "  Options:"
    echo "    --install        Full install (packages, rules, services, crons)"
    echo "    --rules-only     Apply iptables/ipset rules only"
    echo "    --sysctl-only    Apply kernel sysctl tuning only"
    echo "    --status         Show current protection status"
    echo "    --flush          Remove all DDoS rules (rollback)"
    echo "    --report         Generate DDoS activity report"
    echo "    --uninstall      Remove all changes made by this script"
    echo "    --update-feeds   Update IP reputation blocklist feeds only"
    echo "    --help           Show this help message"
    echo ""
}

main() {
    local action="${1:---help}"

    case "$action" in
        --install)
            do_install
            ;;
        --rules-only)
            do_rules_only
            ;;
        --sysctl-only)
            do_sysctl_only
            ;;
        --status)
            check_root
            show_status
            ;;
        --flush)
            check_root
            setup_logging
            do_flush
            ;;
        --report)
            check_root
            setup_logging
            generate_report
            ;;
        --uninstall)
            check_root
            setup_logging
            do_uninstall
            ;;
        --update-feeds)
            check_root
            setup_logging
            load_config
            setup_ipsets
            update_blocklist_feeds
            ;;
        --help|-h)
            print_banner
            usage
            ;;
        *)
            err "Unknown option: $action"
            usage
            exit 1
            ;;
    esac
}

main "$@"
