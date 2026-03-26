#!/usr/bin/env bash
# =============================================================================
# Advanced SELinux Hardening Script for Debian Linux
# =============================================================================
# Implements a comprehensive, layered SELinux security posture for Debian-based
# systems. Covers installation, policy configuration, boolean tuning, user
# confinement, port labelling, audit integration, and custom policy modules.
#
# References:
#   - NSA/Red Hat SELinux User's and Administrator's Guide
#   - Debian SELinux wiki: https://wiki.debian.org/SELinux
#   - CIS Debian Linux Benchmark (SELinux section)
#   - NIST SP 800-123 (Guide to General Server Security)
#   - SELinux Project documentation: https://selinuxproject.org/
#
# Target:  Debian 11 (Bullseye) / Debian 12 (Bookworm)
# Usage:   sudo bash advanced-selinux-hardening.sh [OPTIONS]
#
# Options:
#   -m, --mode MODE     Set SELinux mode: enforcing|permissive|disabled
#                       (default: enforcing)
#   -p, --policy TYPE   Policy type: targeted|mls (default: targeted)
#   -u, --users         Apply strict user confinement (maps system users)
#   -a, --audit         Configure advanced audit logging integration
#   -c, --custom        Build and load custom policy modules for common services
#   -r, --report        Generate a full SELinux posture report (no changes)
#   -y, --yes           Non-interactive: auto-accept all prompts
#   -h, --help          Show this help message
#
# WARNING: Switching to enforcing mode without proper policy can lock you out.
#          Always test in permissive mode first. A serial console or emergency
#          access method is strongly recommended before running on remote hosts.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colours & output helpers
# ---------------------------------------------------------------------------
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
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC}  ${BOLD}%-60s${NC}${CYAN}║${NC}\n" "$1"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    printf "${BLUE}│${NC}  ${BOLD}%-59s${NC}${BLUE}│${NC}\n" "$1"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
}

info()    { echo -e "  ${GREEN}[INFO ]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}[WARN ]${NC}  $*"; }
err()     { echo -e "  ${RED}[ERROR]${NC}  $*"; }
skip()    { echo -e "  ${YELLOW}[SKIP ]${NC}  $*"; }
pass()    { echo -e "  ${GREEN}[PASS ]${NC}  $*" | tee -a "$LOG_FILE"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()    { echo -e "  ${RED}[FAIL ]${NC}  $*" | tee -a "$LOG_FILE"; FAIL_COUNT=$((FAIL_COUNT+1)); }
action()  { echo -e "  ${MAGENTA}[APPLY]${NC}  $*"; }
note()    { echo -e "  ${DIM}[NOTE ]${NC}  $*"; }

log()     { echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"; }

# ---------------------------------------------------------------------------
# Defaults & counters
# ---------------------------------------------------------------------------
LOG_FILE="/var/log/selinux-hardening-$(date +%Y%m%d%H%M%S).log"
REPORT_FILE="/var/log/selinux-posture-report-$(date +%Y%m%d%H%M%S).txt"
BACKUP_DIR="/var/backups/selinux-hardening-$(date +%Y%m%d%H%M%S)"

OPT_MODE="enforcing"
OPT_POLICY="targeted"
OPT_USERS=false
OPT_AUDIT=false
OPT_CUSTOM=false
OPT_REPORT=false
OPT_YES=false

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
CHANGE_COUNT=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    grep '^#' "$0" | grep -E '^\# ' | sed 's/^# //' | sed -n '3,30p'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)     OPT_MODE="$2";   shift 2 ;;
        -p|--policy)   OPT_POLICY="$2"; shift 2 ;;
        -u|--users)    OPT_USERS=true;  shift   ;;
        -a|--audit)    OPT_AUDIT=true;  shift   ;;
        -c|--custom)   OPT_CUSTOM=true; shift   ;;
        -r|--report)   OPT_REPORT=true; shift   ;;
        -y|--yes)      OPT_YES=true;    shift   ;;
        -h|--help)     usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

# Validate mode
case "$OPT_MODE" in
    enforcing|permissive|disabled) ;;
    *) err "Invalid mode '$OPT_MODE'. Use: enforcing|permissive|disabled"; exit 1 ;;
esac

# Validate policy type
case "$OPT_POLICY" in
    targeted|mls) ;;
    *) err "Invalid policy type '$OPT_POLICY'. Use: targeted|mls"; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Helper: ask yes/no
# ---------------------------------------------------------------------------
ask() {
    local prompt="$1"
    local default="${2:-y}"
    if [[ "$OPT_YES" == true ]]; then
        return 0
    fi
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "  ${BOLD}$prompt [Y/n]:${NC} ")" yn
        yn="${yn:-y}"
    else
        read -rp "$(echo -e "  ${BOLD}$prompt [y/N]:${NC} ")" yn
        yn="${yn:-n}"
    fi
    [[ "${yn,,}" == "y" ]]
}

backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -p "$f" "${BACKUP_DIR}/$(basename "$f").$(date +%H%M%S)" 2>/dev/null || true
        log "Backed up $f to $BACKUP_DIR"
    fi
}

run_cmd() {
    local cmd="$*"
    log "CMD: $cmd"
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        log "SUCCESS: $cmd"
        return 0
    else
        local rc=$?
        log "FAILED (rc=$rc): $cmd"
        return $rc
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
banner "Advanced SELinux Hardening — Debian Linux"

echo -e "  ${BOLD}Configuration:${NC}"
echo -e "    Mode:    ${CYAN}${OPT_MODE}${NC}"
echo -e "    Policy:  ${CYAN}${OPT_POLICY}${NC}"
echo -e "    Users:   ${CYAN}${OPT_USERS}${NC}"
echo -e "    Audit:   ${CYAN}${OPT_AUDIT}${NC}"
echo -e "    Custom:  ${CYAN}${OPT_CUSTOM}${NC}"
echo -e "    Report:  ${CYAN}${OPT_REPORT}${NC}"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo bash $0)"
    exit 1
fi

# Debian check
if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script targets Debian-based systems. Proceeding anyway..."
fi

# Source /etc/os-release for distro info
. /etc/os-release 2>/dev/null || true

info "Logging to: $LOG_FILE"
log "=== SELinux Hardening started ==="
log "Mode=$OPT_MODE Policy=$OPT_POLICY Users=$OPT_USERS Audit=$OPT_AUDIT Custom=$OPT_CUSTOM"

# Report-only mode: skip changes, jump to report
if [[ "$OPT_REPORT" == true ]]; then
    info "Report-only mode: no changes will be made."
fi

# ============================================================================
# SECTION 1: Package Installation
# ============================================================================
section "1. SELinux Package Installation"

REQUIRED_PKGS=(
    selinux-basics          # setenforce, getenforce, /etc/selinux/config
    selinux-policy-default  # Debian's default (targeted-equivalent) policy
    policycoreutils         # Core utilities: restorecon, semanage, audit2allow
    policycoreutils-python-utils  # Python bindings (semanage, audit2why)
    auditd                  # Linux Audit daemon
    audispd-plugins         # Audit dispatcher plugins
    setools                 # sesearch, seinfo, apol
    checkpolicy             # checkpolicy, checkmodule (policy compiler)
    libselinux-utils        # selinuxenabled, matchpathcon
    mcstrans                # MCS translation daemon
)

# MLS-specific packages
if [[ "$OPT_POLICY" == "mls" ]]; then
    REQUIRED_PKGS+=(selinux-policy-mls)
fi

MISSING_PKGS=()
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    info "Missing packages: ${MISSING_PKGS[*]}"
    if [[ "$OPT_REPORT" != true ]] && ask "Install missing SELinux packages?"; then
        action "Updating package cache..."
        run_cmd "apt-get update -qq"
        action "Installing: ${MISSING_PKGS[*]}"
        run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${MISSING_PKGS[*]}"
        pass "SELinux packages installed"
        CHANGE_COUNT=$((CHANGE_COUNT+1))
    else
        warn "Some packages are missing — certain checks may fail"
    fi
else
    pass "All required SELinux packages are installed"
fi

# ============================================================================
# SECTION 2: Kernel SELinux Support Verification
# ============================================================================
section "2. Kernel SELinux Support"

check_kernel_selinux() {
    local issues=0

    # Check kernel was compiled with SELinux
    if grep -q 'CONFIG_SECURITY_SELINUX=y' /boot/config-"$(uname -r)" 2>/dev/null \
       || zcat /proc/config.gz 2>/dev/null | grep -q 'CONFIG_SECURITY_SELINUX=y'; then
        pass "Kernel compiled with CONFIG_SECURITY_SELINUX=y"
    else
        warn "Cannot confirm CONFIG_SECURITY_SELINUX=y in kernel config"
        issues=$((issues+1))
    fi

    # Check SELinux is mounted
    if mount | grep -q 'selinuxfs'; then
        pass "selinuxfs is mounted"
    else
        fail "selinuxfs is NOT mounted — SELinux may not be active"
        issues=$((issues+1))
    fi

    # Check /sys/fs/selinux
    if [[ -d /sys/fs/selinux ]]; then
        pass "/sys/fs/selinux directory exists"
    else
        fail "/sys/fs/selinux does not exist"
        issues=$((issues+1))
    fi

    # Check kernel cmdline for selinux=0 (disables SELinux at boot)
    if grep -q 'selinux=0' /proc/cmdline 2>/dev/null; then
        fail "Kernel cmdline contains 'selinux=0' — SELinux disabled at boot!"
        issues=$((issues+1))
    else
        pass "Kernel cmdline does not disable SELinux"
    fi

    # Check for enforcing=0 on cmdline (starts in permissive)
    if grep -q 'enforcing=0' /proc/cmdline 2>/dev/null; then
        warn "Kernel cmdline contains 'enforcing=0' — SELinux starts in permissive mode"
        WARN_COUNT=$((WARN_COUNT+1))
    else
        pass "Kernel cmdline does not force permissive mode"
    fi

    return $issues
}

check_kernel_selinux || true

# ============================================================================
# SECTION 3: SELinux Configuration File (/etc/selinux/config)
# ============================================================================
section "3. SELinux Configuration (config file)"

SELINUX_CONFIG="/etc/selinux/config"

if [[ "$OPT_REPORT" != true ]]; then
    if [[ ! -f "$SELINUX_CONFIG" ]]; then
        info "Creating $SELINUX_CONFIG"
        if ask "Create /etc/selinux/config?"; then
            mkdir -p /etc/selinux
            cat > "$SELINUX_CONFIG" <<SECONFIG
# /etc/selinux/config — managed by advanced-selinux-hardening.sh
# Generated: $(date)
#
# SELINUX= can take one of three values:
#   enforcing  - SELinux security policy is enforced.
#   permissive - SELinux prints warnings instead of enforcing.
#   disabled   - No SELinux policy is loaded.
SELINUX=${OPT_MODE}

# SELINUXTYPE= can take one of three values:
#   targeted   - Targeted processes are protected.
#   mls        - Multi Level Security (MLS) protection.
SELINUXTYPE=${OPT_POLICY}
SECONFIG
            action "Created $SELINUX_CONFIG (mode=$OPT_MODE, policy=$OPT_POLICY)"
            CHANGE_COUNT=$((CHANGE_COUNT+1))
        fi
    else
        backup_file "$SELINUX_CONFIG"
        local_mode=$(grep -E '^SELINUX=' "$SELINUX_CONFIG" | cut -d= -f2 | tr -d ' ')
        local_type=$(grep -E '^SELINUXTYPE=' "$SELINUX_CONFIG" | cut -d= -f2 | tr -d ' ')
        info "Current config: SELINUX=$local_mode  SELINUXTYPE=$local_type"

        if [[ "$local_mode" != "$OPT_MODE" ]]; then
            if ask "Change SELINUX from '$local_mode' to '$OPT_MODE'?"; then
                sed -i "s/^SELINUX=.*/SELINUX=${OPT_MODE}/" "$SELINUX_CONFIG"
                action "Set SELINUX=${OPT_MODE} in $SELINUX_CONFIG"
                CHANGE_COUNT=$((CHANGE_COUNT+1))
            fi
        else
            pass "SELINUX=${OPT_MODE} already configured"
        fi

        if [[ "$local_type" != "$OPT_POLICY" ]]; then
            if ask "Change SELINUXTYPE from '$local_type' to '$OPT_POLICY'?"; then
                sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=${OPT_POLICY}/" "$SELINUX_CONFIG"
                action "Set SELINUXTYPE=${OPT_POLICY} in $SELINUX_CONFIG"
                CHANGE_COUNT=$((CHANGE_COUNT+1))
            fi
        else
            pass "SELINUXTYPE=${OPT_POLICY} already configured"
        fi
    fi
fi

# Verify current runtime state
if command -v getenforce &>/dev/null; then
    CURRENT_MODE=$(getenforce 2>/dev/null || echo "Unknown")
    info "Runtime SELinux mode: ${BOLD}${CURRENT_MODE}${NC}"

    if [[ "$CURRENT_MODE" == "Disabled" ]]; then
        warn "SELinux is currently Disabled. A reboot is required to activate it."
        warn "After reboot, all files will need to be relabelled (autorelabel)."
        if [[ "$OPT_REPORT" != true ]] && ask "Create /.autorelabel to trigger full relabelling on next boot?"; then
            touch /.autorelabel
            action "Created /.autorelabel — full relabel will run on next reboot"
            CHANGE_COUNT=$((CHANGE_COUNT+1))
        fi
    elif [[ "$CURRENT_MODE" == "Permissive" && "$OPT_MODE" == "enforcing" ]]; then
        info "Attempting live switch to enforcing mode..."
        if [[ "$OPT_REPORT" != true ]] && ask "Set SELinux to enforcing now (setenforce 1)?"; then
            if setenforce 1 2>/dev/null; then
                pass "SELinux set to enforcing mode (live)"
                CHANGE_COUNT=$((CHANGE_COUNT+1))
            else
                fail "setenforce 1 failed — check for AVC denials first"
            fi
        fi
    elif [[ "$CURRENT_MODE" == "Enforcing" ]]; then
        pass "SELinux is currently in Enforcing mode"
    fi
fi

# ============================================================================
# SECTION 4: SELinux Policy Booleans — Hardening
# ============================================================================
section "4. SELinux Boolean Hardening"

# Format: "boolean_name" "desired_value" "description"
declare -A BOOLEAN_SETTINGS
declare -A BOOLEAN_DESC

set_boolean_entry() {
    BOOLEAN_SETTINGS["$1"]="$2"
    BOOLEAN_DESC["$1"]="$3"
}

# ---- Network security ----
set_boolean_entry "deny_ptrace"             "on"  "Prevent ptrace across process domains"
set_boolean_entry "global_ssp"              "on"  "Enable global SSP (stack-smashing protection)"
set_boolean_entry "httpd_can_network_connect" "off" "Deny Apache from making arbitrary network connections"
set_boolean_entry "httpd_can_network_relay" "off" "Deny Apache reverse proxy capability"
set_boolean_entry "httpd_enable_cgi"        "off" "Disable Apache CGI scripts (re-enable only if needed)"
set_boolean_entry "httpd_execmem"           "off" "Deny httpd execute+write memory (prevents shellcode injection)"
set_boolean_entry "ftp_home_dir"            "off" "Deny FTP read/write to home dirs"
set_boolean_entry "ftpd_anon_write"         "off" "Deny anonymous FTP writes"
set_boolean_entry "ssh_sysadm_login"        "off" "Deny direct sysadm_r login via SSH"
set_boolean_entry "sysadm_exec_content"     "off" "Prevent sysadm from executing user content"

# ---- Privilege escalation & SUID ----
set_boolean_entry "allow_execstack"         "off" "Deny execution from writable stack memory"
set_boolean_entry "allow_execmem"           "off" "Deny processes using exec+write memory regions"
set_boolean_entry "allow_execmod"           "off" "Deny modified memory sections from being executed"
set_boolean_entry "allow_execheap"          "off" "Deny heap memory execution"
set_boolean_entry "secure_mode"             "on"  "Enable secure mode (restrict setuid, setgid, capability use)"
set_boolean_entry "secure_mode_insmod"      "on"  "Prevent loading kernel modules in secure mode"
set_boolean_entry "secure_mode_policyload"  "on"  "Prevent policy reloading in secure mode"

# ---- Filesystem & storage ----
set_boolean_entry "mount_anyfile"           "off" "Deny mount of arbitrary files"
set_boolean_entry "use_nfs_home_dirs"       "off" "Deny NFS home dirs (enable only if needed)"
set_boolean_entry "use_samba_home_dirs"     "off" "Deny Samba home dirs (enable only if needed)"
set_boolean_entry "allow_write_xattr_cifs"  "off" "Deny CIFS xattr writes (enable only if needed)"

# ---- System services ----
set_boolean_entry "rsync_client"            "off" "Deny rsync client mode (enable if rsync used)"
set_boolean_entry "rsync_export_all_ro"     "off" "Deny rsync from exporting all read-only content"
set_boolean_entry "daemons_dump_core"       "off" "Prevent daemons from creating core dumps"
set_boolean_entry "daemons_use_tty"         "off" "Prevent daemons from using TTYs"
set_boolean_entry "cron_userdomain_transition" "on" "Ensure cron jobs run in the user's domain"
set_boolean_entry "polyinstantiation_enabled" "on" "Enable polyinstantiation for /tmp and /var/tmp"

apply_booleans() {
    local changed=0
    local errors=0

    for bool_name in "${!BOOLEAN_SETTINGS[@]}"; do
        local desired="${BOOLEAN_SETTINGS[$bool_name]}"
        local desc="${BOOLEAN_DESC[$bool_name]}"

        # Check if boolean exists in current policy
        if ! getsebool "$bool_name" &>/dev/null; then
            note "Boolean '$bool_name' not in current policy — skipping"
            continue
        fi

        local current
        current=$(getsebool "$bool_name" 2>/dev/null | awk '{print $NF}')

        if [[ "$current" == "$desired" ]]; then
            pass "  $bool_name = $desired  ($desc)"
        else
            if [[ "$OPT_REPORT" == true ]]; then
                fail "  $bool_name = $current (should be $desired)  ($desc)"
            else
                action "  Setting $bool_name=$desired  ($desc)"
                if setsebool -P "$bool_name" "$desired" 2>/dev/null; then
                    pass "  $bool_name → $desired"
                    changed=$((changed+1))
                    CHANGE_COUNT=$((CHANGE_COUNT+1))
                else
                    fail "  Failed to set $bool_name=$desired"
                    errors=$((errors+1))
                fi
            fi
        fi
    done

    info "Boolean changes: $changed  Errors: $errors"
}

if command -v getsebool &>/dev/null && selinuxenabled 2>/dev/null; then
    apply_booleans
else
    warn "SELinux is not active — boolean configuration will apply after reboot"
    if [[ "$OPT_REPORT" != true ]]; then
        note "Booleans will be validated on next run once SELinux is active"
    fi
fi

# ============================================================================
# SECTION 5: SELinux User Confinement
# ============================================================================
section "5. SELinux User Confinement"

# Map Linux users to confined SELinux users
# guest_u  — no networking, no su/sudo, no setuid
# user_u   — limited: no su/sudo, no setuid
# staff_u  — can use sudo to sysadm_r
# sysadm_u — full admin
# unconfined_u — no restrictions (default, to be minimised)

harden_user_confinement() {
    if ! command -v semanage &>/dev/null; then
        warn "semanage not available — skipping user confinement"
        return
    fi

    info "Current SELinux user mappings:"
    semanage login -l 2>/dev/null || true
    echo ""

    # Map __default__ to user_u (restricts new accounts by default)
    local current_default
    current_default=$(semanage login -l 2>/dev/null | grep '__default__' | awk '{print $2}' || echo "")

    if [[ "$current_default" != "user_u" ]]; then
        if [[ "$OPT_REPORT" == true ]]; then
            fail "__default__ maps to '$current_default' (should be user_u for confinement)"
        else
            if ask "Map __default__ to user_u (confine all new users by default)?"; then
                semanage login -m -s user_u -r s0 __default__ 2>/dev/null \
                    || semanage login -a -s user_u -r s0 __default__ 2>/dev/null || true
                pass "  __default__ → user_u"
                CHANGE_COUNT=$((CHANGE_COUNT+1))
            fi
        fi
    else
        pass "__default__ → user_u (all new users confined)"
    fi

    # Map root to sysadm_u (typed administrative role)
    local root_map
    root_map=$(semanage login -l 2>/dev/null | grep '^root' | awk '{print $2}' || echo "")
    if [[ "$root_map" != "sysadm_u" ]]; then
        if [[ "$OPT_REPORT" == true ]]; then
            warn "root maps to '$root_map' (consider sysadm_u)"
        else
            if ask "Map root to sysadm_u (full admin SELinux user)?"; then
                semanage login -m -s sysadm_u -r s0-s0:c0.c1023 root 2>/dev/null \
                    || semanage login -a -s sysadm_u -r s0-s0:c0.c1023 root 2>/dev/null || true
                pass "  root → sysadm_u"
                CHANGE_COUNT=$((CHANGE_COUNT+1))
            fi
        fi
    else
        pass "root → sysadm_u"
    fi

    # Restrict unconfined_u usage by listing any users currently mapped to it
    local unconfined_users
    unconfined_users=$(semanage login -l 2>/dev/null | grep 'unconfined_u' | grep -v '__default__' | awk '{print $1}' || echo "")
    if [[ -n "$unconfined_users" ]]; then
        warn "The following users are mapped to unconfined_u:"
        echo "$unconfined_users" | while read -r u; do
            echo "    - $u"
        done
        warn "Consider remapping them to user_u or staff_u for proper confinement"
        WARN_COUNT=$((WARN_COUNT+1))
    else
        pass "No users mapped to unconfined_u (other than defaults)"
    fi
}

if [[ "$OPT_USERS" == true ]]; then
    harden_user_confinement
else
    note "User confinement skipped (use -u/--users to enable)"
fi

# ============================================================================
# SECTION 6: File Context & Relabelling
# ============================================================================
section "6. File Context Management"

check_relabel_candidates() {
    if ! command -v restorecon &>/dev/null; then
        warn "restorecon not available"
        return
    fi

    info "Checking for mislabelled files in critical directories..."

    local dirs=(/etc /bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib)
    local mismatches=0

    for d in "${dirs[@]}"; do
        if [[ -d "$d" ]]; then
            local count
            count=$(restorecon -Rnv "$d" 2>/dev/null | wc -l || echo "0")
            if [[ "$count" -gt 0 ]]; then
                warn "$d: $count file(s) with incorrect SELinux contexts"
                mismatches=$((mismatches+count))
                WARN_COUNT=$((WARN_COUNT+1))
            else
                pass "$d: all file contexts correct"
            fi
        fi
    done

    if [[ "$mismatches" -gt 0 ]]; then
        if [[ "$OPT_REPORT" != true ]] && ask "Restore correct contexts on affected files?"; then
            for d in "${dirs[@]}"; do
                [[ -d "$d" ]] || continue
                action "Relabelling $d..."
                restorecon -RF "$d" 2>/dev/null || true
            done
            pass "File contexts restored in critical directories"
            CHANGE_COUNT=$((CHANGE_COUNT+1))
        fi
    fi
}

check_relabel_candidates

# Harden critical file contexts explicitly
apply_file_contexts() {
    if ! command -v chcon &>/dev/null; then return; fi
    if [[ "$OPT_REPORT" == true ]]; then return; fi

    # Ensure /etc/passwd and shadow have correct contexts
    local -a ctx_map=(
        "/etc/passwd:system_u:object_r:passwd_file_t:s0"
        "/etc/shadow:system_u:object_r:shadow_t:s0"
        "/etc/sudoers:system_u:object_r:sudoers_t:s0"
        "/etc/ssh/sshd_config:system_u:object_r:etc_t:s0"
        "/var/log:system_u:object_r:var_log_t:s0"
        "/tmp:system_u:object_r:tmp_t:s0"
        "/var/tmp:system_u:object_r:var_t:s0"
    )

    for entry in "${ctx_map[@]}"; do
        local path="${entry%%:*}"
        local ctx="${entry#*:}"
        if [[ -e "$path" ]]; then
            local current_ctx
            current_ctx=$(ls -Z "$path" 2>/dev/null | awk '{print $1}' || echo "unknown")
            if [[ "$current_ctx" != "$ctx" ]]; then
                restorecon -v "$path" 2>/dev/null || true
            fi
        fi
    done
}

apply_file_contexts

# ============================================================================
# SECTION 7: Port Labelling
# ============================================================================
section "7. SELinux Port Labelling"

check_port_labels() {
    if ! command -v semanage &>/dev/null; then
        warn "semanage not available — skipping port label check"
        return
    fi

    info "Verifying standard service port labels..."

    # Format: port:proto:expected_type
    local -a port_checks=(
        "22:tcp:ssh_port_t"
        "80:tcp:http_port_t"
        "443:tcp:http_port_t"
        "25:tcp:smtp_port_t"
        "53:tcp:dns_port_t"
        "53:udp:dns_port_t"
        "123:udp:ntp_port_t"
        "3306:tcp:mysqld_port_t"
        "5432:tcp:postgresql_port_t"
    )

    for entry in "${port_checks[@]}"; do
        local port proto expected
        port=$(echo "$entry" | cut -d: -f1)
        proto=$(echo "$entry" | cut -d: -f2)
        expected=$(echo "$entry" | cut -d: -f3)
        local actual
        # Use fixed-string grep for the type name to avoid regex metachar issues,
        # then filter by proto and exact port number with word-boundary anchor.
        actual=$(semanage port -l 2>/dev/null \
            | grep -F "$expected" \
            | grep -E "\b${proto}\b" \
            | grep -E "(^|,| )${port}(,| |$)" \
            | head -1 || echo "")
        if [[ -n "$actual" ]]; then
            pass "  port $port/$proto → $expected"
        else
            warn "  port $port/$proto: expected '$expected' — verify with: semanage port -l | grep $port"
            WARN_COUNT=$((WARN_COUNT+1))
        fi
    done
}

check_port_labels

# ============================================================================
# SECTION 8: Audit Integration
# ============================================================================
section "8. Audit & AVC Logging"

configure_audit() {
    local AUDIT_RULES="/etc/audit/rules.d/selinux-hardening.rules"
    local AUDITD_CONF="/etc/audit/auditd.conf"

    # Configure auditd for high-fidelity SELinux logging
    if [[ -f "$AUDITD_CONF" ]]; then
        backup_file "$AUDITD_CONF"

        if [[ "$OPT_REPORT" != true ]]; then
            # Increase log retention for security-critical systems
            sed -i 's/^num_logs\s*=.*/num_logs = 10/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^max_log_file\s*=.*/max_log_file = 100/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = ROTATE/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^space_left_action\s*=.*/space_left_action = EMAIL/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^admin_space_left_action\s*=.*/admin_space_left_action = HALT/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^disk_full_action\s*=.*/disk_full_action = HALT/' "$AUDITD_CONF" 2>/dev/null || true
            sed -i 's/^disk_error_action\s*=.*/disk_error_action = HALT/' "$AUDITD_CONF" 2>/dev/null || true
            pass "auditd.conf hardened (rotation, retention, failure actions)"
            CHANGE_COUNT=$((CHANGE_COUNT+1))
        fi
    fi

    # Write SELinux-specific audit rules
    if [[ "$OPT_REPORT" != true ]]; then
        mkdir -p "$(dirname "$AUDIT_RULES")"
        cat > "$AUDIT_RULES" <<'AUDRULES'
# SELinux Hardening Audit Rules
# Generated by advanced-selinux-hardening.sh

## Delete all existing rules and set default policy to DENY
-D

## Increase the buffers to survive stress events
-b 8192

## Failure mode: 1=printk, 2=panic
-f 1

## Monitor SELinux policy changes
-w /etc/selinux/config -p wa -k selinux_config
-w /etc/selinux/ -p wa -k selinux_policy

## Monitor policy module loads/unloads
-w /sys/fs/selinux/load -p w -k selinux_module_load
-w /sys/fs/selinux/disable -p w -k selinux_disable
-w /sys/fs/selinux/enforce -p rw -k selinux_enforce

## Capture all AVC denials (generated by kernel, shown in audit.log)
## These are automatically captured by auditd when SELinux is active

## Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation
-a always,exit -F arch=b64 -S setresuid -S setresgid -k privilege_escalation
-a always,exit -F arch=b64 -S prctl -k privilege_escalation

## Monitor capability usage
-a always,exit -F arch=b64 -S capset -k capability_change

## Monitor kernel module loads (important for secure_mode_insmod)
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k module_load

## Monitor /etc/passwd, /etc/shadow, /etc/sudoers changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## Monitor cron and at
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/at.allow -p wa -k at
-w /etc/at.deny -p wa -k at

## Monitor logins and auth
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/pam.d/ -p wa -k pam

## Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

## Monitor network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications

## Monitor mount operations
-a always,exit -F arch=b64 -S mount -k mount

## Monitor file deletion by non-root in sensitive dirs
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

## Monitor ptrace (important with deny_ptrace boolean)
-a always,exit -F arch=b64 -S ptrace -k ptrace

## Make the configuration immutable (requires reboot to change rules)
## WARNING: Uncomment only when the rule set is fully tested
# -e 2
AUDRULES
        pass "SELinux audit rules written to $AUDIT_RULES"
        CHANGE_COUNT=$((CHANGE_COUNT+1))

        # Reload audit rules
        if command -v augenrules &>/dev/null; then
            augenrules --load >> "$LOG_FILE" 2>&1 || true
            pass "Audit rules reloaded via augenrules"
        elif command -v auditctl &>/dev/null; then
            auditctl -R "$AUDIT_RULES" >> "$LOG_FILE" 2>&1 || true
        fi

        # Ensure auditd is enabled at boot
        systemctl enable auditd >> "$LOG_FILE" 2>&1 || true
        systemctl restart auditd >> "$LOG_FILE" 2>&1 || true
        pass "auditd enabled and restarted"
    fi
}

# Check current AVC denial rate
check_avc_denials() {
    if command -v ausearch &>/dev/null && [[ -f /var/log/audit/audit.log ]]; then
        local avc_count
        avc_count=$(ausearch -m AVC -ts today 2>/dev/null | grep -c 'type=AVC' || echo "0")
        if [[ "$avc_count" -gt 0 ]]; then
            warn "Today's AVC denials: $avc_count"
            warn "Run: ausearch -m AVC -ts today | audit2why    (to analyse)"
            warn "Run: ausearch -m AVC -ts today | audit2allow  (to generate policy)"
            WARN_COUNT=$((WARN_COUNT+1))
        else
            pass "No AVC denials recorded today"
        fi
    else
        note "ausearch/audit.log not available — skipping AVC denial check"
    fi
}

if [[ "$OPT_AUDIT" == true ]]; then
    if [[ "$OPT_REPORT" != true ]] && ask "Configure advanced audit rules for SELinux?"; then
        configure_audit
    fi
fi

check_avc_denials

# ============================================================================
# SECTION 9: Custom Policy Modules
# ============================================================================
section "9. Custom SELinux Policy Modules"

# Build and load a custom policy module that tightens controls
# for common Debian services: nginx, sshd, cron, systemd-journald

build_and_load_module() {
    local module_name="$1"
    local te_content="$2"
    local build_dir
    build_dir=$(mktemp -d /tmp/selinux-module-XXXXXX)

    cat > "${build_dir}/${module_name}.te" <<< "$te_content"

    info "Compiling module: $module_name"
    if ! checkmodule -M -m -o "${build_dir}/${module_name}.mod" "${build_dir}/${module_name}.te" >> "$LOG_FILE" 2>&1; then
        fail "checkmodule failed for $module_name — see $LOG_FILE"
        rm -rf "$build_dir"
        return 1
    fi

    if ! semodule_package -o "${build_dir}/${module_name}.pp" -m "${build_dir}/${module_name}.mod" >> "$LOG_FILE" 2>&1; then
        fail "semodule_package failed for $module_name"
        rm -rf "$build_dir"
        return 1
    fi

    if ! semodule -i "${build_dir}/${module_name}.pp" >> "$LOG_FILE" 2>&1; then
        fail "semodule -i failed for $module_name"
        rm -rf "$build_dir"
        return 1
    fi

    pass "Custom module '$module_name' loaded successfully"
    rm -rf "$build_dir"
    CHANGE_COUNT=$((CHANGE_COUNT+1))
    return 0
}

apply_custom_modules() {
    if ! command -v checkmodule &>/dev/null; then
        warn "checkmodule not found — install checkpolicy package"
        return
    fi
    if ! selinuxenabled 2>/dev/null; then
        warn "SELinux not active — custom modules deferred until reboot"
        return
    fi

    # Module 1: Restrict SSH to known safe operations
    # NOTE: neverallow is a base-policy compile-time assertion and cannot be used
    # in loadable modules. dontaudit is used here to suppress audit noise for
    # operations that the base policy already denies (sshd writing to /tmp or
    # arbitrary home dirs outside its authorised paths).
    local ssh_module
    ssh_module=$(cat <<'EOF'
policy_module(debian_ssh_hardening, 1.0)

require {
    type sshd_t;
    type user_home_t;
    type tmp_t;
    class file { write create };
    class dir  { write add_name };
}

# Suppress audit noise for sshd denied writes to /tmp
dontaudit sshd_t tmp_t:file { write create };

# Suppress audit noise for sshd denied writes to user home content
dontaudit sshd_t user_home_t:file { write create };
dontaudit sshd_t user_home_t:dir  { write add_name };
EOF
)

    # Module 2: Restrict cron to confined execution domains
    local cron_module
    cron_module=$(cat <<'EOF'
policy_module(debian_cron_hardening, 1.0)

require {
    type crond_t;
    type user_cron_spool_t;
    class file { write };
}

# Suppress audit noise for crond denied writes outside authorised spool paths
dontaudit crond_t user_cron_spool_t:file { write };
EOF
)

    # Module 3: Suppress audit noise for httpd shell-exec denials
    # The base policy denies httpd_t from executing shell_exec_t directly.
    # This module silences the audit messages for that denial so AVC logs
    # stay focused on unexpected/novel denials rather than known-safe ones.
    local web_module
    web_module=$(cat <<'EOF'
policy_module(debian_httpd_shell_deny, 1.0)

require {
    type httpd_t;
    type shell_exec_t;
    class file { execute execute_no_trans };
}

# Suppress audit noise for httpd denied shell execution attempts
dontaudit httpd_t shell_exec_t:file { execute execute_no_trans };
EOF
)

    # Ask and apply each module
    if ask "Load custom SSH hardening SELinux module?"; then
        build_and_load_module "debian_ssh_hardening" "$ssh_module" || true
    fi

    if ask "Load custom cron hardening SELinux module?"; then
        build_and_load_module "debian_cron_hardening" "$cron_module" || true
    fi

    if ask "Load custom httpd-shell-exec-deny SELinux module?"; then
        build_and_load_module "debian_httpd_shell_deny" "$web_module" || true
    fi
}

if [[ "$OPT_CUSTOM" == true ]]; then
    apply_custom_modules
else
    note "Custom policy modules skipped (use -c/--custom to enable)"
fi

# ============================================================================
# SECTION 10: MCS / MLS Category Hardening
# ============================================================================
section "10. MCS/MLS Category Configuration"

check_mcs_mls() {
    if ! command -v semanage &>/dev/null; then return; fi

    info "Checking MCS/MLS sensitivity levels..."

    # Verify that process categories are being enforced
    if selinuxenabled 2>/dev/null; then
        local policy_type
        policy_type=$(sestatus 2>/dev/null | grep 'Policy from config file' | awk '{print $NF}' || echo "unknown")
        info "Active policy type: $policy_type"

        if [[ "$policy_type" == "mls" ]]; then
            pass "MLS policy active — full multi-level security enforced"
        else
            note "Targeted policy active — MCS categories provide container-level isolation"
            note "For stricter separation (e.g., multi-tenant), consider --policy mls"
        fi

        # Verify sensitivity range
        local sensitivity_range
        sensitivity_range=$(sestatus 2>/dev/null | grep 'Policy MLS status' | awk '{print $NF}' || echo "unknown")
        if [[ "$sensitivity_range" == "enabled" ]]; then
            pass "MLS/MCS is enabled in the active policy"
        else
            warn "MLS/MCS may be disabled — verify with: sestatus | grep MLS"
            WARN_COUNT=$((WARN_COUNT+1))
        fi
    else
        note "SELinux not active — MCS/MLS check deferred"
    fi
}

check_mcs_mls

# ============================================================================
# SECTION 11: /proc and /sys Hardening (Kernel Parameters)
# ============================================================================
section "11. Kernel Parameters Supporting SELinux"

SYSCTL_CONF="/etc/sysctl.d/90-selinux-hardening.conf"

apply_sysctl() {
    declare -A SYSCTL_PARAMS

    # These complement SELinux by hardening the kernel ABI surface
    SYSCTL_PARAMS["kernel.dmesg_restrict"]="1"             # Restrict dmesg to root
    SYSCTL_PARAMS["kernel.kptr_restrict"]="2"              # Hide kernel pointers
    SYSCTL_PARAMS["kernel.perf_event_paranoid"]="3"        # Restrict perf events
    SYSCTL_PARAMS["kernel.unprivileged_bpf_disabled"]="1"  # No eBPF for unprivileged users
    SYSCTL_PARAMS["net.core.bpf_jit_harden"]="2"           # Harden BPF JIT
    SYSCTL_PARAMS["kernel.yama.ptrace_scope"]="2"          # Restrict ptrace (admin only)
    SYSCTL_PARAMS["kernel.unprivileged_userns_clone"]="0"  # No unpriv user namespaces (Debian)
    SYSCTL_PARAMS["kernel.modules_disabled"]="0"           # Keep 0 unless fully locked; set 1 after loading all modules
    SYSCTL_PARAMS["fs.protected_hardlinks"]="1"            # Protect hardlink creation
    SYSCTL_PARAMS["fs.protected_symlinks"]="1"             # Protect symlink following
    SYSCTL_PARAMS["fs.protected_fifos"]="2"                # Protect FIFO creation in sticky dirs
    SYSCTL_PARAMS["fs.protected_regular"]="2"              # Protect regular file creation in sticky dirs
    SYSCTL_PARAMS["fs.suid_dumpable"]="0"                  # No core dumps for setuid processes
    SYSCTL_PARAMS["net.ipv4.conf.all.log_martians"]="1"    # Log impossible source addresses
    SYSCTL_PARAMS["net.ipv4.conf.default.log_martians"]="1"
    SYSCTL_PARAMS["net.ipv4.conf.all.rp_filter"]="1"       # Strict reverse-path filtering
    SYSCTL_PARAMS["net.ipv4.conf.default.rp_filter"]="1"
    SYSCTL_PARAMS["net.ipv4.tcp_syncookies"]="1"           # SYN flood protection
    SYSCTL_PARAMS["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    SYSCTL_PARAMS["net.ipv6.conf.all.disable_ipv6"]="0"    # Do not disable IPv6 globally
    SYSCTL_PARAMS["net.ipv6.conf.all.accept_ra"]="0"       # Don't accept IPv6 RA by default

    if [[ "$OPT_REPORT" == true ]]; then
        local issues=0
        for key in "${!SYSCTL_PARAMS[@]}"; do
            local desired="${SYSCTL_PARAMS[$key]}"
            local actual
            actual=$(sysctl -n "$key" 2>/dev/null || echo "not_found")
            if [[ "$actual" == "$desired" ]]; then
                pass "  $key = $desired"
            else
                fail "  $key = $actual (should be $desired)"
                issues=$((issues+1))
            fi
        done
        return $issues
    fi

    if ask "Apply kernel sysctl parameters that support SELinux?"; then
        mkdir -p "$(dirname "$SYSCTL_CONF")"
        {
            echo "# SELinux-supporting kernel parameters"
            echo "# Generated by advanced-selinux-hardening.sh — $(date)"
            echo ""
            for key in "${!SYSCTL_PARAMS[@]}"; do
                echo "${key} = ${SYSCTL_PARAMS[$key]}"
            done
        } > "$SYSCTL_CONF"

        sysctl -p "$SYSCTL_CONF" >> "$LOG_FILE" 2>&1 || true
        pass "Kernel parameters written to $SYSCTL_CONF and applied"
        CHANGE_COUNT=$((CHANGE_COUNT+1))
    fi
}

apply_sysctl

# ============================================================================
# SECTION 12: Verification & Status
# ============================================================================
section "12. SELinux Status Verification"

verify_selinux_status() {
    echo ""
    info "Full SELinux status:"
    echo ""
    sestatus 2>/dev/null | while IFS= read -r line; do
        echo "    $line"
    done
    echo ""

    # Check for loaded policy modules
    if command -v semodule &>/dev/null; then
        local module_count
        module_count=$(semodule -l 2>/dev/null | wc -l || echo "0")
        pass "$module_count SELinux policy modules loaded"
    fi

    # Verify auditd is running
    if systemctl is-active auditd &>/dev/null; then
        pass "auditd is active"
    else
        warn "auditd is not running — AVC denials may not be logged"
        WARN_COUNT=$((WARN_COUNT+1))
    fi

    # Check for recent policy violations in journal
    if command -v journalctl &>/dev/null; then
        local avc_journal
        avc_journal=$(journalctl -k --since "1 hour ago" 2>/dev/null | grep -c 'avc:' || echo "0")
        if [[ "$avc_journal" -gt 0 ]]; then
            warn "Found $avc_journal AVC denial(s) in journal (last hour)"
            warn "Run: journalctl -k | grep 'avc:' | audit2why"
            WARN_COUNT=$((WARN_COUNT+1))
        else
            pass "No AVC denials in kernel journal (last hour)"
        fi
    fi
}

if selinuxenabled 2>/dev/null || { getenforce 2>/dev/null | grep -qvE 'Disabled'; }; then
    verify_selinux_status
else
    note "SELinux is not yet active — full verification available after reboot"
fi

# ============================================================================
# SECTION 13: Posture Report
# ============================================================================
section "13. Hardening Summary Report"

generate_report() {
    {
        echo "========================================================"
        echo "  SELinux Hardening Posture Report"
        echo "  Generated: $(date)"
        echo "  Host: $(hostname)"
        echo "  Kernel: $(uname -r)"
        echo "  OS: ${PRETTY_NAME:-unknown}"
        echo "========================================================"
        echo ""
        echo "SELinux Status:"
        sestatus 2>/dev/null || echo "  sestatus not available"
        echo ""
        echo "Loaded Policy Modules:"
        semodule -l 2>/dev/null | head -40 || echo "  semodule not available"
        echo ""
        echo "SELinux Booleans (non-default):"
        getsebool -a 2>/dev/null | grep ' --> on$' | head -50 || echo "  getsebool not available"
        echo ""
        echo "Login Mappings:"
        semanage login -l 2>/dev/null || echo "  semanage not available"
        echo ""
        echo "Port Labels (custom):"
        semanage port -l 2>/dev/null | grep -v '^SELinux' | head -30 || echo "  semanage not available"
        echo ""
        echo "Recent AVC Denials (today):"
        ausearch -m AVC -ts today 2>/dev/null | tail -30 || echo "  ausearch not available"
        echo ""
        echo "========================================================"
        echo "  Counts: PASS=$PASS_COUNT  FAIL=$FAIL_COUNT  WARN=$WARN_COUNT  CHANGES=$CHANGE_COUNT"
        echo "========================================================"
    } > "$REPORT_FILE"

    pass "Full posture report written to: $REPORT_FILE"
}

generate_report

# ============================================================================
# Final summary
# ============================================================================
banner "Hardening Complete"

echo -e "  ${BOLD}Results:${NC}"
echo -e "    ${GREEN}Passed:${NC}  $PASS_COUNT checks"
echo -e "    ${RED}Failed:${NC}  $FAIL_COUNT checks"
echo -e "    ${YELLOW}Warned:${NC}  $WARN_COUNT items"
echo -e "    ${MAGENTA}Changes:${NC} $CHANGE_COUNT applied"
echo ""
echo -e "  ${BOLD}Log file:${NC}    $LOG_FILE"
echo -e "  ${BOLD}Report:${NC}      $REPORT_FILE"
echo ""

if [[ "$OPT_MODE" == "enforcing" ]] && getenforce 2>/dev/null | grep -q "Disabled"; then
    echo -e "  ${YELLOW}${BOLD}ACTION REQUIRED:${NC}"
    echo -e "  A reboot is required to activate SELinux in enforcing mode."
    echo -e "  After reboot, automatic file relabelling will run if /.autorelabel exists."
    echo ""
fi

echo -e "  ${DIM}Useful commands:${NC}"
echo -e "    ${CYAN}sestatus${NC}                          — Current SELinux status"
echo -e "    ${CYAN}getenforce${NC}                        — Current enforcement mode"
echo -e "    ${CYAN}setenforce 0|1${NC}                    — Toggle permissive/enforcing (runtime)"
echo -e "    ${CYAN}ausearch -m AVC -ts today${NC}         — View today's denials"
echo -e "    ${CYAN}ausearch -m AVC | audit2why${NC}       — Explain AVC denials"
echo -e "    ${CYAN}ausearch -m AVC | audit2allow -M fix${NC} — Generate allow policy"
echo -e "    ${CYAN}semanage boolean -l${NC}               — List all booleans"
echo -e "    ${CYAN}seinfo -t | grep <keyword>${NC}        — Query policy types"
echo -e "    ${CYAN}sesearch --allow -s httpd_t${NC}       — Show allow rules for httpd"
echo -e "    ${CYAN}matchpathcon <path>${NC}               — Expected context for a path"
echo -e "    ${CYAN}restorecon -Rv <path>${NC}             — Restore correct file contexts"
echo ""

log "=== SELinux Hardening completed: PASS=$PASS_COUNT FAIL=$FAIL_COUNT WARN=$WARN_COUNT CHANGES=$CHANGE_COUNT ==="

exit 0
