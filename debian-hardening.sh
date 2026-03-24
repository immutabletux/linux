#!/usr/bin/env bash
# =============================================================================
# Debian Linux Endpoint Hardening Script
# Based on: Mandiant - "Linux Endpoint Hardening to Protect Against Malware
#           and Destructive Attacks" (March 2022)
# Source:   https://services.google.com/fh/files/misc/linux-endpoint-hardening-wp-en.pdf
#
# Target:   Debian 11+ / Ubuntu 20.04+ (apt-based systems)
# Usage:    sudo bash debian-hardening.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colours & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

banner() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

info()    { echo -e "  ${GREEN}[INFO]${NC}  $1"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
err()     { echo -e "  ${RED}[ERR ]${NC}  $1"; }
skip()    { echo -e "  ${YELLOW}[SKIP]${NC}  $1"; }

# Prompt: returns 0 (yes) or 1 (no). Default = Y unless $2 is "n".
ask() {
    local prompt="$1"
    local default="${2:-y}"
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
        cp -n "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        info "Backed up $f"
    fi
}


log_action() {
    echo "[$(date '+%F %T')] $1" >> "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
banner "Debian Linux Endpoint Hardening"
echo ""
echo -e "  Based on the ${BOLD}Mandiant${NC} whitepaper:"
echo "  \"Linux Endpoint Hardening to Protect Against Malware"
echo "   and Destructive Attacks\" (2022)"
echo ""

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
fi

LOG_FILE="/var/log/debian-hardening-$(date +%Y%m%d%H%M%S).log"

if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script is designed for Debian/Ubuntu. Proceed with caution."
    if ! ask "Continue anyway?" "n"; then
        exit 0
    fi
fi

info "Log file: $LOG_FILE"
log_action "=== Hardening session started ==="
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 1. SYSCTL KERNEL HARDENING
# ═══════════════════════════════════════════════════════════════════════════
banner "1. Sysctl Kernel Hardening Parameters"
echo "  Applies recommended kernel parameters to /etc/sysctl.d/99-hardening.conf"
echo "  covering IP forwarding, SYN cookies, ASLR, martian logging, etc."
echo ""

if ask "Apply sysctl hardening parameters?"; then
    SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    backup_file "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'SYSCTL'
# =============================================================================
# Mandiant-recommended sysctl hardening parameters
# =============================================================================

# --- IPv4 Network ---
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Do not accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Do not accept secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log suspicious (martian) packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable TCP SYN cookies (SYN-flood protection)
net.ipv4.tcp_syncookies = 1

# SYN-flood protection retries
net.ipv4.tcp_synack_retries = 2

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- IPv6 ---
# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Kernel ---
# Disable SysRq key
kernel.sysrq = 0

# Append PID to core dumps
kernel.core_uses_pid = 1

# Full address space layout randomisation (ASLR)
kernel.randomize_va_space = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict kernel pointer leaks
kernel.kptr_restrict = 2

# Restrict BPF JIT
net.core.bpf_jit_harden = 2

# Restrict ptrace scope
kernel.yama.ptrace_scope = 2
SYSCTL

    sysctl --system > /dev/null 2>&1
    info "Sysctl parameters applied."
    log_action "Applied sysctl hardening to $SYSCTL_FILE"
else
    skip "Sysctl hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. SSH HARDENING
# ═══════════════════════════════════════════════════════════════════════════
banner "2. SSH Attack Surface Reduction"
echo "  Hardens /etc/ssh/sshd_config: disable root login, empty passwords,"
echo "  X11 forwarding, TCP forwarding; limit auth tries, set timeouts."
echo ""

if ask "Apply SSH hardening?"; then
    SSHD_CFG="/etc/ssh/sshd_config"
    SSHD_DROP="/etc/ssh/sshd_config.d/99-hardening.conf"

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        TARGET="$SSHD_DROP"
        backup_file "$TARGET"
    else
        TARGET="$SSHD_CFG"
        backup_file "$TARGET"
    fi

    cat > "$TARGET" << 'SSH'
# =============================================================================
# Mandiant-recommended SSH hardening
# =============================================================================
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 1
X11Forwarding no
AllowTcpForwarding no
LogLevel VERBOSE
IgnoreRhosts yes
HostbasedAuthentication no
LoginGraceTime 60
MaxStartups 10:30:60
SSH

    # Validate config before restarting
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        info "SSH hardening applied and service reloaded."
    else
        err "sshd config test failed — review $TARGET manually."
    fi
    log_action "Applied SSH hardening to $TARGET"
else
    skip "SSH hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. CRON JOB PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════
banner "3. Cron Job Permission Restrictions"
echo "  Restricts ownership & permissions on /etc/crontab and /etc/cron.d"
echo "  so only root can read/write cron configurations."
echo ""

if ask "Harden cron permissions?"; then
    for f in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -e "$f" ]]; then
            chown root:root "$f"
            chmod og-rwx "$f"
            info "Secured $f  (root:root, og-rwx)"
        fi
    done
    log_action "Hardened cron file/directory permissions"
else
    skip "Cron hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. SUID EXECUTABLE AUDIT
# ═══════════════════════════════════════════════════════════════════════════
banner "4. SUID Executable Audit"
echo "  Lists all binaries with the SUID bit set for manual review."
echo "  SUID binaries can be exploited for privilege escalation."
echo ""

if ask "Scan for SUID executables?"; then
    info "Scanning — this may take a moment..."
    SUID_LIST="/tmp/suid-audit-$(date +%Y%m%d%H%M%S).txt"
    find / -perm -u=s -type f 2>/dev/null | sort > "$SUID_LIST"
    COUNT=$(wc -l < "$SUID_LIST")
    info "Found ${COUNT} SUID binaries. List saved to ${SUID_LIST}"
    echo ""
    head -30 "$SUID_LIST"
    if (( COUNT > 30 )); then
        echo "  ... (truncated — see $SUID_LIST for full list)"
    fi
    log_action "SUID audit completed: $COUNT binaries found → $SUID_LIST"
else
    skip "SUID audit skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. MOUNT POINT HARDENING
# ═══════════════════════════════════════════════════════════════════════════
banner "5. Mounted Partition Permission Options"
echo "  Adds nosuid,noexec,nodev to /tmp, /var/tmp, /dev/shm"
echo "  and nodev to /home (if they exist as separate mount points)."
echo ""

if ask "Harden mount point options in /etc/fstab?"; then
    backup_file /etc/fstab

    harden_mount() {
        local mnt="$1"
        local opts="$2"
        if mount | grep -q " on ${mnt} "; then
            # Check if options already present
            current=$(mount | grep " on ${mnt} " | awk '{print $6}')
            info "${mnt} currently mounted with options: ${current}"
            if grep -q "^[^#].*[[:space:]]${mnt}[[:space:]]" /etc/fstab; then
                # Add options that aren't already there
                for opt in $(echo "$opts" | tr ',' ' '); do
                    if ! grep "^[^#].*[[:space:]]${mnt}[[:space:]]" /etc/fstab | grep -q "$opt"; then
                        # Append opt to the fstab options field regardless of existing options
                        perl -i -pe "s|(^\S+\s+\Q${mnt}\E\s+\S+\s+)(\S+)|\$1\$2,\Q${opt}\E| unless /^#/" /etc/fstab
                        info "Added ${opt} to ${mnt} in /etc/fstab"
                    fi
                done
            else
                warn "${mnt} is mounted but not in /etc/fstab — skipping."
            fi
        else
            warn "${mnt} is not a separate mount point — skipping."
        fi
    }

    harden_mount "/tmp"     "nosuid,noexec,nodev"
    harden_mount "/var/tmp" "nosuid,noexec,nodev"
    harden_mount "/dev/shm" "nosuid,noexec,nodev"
    harden_mount "/home"    "nodev"

    # Apply new options to the running system where possible
    for mnt_live in /tmp /var/tmp /dev/shm /home; do
        if mount | grep -q " on ${mnt_live} "; then
            mount -o remount "$mnt_live" 2>/dev/null \
                && info "Remounted ${mnt_live} with updated options." \
                || warn "Could not remount ${mnt_live} automatically -- reboot to apply fstab changes."
        fi
    done
    log_action "Updated /etc/fstab mount point options"
else
    skip "Mount point hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 6. APPARMOR (Debian/Ubuntu MAC)
# ═══════════════════════════════════════════════════════════════════════════
banner "6. AppArmor — Mandatory Access Control"
echo "  Ensures AppArmor is installed, enabled, and all profiles are enforced."
echo ""

if ask "Install/enforce AppArmor?"; then
    if ! dpkg -s apparmor &>/dev/null; then
        info "Installing AppArmor..."
        apt-get update -qq && apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra 2>/dev/null
    fi

    systemctl enable apparmor 2>/dev/null || true
    systemctl start  apparmor 2>/dev/null || true

    # Enforce all currently loaded profiles
    COMPLAIN_PROFILES=$(aa-status 2>/dev/null | awk '/profiles are in complain mode/{found=1;next} found && /^[[:space:]]/{sub(/^[[:space:]]*/,""); print; next} found && !/^[[:space:]]/{found=0}' || true)
    if [[ -n "$COMPLAIN_PROFILES" ]]; then
        info "Setting complain-mode profiles to enforce mode..."
        for profile in $COMPLAIN_PROFILES; do
            aa-enforce "$profile" 2>/dev/null && info "Enforced: $profile" || true
        done
    fi
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    info "AppArmor status:"
    aa-status 2>/dev/null | head -10
    log_action "AppArmor installed/enforced"
else
    skip "AppArmor skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. FIREWALL — nftables (Debian 10+)
# ═══════════════════════════════════════════════════════════════════════════
banner "7. Firewall — nftables / ufw"
echo "  Debian 10+ recommends nftables. This section ensures a firewall"
echo "  is active with a default-deny inbound policy."
echo ""

if ask "Configure firewall (ufw)?"; then
    if command -v ufw &>/dev/null; then
        info "Using ufw (Uncomplicated Firewall)..."
        ufw default deny incoming
        ufw default allow outgoing

        if ask "  Allow inbound SSH (port 22)?" "y"; then
            ufw allow ssh
            info "SSH allowed inbound."
        fi

        ufw --force enable
        ufw status verbose
        log_action "Enabled ufw with default-deny inbound"
    elif command -v nft &>/dev/null; then
        info "ufw not found — nftables is available."
        warn "Manual nftables configuration is recommended."
        warn "Consider: apt install ufw && ufw enable"
        log_action "nftables present but no auto-config applied"
    else
        warn "No firewall tool found. Installing ufw..."
        apt-get install -y -qq ufw
        ufw default deny incoming
        ufw default allow outgoing
        if ask "  Allow inbound SSH (port 22)?" "y"; then
            ufw allow ssh
        fi
        ufw --force enable
        ufw status verbose
        log_action "Installed and enabled ufw"
    fi
else
    skip "Firewall configuration skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. DISABLE UNNECESSARY SERVICES
# ═══════════════════════════════════════════════════════════════════════════
banner "8. Disable Unnecessary Services"
echo "  Reviews commonly abused services and offers to disable them."
echo ""

SERVICES_TO_CHECK=(avahi-daemon rpcbind rsync smbd nmbd telnet.socket vsftpd)

for svc in "${SERVICES_TO_CHECK[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -q 'enabled'; then
        warn "Service '${svc}' is currently enabled."
        if ask "  Disable ${svc}?"; then
            systemctl --now disable "$svc" 2>/dev/null
            info "Disabled ${svc}"
            log_action "Disabled service: $svc"
        else
            skip "Kept ${svc} enabled."
        fi
    fi
done

info "Service review complete."

# ═══════════════════════════════════════════════════════════════════════════
# 9. ROOT ACCOUNT & PRIVILEGED ACCOUNT HARDENING
# ═══════════════════════════════════════════════════════════════════════════
banner "9. Root & Privileged Account Hardening"
echo "  Checks for non-root accounts with UID 0 and reviews sudoers."
echo ""

if ask "Audit privileged accounts?"; then
    info "Accounts with UID 0:"
    UID0=$(awk -F: '($3 == 0) { print "    " $1 }' /etc/passwd)
    echo "$UID0"
    NON_ROOT_UID0=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
    if [[ -n "$NON_ROOT_UID0" ]]; then
        err "WARNING: Non-root account(s) with UID 0: $NON_ROOT_UID0"
        warn "Investigate and remove UID 0 from these accounts."
    else
        info "Only root has UID 0 — OK."
    fi

    echo ""
    info "Members of sudo/admin groups:"
    for grp in sudo wheel adm; do
        MEMBERS=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [[ -n "$MEMBERS" ]]; then
            echo "    ${grp}: ${MEMBERS}"
        fi
    done

    echo ""
    info "Accounts with shells (potential interactive logins):"
    awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ { printf "    %-20s %s\n", $1, $7 }' /etc/passwd

    log_action "Privileged account audit completed"
else
    skip "Privileged account audit skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 10. PASSWORD POLICY ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════
banner "10. Strong Password Enforcement"
echo "  Installs libpam-pwquality and configures minimum password complexity."
echo ""

if ask "Enforce strong password policy?"; then
    apt-get install -y -qq libpam-pwquality 2>/dev/null || true

    PWQUALITY_CONF="/etc/security/pwquality.conf"
    backup_file "$PWQUALITY_CONF"

    cat > "$PWQUALITY_CONF" << 'PWQUAL'
# =============================================================================
# Password quality requirements (Mandiant-recommended baseline)
# =============================================================================
# Minimum password length
minlen = 15
# Require at least 1 uppercase letter
ucredit = -1
# Require at least 1 lowercase letter
lcredit = -1
# Require at least 1 digit
dcredit = -1
# Require at least 1 special character
ocredit = -1
# Max consecutive identical characters
maxrepeat = 3
# Max sequential characters (e.g. abc, 123)
maxsequence = 3
# Reject passwords containing the username
usercheck = 1
# Number of retries
retry = 3
PWQUAL

    info "Password quality policy written to $PWQUALITY_CONF"
    log_action "Configured password quality policy"
else
    skip "Password policy skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 11. ACCOUNT LOCKOUT FOR FAILED AUTH
# ═══════════════════════════════════════════════════════════════════════════
banner "11. Account Lockout on Failed Authentication"
echo "  Configures pam_faillock to lock accounts after 5 failed attempts"
echo "  for 15 minutes."
echo ""

if ask "Configure account lockout policy?"; then
    FAILLOCK_CONF="/etc/security/faillock.conf"
    if [[ -f "$FAILLOCK_CONF" ]]; then
        backup_file "$FAILLOCK_CONF"
        cat > "$FAILLOCK_CONF" << 'FAILLOCK'
# Lock account after 5 failed attempts
deny = 5
# Unlock after 900 seconds (15 min)
unlock_time = 900
# Don't lock root (prevent DoS against root)
# even_deny_root is omitted -- root is exempt from lockout by default
# Audit failed attempts
audit
FAILLOCK
        info "faillock.conf configured."
    else
        warn "/etc/security/faillock.conf not found."
        info "Attempting pam_faillock configuration in PAM files..."
        # For older systems without faillock.conf
        for pam_file in /etc/pam.d/common-auth /etc/pam.d/system-auth; do
            if [[ -f "$pam_file" ]] && ! grep -q pam_faillock "$pam_file"; then
                backup_file "$pam_file"
                info "Consider manually adding pam_faillock to $pam_file"
            fi
        done
    fi
    log_action "Configured account lockout policy"
else
    skip "Account lockout skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 12. SHA512 PASSWORD HASHING
# ═══════════════════════════════════════════════════════════════════════════
banner "12. SHA512 Password Hashing"
echo "  Ensures passwords are stored using the sha512 algorithm."
echo ""

if ask "Enforce SHA512 password hashing?"; then
    PAM_PASS="/etc/pam.d/common-password"
    if [[ -f "$PAM_PASS" ]]; then
        if grep -q "pam_unix.so" "$PAM_PASS"; then
            if ! grep "pam_unix.so" "$PAM_PASS" | grep -q "sha512"; then
                backup_file "$PAM_PASS"
                sed -i 's/\(pam_unix.so.*\)/\1 sha512/' "$PAM_PASS"
                info "Added sha512 to pam_unix.so in $PAM_PASS"
            else
                info "sha512 already configured in $PAM_PASS"
            fi
        fi
    fi

    # Also set in login.defs
    if [[ -f /etc/login.defs ]]; then
        if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
            sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        else
            echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
        fi
        info "ENCRYPT_METHOD set to SHA512 in /etc/login.defs"
    fi
    log_action "Enforced SHA512 password hashing"
else
    skip "SHA512 enforcement skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 13. DISABLE INTERACTIVE LOGIN FOR SERVICE ACCOUNTS
# ═══════════════════════════════════════════════════════════════════════════
banner "13. Interactive Logon Restrictions"
echo "  Sets /sbin/nologin for system/service accounts that should not"
echo "  have interactive shell access."
echo ""

if ask "Audit and restrict service account shells?"; then
    info "System accounts (UID < 1000) with interactive shells:"
    FOUND=0
    while IFS=: read -r user _pass uid _gid _gecos _home shell; do
        if (( uid > 0 && uid < 1000 )) && [[ "$shell" != */nologin && "$shell" != */false && "$shell" != "" ]]; then
            echo "    ${user} (UID ${uid}) → ${shell}"
            FOUND=1
        fi
    done < /etc/passwd

    if (( FOUND )); then
        echo ""
        if ask "  Set these accounts to /sbin/nologin?" "n"; then
            while IFS=: read -r user _pass uid _gid _gecos _home shell; do
                if (( uid > 0 && uid < 1000 )) && [[ "$shell" != */nologin && "$shell" != */false && "$shell" != "" ]]; then
                    usermod -s /sbin/nologin "$user"
                    info "Set $user → /sbin/nologin"
                fi
            done < /etc/passwd
            log_action "Restricted service account shells"
        fi
    else
        info "No service accounts with interactive shells found — OK."
    fi
else
    skip "Interactive logon restriction skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 14. AUDITD — SYSTEM AUDITING
# ═══════════════════════════════════════════════════════════════════════════
banner "14. AuditD — System Auditing"
echo "  Installs and configures auditd for comprehensive event logging."
echo ""

if ask "Install and configure auditd?"; then
    apt-get install -y -qq auditd audispd-plugins 2>/dev/null || apt-get install -y -qq auditd 2>/dev/null || true

    AUDITD_CONF="/etc/audit/auditd.conf"
    if [[ -f "$AUDITD_CONF" ]]; then
        backup_file "$AUDITD_CONF"
        # Tune key performance settings
        sed -i 's/^max_log_file .*/max_log_file = 50/'            "$AUDITD_CONF" 2>/dev/null || true
        sed -i 's/^num_logs .*/num_logs = 99/'                    "$AUDITD_CONF" 2>/dev/null || true
        sed -i 's/^max_log_file_action .*/max_log_file_action = ROTATE/' "$AUDITD_CONF" 2>/dev/null || true
        sed -i 's/^space_left_action .*/space_left_action = EMAIL/'      "$AUDITD_CONF" 2>/dev/null || true
        info "Tuned $AUDITD_CONF"
    fi

    # Add hardening audit rules
    AUDIT_RULES="/etc/audit/rules.d/99-hardening.rules"
    cat > "$AUDIT_RULES" << 'AUDITRULES'
# =============================================================================
# Mandiant-recommended audit rules
# =============================================================================

# Self-auditing — protect audit config & logs
-w /etc/audit/ -p wa -k audit_config
-w /var/log/audit/ -p wa -k audit_logs

# Identity & authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Login & PAM
-w /etc/login.defs -p wa -k login
-w /etc/pam.d/ -p wa -k pam

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k priv_esc

# Unauthorised file access attempts
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access_denied

# File deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_delete

# Mount operations
-a always,exit -F arch=b64 -S mount -k mount

# Make the audit configuration immutable (requires reboot to change)
-e 2
AUDITRULES

    # Reload rules
    augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES" 2>/dev/null || true
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    info "AuditD rules loaded from $AUDIT_RULES"
    log_action "Installed and configured auditd with hardening rules"
else
    skip "AuditD configuration skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 15. BASH HISTORY TIMESTAMPS & SIZE
# ═══════════════════════════════════════════════════════════════════════════
banner "15. Shell History Timestamps & Unlimited Size"
echo "  Enables timestamps in .bash_history and removes the default"
echo "  1000-line limit for all users."
echo ""

if ask "Configure shell history enhancements?"; then
    PROFILE_D="/etc/profile.d/history-hardening.sh"
    cat > "$PROFILE_D" << 'HISTCFG'
# Mandiant-recommended shell history hardening
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=-1
export HISTFILESIZE=-1
export HISTCONTROL=ignoredups
HISTCFG
    chmod 644 "$PROFILE_D"
    info "Shell history config written to $PROFILE_D (applies to new sessions)."
    log_action "Configured shell history timestamps & unlimited size"
else
    skip "Shell history configuration skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 16. FILE INTEGRITY MONITORING (AIDE)
# ═══════════════════════════════════════════════════════════════════════════
banner "16. File Integrity Monitoring (AIDE)"
echo "  Installs AIDE and initialises the file integrity database."
echo "  Note: Initial database generation can take several minutes."
echo ""

if ask "Install and initialise AIDE?"; then
    apt-get install -y -qq aide 2>/dev/null || true

    if command -v aideinit &>/dev/null; then
        info "Initialising AIDE database (this may take a while)..."
        aideinit 2>/dev/null || aide --init 2>/dev/null || true
        # Move new DB into place -- Debian gzips its AIDE databases
        if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            info "AIDE database (gzip) activated as aide.db.gz"
        elif [[ -f /var/lib/aide/aide.db.new ]]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            info "AIDE database activated as aide.db"
        else
            warn "AIDE init ran but no database file found -- check /var/lib/aide/"
        fi
        info "AIDE database initialised."
        info "Run 'aide --check' to verify file integrity at any time."
    elif command -v aide &>/dev/null; then
        info "Initialising AIDE database..."
        aide --init 2>/dev/null || true
        info "AIDE initialised. Check /etc/aide/aide.conf for paths monitored."
    fi

    # Set up daily cron check
    if [[ -d /etc/cron.daily ]]; then
        cat > /etc/cron.daily/aide-check << 'AIDECRON'
#!/bin/bash
/usr/bin/aide --check > /var/log/aide-check.log 2>&1
AIDECRON
        chmod 700 /etc/cron.daily/aide-check
        info "Daily AIDE check cron job created."
    fi
    log_action "Installed and initialised AIDE"
else
    skip "AIDE installation skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 17. NFS HARDENING (if applicable)
# ═══════════════════════════════════════════════════════════════════════════
if systemctl is-active nfs-kernel-server &>/dev/null || [[ -f /etc/exports ]]; then
    banner "17. NFS Server Hardening"
    echo "  Reviews /etc/exports for world-writable or overly permissive shares."
    echo ""

    if ask "Audit NFS exports?"; then
        if [[ -f /etc/exports ]] && [[ -s /etc/exports ]]; then
            info "Current NFS exports:"
            cat /etc/exports
            echo ""
            warn "Review exports for: rw without client restrictions, no_root_squash, etc."
            info "Use 'showmount -e' to verify exported directories."
        else
            info "/etc/exports is empty or not found — no NFS shares configured."
        fi
        log_action "NFS export audit completed"
    else
        skip "NFS audit skipped."
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 18. KERNEL MODULE LOADING RESTRICTION
# ═══════════════════════════════════════════════════════════════════════════
banner "18. Kernel Module Loading Restriction"
echo -e "  ${RED}CAUTION:${NC} Disabling module loading prevents ANY new modules from"
echo "  loading until reboot. This can break drivers and services."
echo "  Only apply on hardened, fully-configured systems."
echo ""

if ask "Disable kernel module loading (kernel.modules_disabled=1)?" "n"; then
    echo "  This will take effect immediately. A reboot is needed to re-enable."
    if ask "  Are you sure? This is irreversible until reboot." "n"; then
        sysctl -w kernel.modules_disabled=1
        info "Kernel module loading is now DISABLED."
        log_action "Set kernel.modules_disabled=1"
    else
        skip "Kernel module lockdown cancelled."
    fi
else
    skip "Kernel module restriction skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
banner "Hardening Complete"
echo ""
info "All actions have been logged to: ${LOG_FILE}"
echo ""
echo -e "  ${BOLD}Recommended next steps:${NC}"
echo "    1. Review the SUID audit file (if generated)."
echo "    2. Reboot to apply all mount & kernel changes."
echo "    3. Test SSH access from another session before disconnecting."
echo "    4. Forward auditd logs to your SIEM / log aggregator."
echo "    5. Schedule periodic AIDE checks (already in cron.daily if enabled)."
echo "    6. Review /etc/fstab changes with 'mount -a' before reboot."
echo ""
log_action "=== Hardening session completed ==="
echo -e "${GREEN}Done.${NC}"
