#!/usr/bin/env bash
# =============================================================================
# Debian Linux Hardening Script
# Based on: madaidan's Linux Hardening Guide
# Source:   https://madaidans-insecurities.github.io/guides/linux-hardening.html
#
# Target:   Debian 11+ / Ubuntu 20.04+ (apt-based systems)
# Usage:    sudo bash madaidans-hardening.sh
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
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

info()  { echo -e "  ${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
err()   { echo -e "  ${RED}[ERR ]${NC}  $1"; }
skip()  { echo -e "  ${YELLOW}[SKIP]${NC}  $1"; }

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
banner "madaidan's Linux Hardening — Debian/Ubuntu"
echo ""
echo -e "  Based on: ${BOLD}madaidan's Linux Hardening Guide${NC}"
echo "  https://madaidans-insecurities.github.io/guides/linux-hardening.html"
echo ""

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
fi

LOG_FILE="/var/log/madaidans-hardening-$(date +%Y%m%d%H%M%S).log"

if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script is designed for Debian/Ubuntu. Proceed with caution."
    if ! ask "Continue anyway?" "n"; then exit 0; fi
fi

info "Log file: $LOG_FILE"
log_action "=== Hardening session started ==="
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 1. SYSCTL — KERNEL SELF-PROTECTION
# ═══════════════════════════════════════════════════════════════════════════
banner "1. Sysctl — Kernel Self-Protection Parameters"
echo "  Writes /etc/sysctl.d/99-madaidans-hardening.conf covering:"
echo "  kernel pointer leaks, dmesg, BPF JIT hardening, kexec, perf, ptrace,"
echo "  ASLR, core dumps, network anti-spoofing, TCP protections, and more."
echo ""

if ask "Apply kernel self-protection sysctl settings?"; then
    SYSCTL_FILE="/etc/sysctl.d/99-madaidans-hardening.conf"
    backup_file "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'SYSCTL'
# =============================================================================
# madaidan's Linux Hardening Guide — sysctl parameters
# https://madaidans-insecurities.github.io/guides/linux-hardening.html
# =============================================================================

# ── Kernel self-protection ──────────────────────────────────────────────────

# Hide kernel symbol addresses from /proc/kallsyms even from root
kernel.kptr_restrict = 2

# Restrict dmesg to CAP_SYSLOG
kernel.dmesg_restrict = 1

# Silence kernel messages to console
kernel.printk = 3 3 3 3

# Disable unprivileged use of eBPF (major attack surface)
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT compiler against JIT spraying
net.core.bpf_jit_harden = 2

# Disable auto-loading of line disciplines (tty ldisc attacks)
dev.tty.ldisc_autoload = 0

# Disable unprivileged userfaultfd (kernel exploit primitive)
vm.unprivileged_userfaultfd = 0

# Disable kexec (prevents replacing the running kernel)
kernel.kexec_load_disabled = 1

# Restrict SysRq to SAK only (Alt+SysRq+k kills all processes on tty)
kernel.sysrq = 4

# Disable unprivileged user namespaces (large attack surface)
# Note: some applications (browsers, containers) require this
kernel.unprivileged_userns_clone = 0

# Restrict perf_event_open to CAP_PERFMON / CAP_SYS_ADMIN
kernel.perf_event_paranoid = 3

# Full ASLR
kernel.randomize_va_space = 2

# Disable core dumps for setuid processes
fs.suid_dumpable = 0

# Disable core dumps system-wide (via sysctl)
kernel.core_pattern = |/bin/false

# ── Network hardening ───────────────────────────────────────────────────────

# TCP SYN cookie protection
net.ipv4.tcp_syncookies = 1

# Protect against TIME-WAIT assassination (RFC 1337)
net.ipv4.tcp_rfc1337 = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Do not accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore all ICMP echo requests (ping)
net.ipv4.icmp_echo_ignore_all = 1

# Do not accept source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Do not accept IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable TCP SACK (historically exploited)
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Disable TCP timestamps (fingerprinting & uptime leakage)
net.ipv4.tcp_timestamps = 0

# ── User-space protections ──────────────────────────────────────────────────

# Restrict ptrace to CAP_SYS_PTRACE only (no parent->child by default)
kernel.yama.ptrace_scope = 2

# Increase ASLR entropy
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# Protect symlinks in world-writable sticky dirs
fs.protected_symlinks = 1

# Protect hardlinks to files you don't own
fs.protected_hardlinks = 1

# Restrict FIFO creation in world-writable sticky dirs
fs.protected_fifos = 2

# Restrict regular file creation in world-writable sticky dirs
fs.protected_regular = 2

# Minimise disk swap usage
vm.swappiness = 1
SYSCTL

    sysctl --system > /dev/null 2>&1
    info "Sysctl parameters applied from $SYSCTL_FILE"
    log_action "Applied sysctl hardening to $SYSCTL_FILE"
else
    skip "Sysctl hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. BOOT PARAMETERS (GRUB)
# ═══════════════════════════════════════════════════════════════════════════
banner "2. Kernel Boot Parameters (GRUB)"
echo "  Adds security-hardening parameters to GRUB_CMDLINE_LINUX_DEFAULT."
echo "  Covers: slab_nomerge, PTI, init_on_alloc/free, vsyscall=none,"
echo "  debugfs=off, oops=panic, CPU mitigations, and more."
echo ""
warn "Review each parameter for your hardware before applying."
echo ""

if ask "Configure hardened boot parameters in /etc/default/grub?"; then
    GRUB_FILE="/etc/default/grub"
    if [[ ! -f "$GRUB_FILE" ]]; then
        warn "$GRUB_FILE not found — GRUB may not be in use."
        skip "GRUB boot parameter hardening skipped."
    else
        backup_file "$GRUB_FILE"

        PARAMS=(
            "slab_nomerge"
            "init_on_alloc=1"
            "init_on_free=1"
            "page_alloc.shuffle=1"
            "pti=on"
            "vsyscall=none"
            "debugfs=off"
            "oops=panic"
            "quiet"
            "loglevel=0"
            "random.trust_cpu=off"
        )

        echo ""
        info "The following base parameters will be added:"
        for p in "${PARAMS[@]}"; do echo "    $p"; done

        echo ""
        warn "CPU mitigations — apply if your CPU is vulnerable (check /sys/devices/system/cpu/vulnerabilities/)."
        MITIGATIONS=()
        if ask "  Add Spectre v2 mitigation (spectre_v2=on)?" "n"; then
            MITIGATIONS+=("spectre_v2=on")
        fi
        if ask "  Add Speculative Store Bypass mitigation (spec_store_bypass_disable=on)?" "n"; then
            MITIGATIONS+=("spec_store_bypass_disable=on")
        fi
        if ask "  Disable TSX (tsx=off tsx_async_abort=full,nosmt) — Intel only?" "n"; then
            MITIGATIONS+=("tsx=off" "tsx_async_abort=full,nosmt")
        fi
        if ask "  Add MDS mitigation (mds=full,nosmt) — Intel only?" "n"; then
            MITIGATIONS+=("mds=full,nosmt")
        fi
        if ask "  Add L1TF mitigation (l1tf=full,force) — Intel only?" "n"; then
            MITIGATIONS+=("l1tf=full,force")
        fi
        if ask "  Disable SMT/HyperThreading (nosmt=force)?" "n"; then
            MITIGATIONS+=("nosmt=force")
        fi

        echo ""
        if ask "  Add IOMMU parameters (intel_iommu=on amd_iommu=on efi=disable_early_pci_dma)?"; then
            PARAMS+=("intel_iommu=on" "amd_iommu=on" "efi=disable_early_pci_dma")
        fi
        if ask "  Disable USB at boot (nousb)?" "n"; then
            PARAMS+=("nousb")
        fi
        if ask "  Disable IPv6 kernel-wide (ipv6.disable=1)?" "n"; then
            PARAMS+=("ipv6.disable=1")
        fi

        ALL_PARAMS=("${PARAMS[@]}" "${MITIGATIONS[@]}")

        # Read existing GRUB_CMDLINE_LINUX_DEFAULT
        EXISTING=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/\1/')

        # Merge: append params not already present
        MERGED="$EXISTING"
        for p in "${ALL_PARAMS[@]}"; do
            KEY="${p%%=*}"
            if ! echo "$MERGED" | grep -qw "$KEY"; then
                MERGED="$MERGED $p"
            fi
        done
        MERGED=$(echo "$MERGED" | sed 's/^ *//')

        sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$MERGED\"|" "$GRUB_FILE"
        info "Updated GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_FILE"

        if command -v update-grub &>/dev/null; then
            update-grub 2>/dev/null
            info "GRUB configuration regenerated."
        else
            warn "Run 'grub-mkconfig -o /boot/grub/grub.cfg' manually to apply."
        fi
        log_action "Applied boot hardening parameters to $GRUB_FILE"
    fi
else
    skip "Boot parameter hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. /proc HARDENING (hidepid)
# ═══════════════════════════════════════════════════════════════════════════
banner "3. /proc Filesystem Hardening (hidepid)"
echo "  Mounts /proc with hidepid=2 so users can only see their own processes."
echo "  Also configures systemd-logind compatibility."
echo ""

if ask "Apply /proc hidepid=2 hardening?"; then
    backup_file /etc/fstab

    if grep -q '^proc ' /etc/fstab; then
        # Update existing proc entry
        sed -i 's|^proc\s.*|proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0|' /etc/fstab
        info "Updated existing /proc entry in /etc/fstab"
    else
        echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab
        info "Added /proc hardening entry to /etc/fstab"
    fi

    # Ensure 'proc' group exists
    if ! getent group proc > /dev/null 2>&1; then
        groupadd -r proc
        info "Created 'proc' group"
    fi

    # systemd-logind drop-in for hidepid compatibility
    if systemctl is-active systemd-logind &>/dev/null; then
        LOGIND_DROP="/etc/systemd/system/systemd-logind.service.d"
        mkdir -p "$LOGIND_DROP"
        cat > "$LOGIND_DROP/hidepid.conf" << 'LOGIND'
[Service]
SupplementaryGroups=proc
LOGIND
        systemctl daemon-reload
        info "Created systemd-logind hidepid drop-in."
    fi

    # Apply immediately
    mount -o remount,nosuid,nodev,noexec,hidepid=2,gid=proc /proc 2>/dev/null \
        && info "/proc remounted with hidepid=2" \
        || warn "Could not remount /proc now — will apply on next boot."

    log_action "Applied /proc hidepid=2 hardening"
else
    skip "/proc hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. KERNEL MODULE BLACKLISTING
# ═══════════════════════════════════════════════════════════════════════════
banner "4. Kernel Module Blacklisting"
echo "  Blacklists uncommon/dangerous kernel modules to reduce attack surface."
echo "  Covers: uncommon network protocols, rare filesystems, and peripherals."
echo ""

MODULES_CHANGED=0

if ask "Blacklist uncommon network protocol modules?"; then
    MODULES_CHANGED=1
    cat > /etc/modprobe.d/madaidans-net-blacklist.conf << 'NETMOD'
# madaidan's hardening — uncommon network protocol modules
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
NETMOD
    info "Network protocol blacklist written to /etc/modprobe.d/madaidans-net-blacklist.conf"
    log_action "Blacklisted uncommon network protocol modules"
else
    skip "Network protocol module blacklisting skipped."
fi

if ask "Blacklist uncommon filesystem modules?"; then
    MODULES_CHANGED=1
    cat > /etc/modprobe.d/madaidans-fs-blacklist.conf << 'FSMOD'
# madaidan's hardening — uncommon filesystem modules
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
# Network filesystems (use /bin/true to silently succeed without loading)
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true
FSMOD
    info "Filesystem blacklist written to /etc/modprobe.d/madaidans-fs-blacklist.conf"
    log_action "Blacklisted uncommon filesystem modules"
else
    skip "Filesystem module blacklisting skipped."
fi

if ask "Blacklist peripheral/device modules (Bluetooth, webcam, FireWire, Thunderbolt)?"; then
    MODULES_CHANGED=1
    cat > /etc/modprobe.d/madaidans-dev-blacklist.conf << 'DEVMOD'
# madaidan's hardening — peripheral device modules
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
install vivid /bin/false
DEVMOD
    info "Device blacklist written to /etc/modprobe.d/madaidans-dev-blacklist.conf"
    log_action "Blacklisted peripheral device modules"
    warn "Bluetooth and webcam are now blacklisted. Reboot or 'rmmod' to unload."
else
    skip "Peripheral device module blacklisting skipped."
fi

# Update initramfs so blacklists take effect in early boot
if [[ $MODULES_CHANGED -eq 1 ]] && command -v update-initramfs &>/dev/null; then
    if ask "Regenerate initramfs to apply module blacklists at boot?"; then
        update-initramfs -u -k all 2>/dev/null
        info "initramfs regenerated."
        log_action "Regenerated initramfs after module blacklisting"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. ROOT ACCOUNT HARDENING
# ═══════════════════════════════════════════════════════════════════════════
banner "5. Root Account Hardening"
echo "  Restricts root access: empties securetty, locks root password,"
echo "  restricts su, denies SSH root login, and raises password hash rounds."
echo ""

if ask "Apply root account hardening?"; then

    # Empty /etc/securetty to prevent direct root console login
    if [[ -f /etc/securetty ]]; then
        backup_file /etc/securetty
        > /etc/securetty
        info "Cleared /etc/securetty — direct root terminal login now denied."
        log_action "Cleared /etc/securetty"
    fi

    # Lock the root password
    if ask "  Lock root account password (passwd -l root)?" "n"; then
        passwd -l root
        info "Root account locked."
        log_action "Locked root account"
        warn "Use 'sudo -i' or a wheel-group admin account for elevated access."
    else
        skip "Root password lock skipped."
    fi

    # Restrict su to wheel/sudo group
    for pam_su in /etc/pam.d/su /etc/pam.d/su-l; do
        if [[ -f "$pam_su" ]]; then
            backup_file "$pam_su"
            if ! grep -q 'pam_wheel.so' "$pam_su"; then
                # Insert after the first auth line
                sed -i '1s/^/auth required pam_wheel.so use_uid\n/' "$pam_su"
                info "Restricted su to wheel group in $pam_su"
                log_action "Restricted su via pam_wheel in $pam_su"
            else
                info "pam_wheel.so already present in $pam_su"
            fi
        fi
    done

    # Increase password hashing rounds
    if [[ -f /etc/pam.d/common-password ]]; then
        backup_file /etc/pam.d/common-password
        if grep -q 'pam_unix.so' /etc/pam.d/common-password; then
            if ! grep 'pam_unix.so' /etc/pam.d/common-password | grep -q 'rounds='; then
                sed -i 's/\(pam_unix.so.*\)/\1 rounds=65536/' /etc/pam.d/common-password
                info "Set password hashing rounds=65536 in /etc/pam.d/common-password"
                log_action "Increased password hashing rounds to 65536"
            else
                info "rounds= already set in /etc/pam.d/common-password"
            fi
        fi
    fi

    # Deny SSH root login
    SSHD_CFG="/etc/ssh/sshd_config"
    SSHD_DROP_DIR="/etc/ssh/sshd_config.d"
    if [[ -d "$SSHD_DROP_DIR" ]]; then
        TARGET_SSH="$SSHD_DROP_DIR/99-no-root.conf"
        echo "PermitRootLogin no" > "$TARGET_SSH"
        info "Set PermitRootLogin no in $TARGET_SSH"
    elif [[ -f "$SSHD_CFG" ]]; then
        backup_file "$SSHD_CFG"
        if grep -q '^PermitRootLogin' "$SSHD_CFG"; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CFG"
        else
            echo "PermitRootLogin no" >> "$SSHD_CFG"
        fi
        info "Set PermitRootLogin no in $SSHD_CFG"
    fi

    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        info "SSH service reloaded."
    fi
    log_action "Applied root account hardening"
else
    skip "Root account hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 6. FILE PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════
banner "6. File & Directory Permissions"
echo "  Restricts permissions on home directories, kernel/boot files."
echo "  Also audits SUID/SGID binaries."
echo ""

if ask "Restrict home directory permissions (chmod 700 /home/*)?"; then
    for homedir in /home/*/; do
        if [[ -d "$homedir" ]]; then
            chmod 700 "$homedir"
            info "chmod 700 $homedir"
        fi
    done
    log_action "Restricted home directory permissions"
else
    skip "Home directory permissions skipped."
fi

if ask "Restrict boot and kernel source permissions (chmod 700)?"; then
    for d in /boot /usr/src /lib/modules /usr/lib/modules; do
        if [[ -d "$d" ]]; then
            chmod 700 "$d"
            info "chmod 700 $d"
            # Preserve across Debian upgrades
            if command -v dpkg-statoverride &>/dev/null; then
                dpkg-statoverride --list "$d" &>/dev/null || \
                    dpkg-statoverride --add --update root root 0700 "$d" 2>/dev/null || true
            fi
        fi
    done
    log_action "Restricted /boot and kernel module permissions"
else
    skip "Boot/kernel permissions skipped."
fi

if ask "Audit SUID/SGID binaries?"; then
    SUID_FILE="/tmp/suid-audit-$(date +%Y%m%d%H%M%S).txt"
    info "Scanning for SUID/SGID binaries..."
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort > "$SUID_FILE"
    COUNT=$(wc -l < "$SUID_FILE")
    info "Found ${COUNT} SUID/SGID binaries — see $SUID_FILE"
    echo ""
    head -30 "$SUID_FILE"
    (( COUNT > 30 )) && echo "  ... (truncated — see $SUID_FILE)" || true
    log_action "SUID/SGID audit: $COUNT binaries found → $SUID_FILE"
else
    skip "SUID/SGID audit skipped."
fi

if ask "Set restrictive umask (0077) system-wide?"; then
    PROFILE_UMASK="/etc/profile.d/umask-hardening.sh"
    echo 'umask 0077' > "$PROFILE_UMASK"
    chmod 644 "$PROFILE_UMASK"
    info "umask 0077 set in $PROFILE_UMASK (applies to new login sessions)."
    log_action "Set system-wide umask 0077"
else
    skip "umask hardening skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. CORE DUMP DISABLING
# ═══════════════════════════════════════════════════════════════════════════
banner "7. Core Dump Disabling"
echo "  Disables core dumps via sysctl, systemd, and PAM limits."
echo "  Core dumps can leak sensitive process memory to disk."
echo ""

if ask "Disable core dumps?"; then
    # PAM limits
    LIMITS_CONF="/etc/security/limits.d/99-no-coredump.conf"
    cat > "$LIMITS_CONF" << 'LIMITS'
# Disable core dumps
* hard core 0
LIMITS
    info "Core dump limit written to $LIMITS_CONF"

    # systemd coredump
    if [[ -d /etc/systemd ]]; then
        COREDUMP_DROP="/etc/systemd/coredump.conf.d"
        mkdir -p "$COREDUMP_DROP"
        cat > "$COREDUMP_DROP/disable.conf" << 'COREDUMP'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP
        info "systemd coredump disabled via $COREDUMP_DROP/disable.conf"
        systemctl daemon-reload
    fi

    log_action "Disabled core dumps (sysctl, systemd, PAM)"
else
    skip "Core dump disabling skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. APPARMOR — MANDATORY ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════════════════
banner "8. AppArmor — Mandatory Access Control"
echo "  Ensures AppArmor is installed, enabled, and all profiles are enforced."
echo ""

if ask "Install and enforce AppArmor?"; then
    if ! dpkg -s apparmor &>/dev/null; then
        info "Installing AppArmor packages..."
        apt-get update -qq
        apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra 2>/dev/null || true
    fi

    systemctl enable --now apparmor 2>/dev/null || true

    # Enforce all complain-mode profiles
    if command -v aa-enforce &>/dev/null; then
        aa-enforce /etc/apparmor.d/* 2>/dev/null || true
        info "All AppArmor profiles set to enforce mode."
    fi

    if command -v aa-status &>/dev/null; then
        info "AppArmor status:"
        aa-status 2>/dev/null | head -12
    fi

    # Ensure boot parameters include apparmor=1
    GRUB_FILE="/etc/default/grub"
    if [[ -f "$GRUB_FILE" ]]; then
        EXISTING=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/\1/')
        MERGED="$EXISTING"
        for p in "apparmor=1" "security=apparmor"; do
            echo "$MERGED" | grep -qw "$p" || MERGED="$MERGED $p"
        done
        MERGED_CLEAN=$(echo "$MERGED" | sed 's/^ *//')
        sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$MERGED_CLEAN\"|" "$GRUB_FILE"
        command -v update-grub &>/dev/null && update-grub 2>/dev/null || true
        info "AppArmor boot parameters added to GRUB."
    fi

    log_action "AppArmor installed and enforced"
else
    skip "AppArmor skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 9. FIREWALL — UFW / nftables
# ═══════════════════════════════════════════════════════════════════════════
banner "9. Firewall — Default-Deny Inbound Policy"
echo "  Configures a default-deny inbound firewall using ufw or nftables."
echo ""

if ask "Configure firewall?"; then
    if ! command -v ufw &>/dev/null; then
        info "Installing ufw..."
        apt-get install -y -qq ufw 2>/dev/null || true
    fi

    if command -v ufw &>/dev/null; then
        ufw default deny incoming
        ufw default allow outgoing

        if ask "  Allow inbound SSH (port 22)?"; then
            ufw allow ssh
            info "SSH allowed inbound."
        fi

        ufw --force enable
        ufw status verbose
        log_action "Configured ufw default-deny inbound firewall"
    else
        warn "Neither ufw nor suitable firewall found — configure nftables manually."
        log_action "Firewall: ufw unavailable, skipped auto-config"
    fi
else
    skip "Firewall configuration skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 10. APT SECCOMP-BPF SANDBOX
# ═══════════════════════════════════════════════════════════════════════════
banner "10. APT Seccomp-BPF Sandbox"
echo "  Enables APT's built-in seccomp-BPF sandbox to restrict system calls"
echo "  available during package installation."
echo ""

if ask "Enable APT seccomp-BPF sandbox?"; then
    APT_SANDBOX_CONF="/etc/apt/apt.conf.d/40sandbox"
    cat > "$APT_SANDBOX_CONF" << 'APTSBX'
APT::Sandbox::Seccomp "true";
APTSBX
    info "APT seccomp-BPF sandbox enabled via $APT_SANDBOX_CONF"
    log_action "Enabled APT seccomp-BPF sandbox"
else
    skip "APT sandbox skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 11. IPV6 PRIVACY EXTENSIONS
# ═══════════════════════════════════════════════════════════════════════════
banner "11. IPv6 Privacy Extensions"
echo "  Enables temporary, randomised IPv6 addresses to prevent tracking."
echo ""

if ask "Enable IPv6 privacy extensions?"; then
    # Already handled via sysctl in section 1 but add here for clarity
    SYSCTL_IPV6="/etc/sysctl.d/99-ipv6-privacy.conf"
    cat > "$SYSCTL_IPV6" << 'IPV6'
# IPv6 privacy extensions — use temporary addresses
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
IPV6
    sysctl --system > /dev/null 2>&1
    info "IPv6 privacy extensions enabled via $SYSCTL_IPV6"

    # NetworkManager
    NM_CONF="/etc/NetworkManager/NetworkManager.conf"
    if [[ -f "$NM_CONF" ]]; then
        backup_file "$NM_CONF"
        if ! grep -q 'ipv6.ip6-privacy' "$NM_CONF"; then
            cat >> "$NM_CONF" << 'NMCONF'

[connection]
ipv6.ip6-privacy=2
NMCONF
            info "NetworkManager IPv6 privacy set in $NM_CONF"
            systemctl reload NetworkManager 2>/dev/null || true
        fi
    fi

    # systemd-networkd
    if systemctl is-enabled systemd-networkd &>/dev/null; then
        NETWORKD_CONF="/etc/systemd/network/99-ipv6-privacy.conf"
        cat > "$NETWORKD_CONF" << 'NDCONF'
[Network]
IPv6PrivacyExtensions=kernel
NDCONF
        info "systemd-networkd IPv6 privacy config written."
    fi

    log_action "Enabled IPv6 privacy extensions"
else
    skip "IPv6 privacy extensions skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 12. PAM — LOGIN DELAY
# ═══════════════════════════════════════════════════════════════════════════
banner "12. PAM — Login Failure Delay"
echo "  Adds a 4-second delay after failed authentication attempts to slow"
echo "  brute-force attacks."
echo ""

if ask "Add pam_faildelay login delay?"; then
    PAM_SYS_LOGIN="/etc/pam.d/system-login"
    PAM_COMMON_AUTH="/etc/pam.d/common-auth"

    TARGET_PAM=""
    if [[ -f "$PAM_SYS_LOGIN" ]]; then
        TARGET_PAM="$PAM_SYS_LOGIN"
    elif [[ -f "$PAM_COMMON_AUTH" ]]; then
        TARGET_PAM="$PAM_COMMON_AUTH"
    fi

    if [[ -n "$TARGET_PAM" ]]; then
        backup_file "$TARGET_PAM"
        if ! grep -q 'pam_faildelay' "$TARGET_PAM"; then
            echo "auth optional pam_faildelay.so delay=4000000" >> "$TARGET_PAM"
            info "pam_faildelay added to $TARGET_PAM (4 second delay on failure)"
            log_action "Added pam_faildelay to $TARGET_PAM"
        else
            info "pam_faildelay already present in $TARGET_PAM"
        fi
    else
        warn "No suitable PAM login config found. Skipping."
    fi
else
    skip "PAM login delay skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 13. ENTROPY — HAVEGED / JITTERENTROPY
# ═══════════════════════════════════════════════════════════════════════════
banner "13. Additional Entropy Sources"
echo "  Installs haveged and/or jitterentropy to improve /dev/random entropy,"
echo "  especially important on VMs or headless servers."
echo ""

if ask "Install haveged (userspace entropy daemon)?"; then
    apt-get install -y -qq haveged 2>/dev/null || true
    systemctl enable --now haveged 2>/dev/null || true
    info "haveged installed and started."
    log_action "Installed haveged"
else
    skip "haveged skipped."
fi

if ask "Load jitterentropy kernel module?"; then
    JITTER_CONF="/usr/lib/modules-load.d/jitterentropy.conf"
    echo "jitterentropy_rng" > "$JITTER_CONF"
    modprobe jitterentropy_rng 2>/dev/null || true
    info "jitterentropy_rng module loaded and set to load at boot."
    log_action "Configured jitterentropy_rng"
else
    skip "jitterentropy skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 14. MICROCODE UPDATES
# ═══════════════════════════════════════════════════════════════════════════
banner "14. CPU Microcode Updates"
echo "  Installs CPU microcode updates for Intel or AMD processors."
echo "  Microcode updates patch CPU-level vulnerabilities."
echo ""

CPU_VENDOR=$(grep -m1 'vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}')

if [[ "$CPU_VENDOR" == "GenuineIntel" ]]; then
    if ask "Install Intel microcode (intel-microcode)?"; then
        apt-get install -y -qq intel-microcode 2>/dev/null || true
        info "Intel microcode installed."
        log_action "Installed intel-microcode"
    else
        skip "Intel microcode skipped."
    fi
elif [[ "$CPU_VENDOR" == "AuthenticAMD" ]]; then
    if ask "Install AMD microcode (amd64-microcode)?"; then
        apt-get install -y -qq amd64-microcode 2>/dev/null || true
        info "AMD microcode installed."
        log_action "Installed amd64-microcode"
    else
        skip "AMD microcode skipped."
    fi
else
    warn "Could not determine CPU vendor (got: '${CPU_VENDOR}'). Install microcode manually."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 15. GRUB BOOTLOADER PASSWORD
# ═══════════════════════════════════════════════════════════════════════════
banner "15. GRUB Bootloader Password"
echo "  Sets a GRUB superuser password to prevent unauthorized boot parameter"
echo "  changes or single-user mode access on physical/console access."
echo ""
warn "You will need this password to edit GRUB entries at boot."
echo ""

if ask "Set a GRUB bootloader password?" "n"; then
    echo ""
    info "Run the following command to generate a hashed GRUB password:"
    echo ""
    echo "    grub-mkpasswd-pbkdf2"
    echo ""
    read -rp "  Paste the grub.pbkdf2.sha512.* hash here (or leave blank to skip): " GRUB_HASH

    if [[ -n "$GRUB_HASH" ]]; then
        GRUB_PW_SCRIPT="/etc/grub.d/40_password"
        backup_file "$GRUB_PW_SCRIPT"
        cat > "$GRUB_PW_SCRIPT" << GRUBPW
#!/bin/sh
cat << EOF
set superusers="root"
password_pbkdf2 root ${GRUB_HASH}
EOF
GRUBPW
        chmod 700 "$GRUB_PW_SCRIPT"
        command -v update-grub &>/dev/null && update-grub 2>/dev/null || true
        info "GRUB password set. You will need it to edit boot entries."
        log_action "Set GRUB bootloader password"
    else
        skip "No hash provided — GRUB password not set."
    fi
else
    skip "GRUB password skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# 16. USBGuard (optional)
# ═══════════════════════════════════════════════════════════════════════════
banner "16. USBGuard — USB Device Authorization"
echo "  USBGuard controls which USB devices can be connected at runtime."
echo "  Generates an initial policy for currently connected devices."
echo ""
warn "Only safe if you have your required USB devices connected RIGHT NOW."
echo ""

if ask "Install and configure USBGuard?" "n"; then
    apt-get install -y -qq usbguard 2>/dev/null || true

    if command -v usbguard &>/dev/null; then
        # Generate policy from currently connected devices
        usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
        info "USBGuard policy generated from connected devices."
        systemctl enable --now usbguard 2>/dev/null || true
        info "USBGuard enabled and started."
        warn "New USB devices will now be blocked by default."
        log_action "Installed and configured USBGuard"
    else
        warn "USBGuard installation failed."
    fi
else
    skip "USBGuard skipped."
fi

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
banner "Hardening Complete"
echo ""
info "All actions logged to: ${LOG_FILE}"
echo ""
echo -e "  ${BOLD}Recommended next steps:${NC}"
echo "    1. Reboot to apply boot parameters, hidepid, and module blacklists."
echo "    2. Test SSH login from a separate session before disconnecting."
echo "    3. Verify AppArmor status: aa-status"
echo "    4. Check firewall rules: ufw status verbose"
echo "    5. Review SUID audit file (if generated)."
echo "    6. Verify microcode loaded: dmesg | grep -i microcode"
echo "    7. If GRUB password set — memorise it (required to edit boot entries)."
echo ""
echo -e "  ${YELLOW}Note:${NC} Some settings (kernel.unprivileged_userns_clone=0) may"
echo "  break browsers (Chromium/Firefox sandbox) and container runtimes."
echo "  Re-enable with: sysctl -w kernel.unprivileged_userns_clone=1"
echo ""
log_action "=== Hardening session completed ==="
echo -e "${GREEN}Done.${NC}"
