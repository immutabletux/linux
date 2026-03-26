#!/usr/bin/env bash
# =============================================================================
# Linux Kernel Configuration Hardening Script
# Based on: Timesys Corporation – "Securing your Linux Configuration
#           (Kernel Hardening)", Nathan Barrett-Morrison, 2022-02-01
# Source:   https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf
#
# Usage:
#   bash timesys-kernel-hardening.sh [OPTIONS] [CONFIG_FILE]
#
# Options:
#   -f, --fix       Apply hardening changes to the config file (writes in-place)
#   -o, --output F  Write a hardened copy of the config to F (leaves original)
#   -h, --help      Show this help
#
# Config file defaults (searched in order if not supplied):
#   $BUILD_DIR/.config  |  /boot/config-$(uname -r)  |  /proc/config.gz
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colours & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

info()    { echo -e "  ${GREEN}[INFO ]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}[WARN ]${NC}  $*"; }
err()     { echo -e "  ${RED}[ERROR]${NC}  $*"; }
skip()    { echo -e "  ${YELLOW}[SKIP ]${NC}  $*"; }
pass()    { echo -e "  ${GREEN}[PASS ]${NC}  $*"; }
fail()    { echo -e "  ${RED}[FAIL ]${NC}  $*"; }

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0; FIXED=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
FIX_MODE=false
OUTPUT_FILE=""
CONFIG_FILE=""
FORCE_KERNEL_VERSION=""
INTERACTIVE=false

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [CONFIG_FILE]

  -f, --fix           Apply hardening changes directly to CONFIG_FILE
  -i, --interactive   Prompt Y/n before applying each fix (requires -f or -o)
  -o FILE             Write hardened copy to FILE (original unchanged)
  -k, --kernel VER    Override kernel version (e.g. 6.19.6)
  -h, --help          Show this help

CONFIG_FILE defaults (searched in order):
  \$BUILD_DIR/.config  |  /boot/config-\$(uname -r)  |  /proc/config.gz
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--fix) FIX_MODE=true; shift ;;
        -i|--interactive) INTERACTIVE=true; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -k|--kernel) FORCE_KERNEL_VERSION="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) err "Unknown option: $1"; usage ;;
        *) CONFIG_FILE="$1"; shift ;;
    esac
done

# ---------------------------------------------------------------------------
# Locate .config
# ---------------------------------------------------------------------------
if [[ -z "$CONFIG_FILE" ]]; then
    for candidate in \
        "${BUILD_DIR:+$BUILD_DIR/.config}" \
        "/boot/config-$(uname -r 2>/dev/null || true)" \
        ".config"; do
        [[ -n "$candidate" && -f "$candidate" ]] && { CONFIG_FILE="$candidate"; break; }
    done

    # Handle compressed /proc/config.gz
    if [[ -z "$CONFIG_FILE" && -f /proc/config.gz ]]; then
        TMP_CONFIG=$(mktemp)
        zcat /proc/config.gz > "$TMP_CONFIG"
        CONFIG_FILE="$TMP_CONFIG"
        info "Extracted /proc/config.gz to $TMP_CONFIG"
    fi
fi

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
    err "Could not locate a kernel .config file."
    err "Pass one explicitly:  $0 /path/to/.config"
    exit 1
fi

# ---------------------------------------------------------------------------
# Prepare working copy
# ---------------------------------------------------------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
    cp "$CONFIG_FILE" "$OUTPUT_FILE"
    WORK_FILE="$OUTPUT_FILE"
elif $FIX_MODE; then
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    info "Backup written to ${CONFIG_FILE}.bak.*"
    WORK_FILE="$CONFIG_FILE"
else
    WORK_FILE="$CONFIG_FILE"   # read-only mode
fi

# ---------------------------------------------------------------------------
# Detect kernel version from .config (or CLI override)
# ---------------------------------------------------------------------------
KERNEL_VERSION=""
KERNEL_MAJOR=0; KERNEL_MINOR=0; KERNEL_PATCH=0

if [[ -n "$FORCE_KERNEL_VERSION" ]]; then
    KERNEL_VERSION=$(echo "$FORCE_KERNEL_VERSION" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || true)
    [[ -z "$KERNEL_VERSION" ]] && { err "Invalid --kernel value: $FORCE_KERNEL_VERSION"; exit 1; }
fi

if [[ -z "$KERNEL_VERSION" ]]; then
    # Try "# Linux/ARCH X.Y.Z ..." comment (most common)
    VER_LINE=$(grep -m1 "^# Linux/" "$WORK_FILE" 2>/dev/null || true)
    [[ -n "$VER_LINE" ]] && \
        KERNEL_VERSION=$(echo "$VER_LINE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -z "$KERNEL_VERSION" ]]; then
    # Try CONFIG_VERSION_SIGNATURE (common in Debian/Ubuntu packaged configs)
    SIG_LINE=$(grep -m1 "^CONFIG_VERSION_SIGNATURE=" "$WORK_FILE" 2>/dev/null || true)
    [[ -n "$SIG_LINE" ]] && \
        KERNEL_VERSION=$(echo "$SIG_LINE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [[ -z "$KERNEL_VERSION" ]]; then
    # Fall back to running kernel
    KERNEL_VERSION=$(uname -r 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "0.0.0")
fi

KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3)
KERNEL_MAJOR=${KERNEL_MAJOR:-0}; KERNEL_MINOR=${KERNEL_MINOR:-0}; KERNEL_PATCH=${KERNEL_PATCH:-0}

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
ARCH_RAW=$(uname -m 2>/dev/null || echo "unknown")
case "$ARCH_RAW" in
    x86_64)          ARCH="X86_64" ;;
    i?86)            ARCH="X86_32" ;;
    aarch64|arm64)   ARCH="ARM64"  ;;
    arm*)            ARCH="ARM"    ;;
    *)               ARCH="UNKNOWN" ;;
esac

# Check config for architecture hints
if grep -q "CONFIG_ARM64=y\|CONFIG_AARCH64=y" "$WORK_FILE" 2>/dev/null; then ARCH="ARM64"
elif grep -q "CONFIG_ARM=y" "$WORK_FILE" 2>/dev/null; then ARCH="ARM"
elif grep -q "CONFIG_X86_64=y" "$WORK_FILE" 2>/dev/null; then ARCH="X86_64"
elif grep -q "CONFIG_X86_32=y\|CONFIG_X86=y" "$WORK_FILE" 2>/dev/null; then ARCH="X86_32"
fi

# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------
# ver_ge A B  → true if A >= B   (A and B are "major.minor" strings)
ver_ge() {
    local a_maj a_min b_maj b_min
    IFS='.' read -r a_maj a_min _ <<< "$1.0"
    IFS='.' read -r b_maj b_min _ <<< "$2.0"
    (( a_maj > b_maj )) || { (( a_maj == b_maj )) && (( a_min >= b_min )); }
}
ver_le() { ver_ge "$2" "$1"; }
# ver_in_range A MIN MAX → true if MIN <= A <= MAX
ver_in_range() {
    ver_ge "$1" "$2" && ver_le "$1" "$3"
}

KV="${KERNEL_MAJOR}.${KERNEL_MINOR}"

# ---------------------------------------------------------------------------
# Config read/write helpers
# ---------------------------------------------------------------------------
# get_option CONFIG_FOO → current value (y/m/n/"is not set"/unset)
get_option() {
    local opt="$1"
    local line
    line=$(grep -E "^(CONFIG_${opt}=|# CONFIG_${opt} is not set)" "$WORK_FILE" 2>/dev/null | tail -1 || true)
    if [[ -z "$line" ]]; then
        echo "unset"
    elif echo "$line" | grep -q "is not set"; then
        echo "is not set"
    else
        echo "${line#*=}"
    fi
}

# set_option CONFIG_FOO y|m|n|"is not set"
set_option() {
    local opt="$1"
    local val="$2"

    if [[ "$val" == "is not set" ]]; then
        # Remove any existing assignment and add "not set" comment
        sed -i "/^CONFIG_${opt}=/d" "$WORK_FILE"
        if grep -q "# CONFIG_${opt} is not set" "$WORK_FILE"; then
            : # already there
        else
            echo "# CONFIG_${opt} is not set" >> "$WORK_FILE"
        fi
    else
        local newline="CONFIG_${opt}=${val}"
        if grep -q "^CONFIG_${opt}=" "$WORK_FILE"; then
            sed -i "s|^CONFIG_${opt}=.*|${newline}|" "$WORK_FILE"
        else
            # Remove "not set" comment if present, then append
            sed -i "/^# CONFIG_${opt} is not set/d" "$WORK_FILE"
            echo "$newline" >> "$WORK_FILE"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Main check/fix function
# check_option  OPTION  EXPECTED  MIN_VER  MAX_VER  ARCHS  CATEGORY  DESC
#   EXPECTED : "y" | "m" | "is not set" | "n" (same as "is not set")
#   MIN_VER  : e.g. "4.8"   (inclusive)
#   MAX_VER  : e.g. "5.17"  (inclusive) — or "any"
#   ARCHS    : space-separated list of X86_64 X86_32 ARM ARM64 — or "any"
# ---------------------------------------------------------------------------
check_option() {
    local opt="$1"
    local expected="$2"
    local min_ver="$3"
    local max_ver="$4"
    local archs="$5"
    local category="$6"
    local desc="$7"

    TOTAL=$(( TOTAL + 1 ))

    # Normalise expected
    [[ "$expected" == "n" ]] && expected="is not set"

    # Architecture check
    if [[ "$archs" != "any" ]]; then
        local arch_ok=false
        for a in $archs; do [[ "$a" == "$ARCH" ]] && { arch_ok=true; break; }; done
        if ! $arch_ok; then
            SKIPPED=$(( SKIPPED + 1 ))
            skip "CONFIG_${opt} — not applicable for ${ARCH}  [${category}]"
            return
        fi
    fi

    # Version range check
    if [[ "$min_ver" != "any" ]]; then
        if ! ver_ge "$KV" "$min_ver"; then
            SKIPPED=$(( SKIPPED + 1 ))
            skip "CONFIG_${opt} — kernel ${KV} < min ${min_ver}  [${category}]"
            return
        fi
    fi
    if [[ "$max_ver" != "any" ]]; then
        if ! ver_le "$KV" "$max_ver"; then
            SKIPPED=$(( SKIPPED + 1 ))
            skip "CONFIG_${opt} — kernel ${KV} > max ${max_ver}  [${category}]"
            return
        fi
    fi

    local current
    current=$(get_option "$opt")

    if [[ "$current" == "$expected" ]]; then
        PASSED=$(( PASSED + 1 ))
        pass "CONFIG_${opt}=${expected}  [${category}]  ${desc}"
    else
        FAILED=$(( FAILED + 1 ))
        fail "CONFIG_${opt}: expected=${expected}, got=${current}  [${category}]  ${desc}"
        if $FIX_MODE || [[ -n "$OUTPUT_FILE" ]]; then
            local do_fix=true
            if $INTERACTIVE; then
                printf "  ${CYAN}[FIX? ]${NC}  Apply CONFIG_${opt}=${expected}? [Y/n] "
                read -r yn </dev/tty
                [[ "$yn" =~ ^[Nn] ]] && do_fix=false
            fi
            if $do_fix; then
                set_option "$opt" "$expected"
                FIXED=$(( FIXED + 1 ))
                info "  → Fixed: CONFIG_${opt}=${expected}"
            else
                skip "  Skipped: CONFIG_${opt}"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# ============================================================
#  HARDENING CHECKS  (source: Timesys Kernel Hardening Guide)
# ============================================================
# ---------------------------------------------------------------------------
banner "Timesys Linux Kernel Configuration Hardening"
info "Config file : $WORK_FILE"
info "Kernel ver  : ${KERNEL_MAJOR}.${KERNEL_MINOR}.${KERNEL_PATCH}"
info "Architecture: ${ARCH}"
[[ -n "$OUTPUT_FILE" ]] && info "Output file : $OUTPUT_FILE"
$FIX_MODE && warn "FIX MODE enabled — config will be modified in place"
$INTERACTIVE && info "Interactive : Y/n prompt before each fix"
echo ""

# ─────────────────────────────────────────────
banner "1. Memory Protection — Stack Overflow"
# ─────────────────────────────────────────────

check_option "INIT_STACK_ALL_ZERO"        "y"        "5.9"  "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Zero-init all stack vars (strongest, safest)"
# INIT_STACK_ALL_PATTERN is a CHOICE alternative to ZERO — must be unset when ZERO is selected
check_option "INIT_STACK_ALL_PATTERN"     "is not set" "5.9" "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Pattern-init disabled (ZERO is preferred)"
check_option "INIT_STACK_ALL"             "y"        "5.2"  "5.8"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Init stack with 0xAA (kernels 5.2-5.8)"
check_option "STACKPROTECTOR"             "y"        "4.18" "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Stack canary on function entry/exit"
check_option "STACKPROTECTOR_STRONG"      "y"        "4.18" "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Stronger stack canary (additional conditions)"
check_option "CC_STACKPROTECTOR"          "y"        "3.14" "4.17" "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Stack protector (pre-4.18 name)"
check_option "CC_STACKPROTECTOR_STRONG"   "y"        "3.14" "4.17" "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Strong stack protector (pre-4.18 name)"
check_option "STACKPROTECTOR_PER_TASK"    "y"        "5.0"  "any"  "ARM ARM64"               "stack_canary" \
    "Per-task stack canary value"
check_option "VMAP_STACK"                 "y"        "4.9"  "any"  "X86_64 ARM64"            "stack_canary" \
    "Virtually mapped stacks with guard pages"
check_option "SCHED_STACK_END_CHECK"      "y"        "3.18" "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Detect stack corruption on schedule()"
check_option "STACKLEAK_METRICS"          "is not set" "5.2" "any" "X86_32 X86_64 ARM64"     "stack_canary" \
    "Do not expose STACKLEAK metrics via /proc"
check_option "STACKLEAK_RUNTIME_DISABLE"  "is not set" "5.2" "any" "X86_32 X86_64 ARM64"     "stack_canary" \
    "Disallow runtime disable of stack erasing"
check_option "GCC_PLUGIN_STACKLEAK"       "y"        "5.2"  "any"  "X86_32 X86_64 ARM64"     "gcc_plugin" \
    "GCC plugin: erase stack before returning (~1% overhead)"
check_option "GCC_PLUGIN_ARM_SSP_PER_TASK" "y"       "5.2"  "any"  "ARM"                     "gcc_plugin" \
    "GCC plugin: per-task stack canary (ARM)"
check_option "RANDOMIZE_KSTACK_OFFSET_DEFAULT" "y"   "5.13" "any"  "X86_32 X86_64 ARM ARM64" "stack_canary" \
    "Randomize kernel stack offset at syscall entry"
check_option "SHADOW_CALL_STACK"          "y"        "5.8"  "any"  "ARM ARM64"               "stack_canary" \
    "Clang shadow call stack (protects return addresses — ARM/ARM64 only in mainline)"
check_option "THREAD_INFO_IN_TASK"        "y"        "4.9"  "any"  "X86_32 X86_64 ARM64"     "stack_canary" \
    "Move thread_info out of the stack into task_struct"

# ─────────────────────────────────────────────
banner "2. Memory Protection — Heap Overflow"
# ─────────────────────────────────────────────

check_option "STRICT_KERNEL_RWX"          "y"        "4.11" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Kernel text/rodata read-only; non-text non-executable"
check_option "DEBUG_RODATA"               "y"        "2.6.16" "4.10" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Same as STRICT_KERNEL_RWX (pre-4.11)"
check_option "SLAB_FREELIST_HARDENED"     "y"        "4.14" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Harden slab freelist metadata"
check_option "SLAB_FREELIST_RANDOM"       "y"        "4.7"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Randomize slab freelist order"
check_option "SHUFFLE_PAGE_ALLOCATOR"     "y"        "5.2"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Randomize page allocator order"
check_option "COMPAT_BRK"                 "is not set" "2.6.25" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Do not disable heap randomization"
check_option "INET_DIAG"                  "is not set" "2.6.14" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Disable INET socket monitoring (assists heap attacks)"
check_option "SLAB_MERGE_DEFAULT"         "is not set" "4.13" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Keep slab caches unmerged to limit heap overflow impact"

# ─────────────────────────────────────────────
banner "3. Memory Protection — User-Copy"
# ─────────────────────────────────────────────

check_option "HARDENED_USERCOPY"          "y"        "4.8"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Validate memory regions on copy_to/from_user()"
check_option "HARDENED_USERCOPY_FALLBACK" "is not set" "4.16" "5.15" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "No fallback for missing usercopy whitelists"
check_option "HARDENED_USERCOPY_PAGESPAN" "is not set" "4.8" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Reject multi-page usercopy without __GFP_COMP"
check_option "HAVE_HARDENED_USERCOPY_ALLOCATOR" "y"  "4.8"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Heap object size validation for usercopy"
check_option "FORTIFY_SOURCE"             "y"        "4.13" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Harden common str/mem functions against buffer overflows"

# ─────────────────────────────────────────────
banner "4. Memory Protection — Information Exposure"
# ─────────────────────────────────────────────

check_option "X86_UMIP"                   "y"        "5.5"  "any"  "X86_32 X86_64"           "memory_protection" \
    "Block SGDT/SIDT etc. in user mode (prevents hardware state leak)"
check_option "X86_INTEL_UMIP"             "y"        "4.15" "5.4"  "X86_32 X86_64"           "memory_protection" \
    "Same as X86_UMIP (pre-5.5 name)"
check_option "PROC_PAGE_MONITOR"          "is not set" "2.6.28" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Don't expose process memory via /proc"
check_option "PROC_VMCORE"                "is not set" "2.6.37" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Don't export crashed kernel dump image"
check_option "PROC_KCORE"                 "is not set" "2.6.27" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "No virtual ELF core of live kernel (GDB accessible)"
check_option "DEBUG_FS"                   "is not set" "2.6.11" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Disable debugfs (potential vulnerability exposure)"
check_option "KALLSYMS"                   "is not set" "2.6.20" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Don't load/print symbolic kernel crash info"
check_option "SECURITY_DMESG_RESTRICT"    "y"        "2.6.37" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Restrict unprivileged dmesg reading"
check_option "DEBUG_BUGVERBOSE"           "is not set" "2.6.9" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "No backtrace info leakage on BUG()"

# ─────────────────────────────────────────────
banner "5. Memory Protection — KASLR & Randomization"
# ─────────────────────────────────────────────

check_option "ARCH_HAS_ELF_RANDOMIZE"     "y"        "4.1"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Randomize stack, mmap, brk, ET_DYN locations"
check_option "RANDOMIZE_BASE"             "y"        "4.7"  "any"  "X86_32 X86_64 ARM64"     "memory_protection" \
    "KASLR: randomize kernel image physical and virtual address"
check_option "RANDOMIZE_MEMORY"           "y"        "4.8"  "any"  "X86_64"                  "memory_protection" \
    "KASLR: randomize kernel memory section base addresses"
check_option "GCC_PLUGIN_RANDSTRUCT"      "y"        "4.13" "6.1"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "GCC plugin: randomize layout of sensitive kernel structures (pre-6.2 name)"
check_option "GCC_PLUGIN_RANDSTRUCT_PERFORMANCE" "is not set" "4.13" "6.1" "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Full structure randomization (not cacheline-only) (pre-6.2 name)"
# Renamed in 6.2: GCC_PLUGIN_RANDSTRUCT → RANDSTRUCT_FULL / RANDSTRUCT_PERFORMANCE
check_option "RANDSTRUCT_FULL"            "y"        "6.2"  "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Full structure layout randomization (GCC or Clang, 6.2+)"
check_option "RANDSTRUCT_PERFORMANCE"     "is not set" "6.2" "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Cacheline-only randomization disabled (use FULL)"
check_option "ARCH_MMAP_RND_BITS"         "32"       "4.5"  "any"  "X86_64 ARM64"            "memory_protection" \
    "Maximum mmap ASLR entropy (64-bit)"
check_option "ARCH_MMAP_RND_BITS"         "16"       "4.5"  "any"  "X86_32 ARM"              "memory_protection" \
    "Maximum mmap ASLR entropy (32-bit)"

# ─────────────────────────────────────────────
banner "6. Memory Protection — Initialization"
# ─────────────────────────────────────────────

check_option "INIT_ON_ALLOC_DEFAULT_ON"   "y"        "5.3"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Zero-init page/slab allocator memory on alloc"
check_option "INIT_ON_FREE_DEFAULT_ON"    "y"        "5.3"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Wipe memory immediately on free (prevents cold-boot attacks)"
check_option "PAGE_POISONING"             "y"        "4.6"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Poison free pages (boot with page_poison=1)"
check_option "PAGE_POISONING_NO_SANITY"   "is not set" "4.6" "5.10" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Keep sanity checks on alloc (not poison-on-free only)"
check_option "PAGE_POISONING_ZERO"        "y"        "4.19" "5.10" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Fill freed pages with zeros"
check_option "SLUB_DEBUG"                 "y"        "2.6.22" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "SLUB debug: slab poisoning via boot cmdline (slub_debug=P)"
check_option "REFCOUNT_FULL"              "y"        "4.13" "5.4"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Full reference count validation (use-after-free protection)"

# ─────────────────────────────────────────────
banner "7. Memory Protection — Misc Validation"
# ─────────────────────────────────────────────

check_option "BUG"                        "y"        "2.6.12" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Terminate processes on BUG() conditions"
check_option "BUG_ON_DATA_CORRUPTION"     "y"        "4.10" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "BUG on kernel memory structure data corruption"
check_option "DEBUG_ALIGN_RODATA"         "y"        "4.6"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Make rodata explicitly non-executable"
check_option "DEBUG_LIST"                 "y"        "2.6.19" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Extended checks in linked-list walking routines"
check_option "DEBUG_SG"                   "y"        "2.6.24" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Checks on scatter-gather tables"
check_option "DEBUG_CREDENTIALS"          "y"        "2.6.32" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Credential management debug tracking"
check_option "DEBUG_NOTIFIERS"            "y"        "2.6.29" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Sanity checking for notifier call chains"
check_option "DEBUG_VIRTUAL"              "y"        "2.6.28" "any" "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Sanity checks in virt_to_page()"
check_option "DEBUG_WX"                   "y"        "4.4"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Warn on W+X mappings at boot"
check_option "IOMMU_SUPPORT"              "y"        "3.1"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "IOMMU support for DMA attack mitigation"
check_option "EFI_DISABLE_PCI_DMA"        "y"        "5.6"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Disable PCI busmaster on ExitBootServices (DMA protection)"
check_option "RESET_ATTACK_MITIGATION"    "y"        "4.14" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Clear RAM via TCG spec on reboot (cold-boot attack defense)"
check_option "STATIC_USERMODEHELPER"      "y"        "4.11" "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "Route usermode-helper calls through single fixed executable"
check_option "DEFAULT_MMAP_MIN_ADDR"      "65536"    "2.6.31" "any" "X86_32 X86_64"          "memory_protection" \
    "Protect low memory pages from userspace (NULL ptr defense)"
check_option "DEFAULT_MMAP_MIN_ADDR"      "32768"    "2.6.31" "any" "ARM ARM64"               "memory_protection" \
    "Protect low memory pages from userspace (NULL ptr defense)"

# ─────────────────────────────────────────────
banner "8. Reducing Attack Surface — Kernel Replacement"
# ─────────────────────────────────────────────

check_option "HIBERNATION"                "is not set" "2.6.23" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable hibernation (allows kernel replacement)"
check_option "KEXEC"                      "is not set" "2.6.16" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable kexec (boot another kernel)"
check_option "KEXEC_FILE"                 "is not set" "3.17" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable kexec file loading"

# ─────────────────────────────────────────────
banner "9. Reducing Attack Surface — Module Security"
# ─────────────────────────────────────────────

check_option "STRICT_MODULE_RWX"          "y"        "4.11" "any"  "X86_32 X86_64 ARM ARM64" "module_security" \
    "Module text/rodata read-only; data non-executable"
check_option "MODULE_SIG"                 "y"        "3.7"  "any"  "X86_32 X86_64 ARM ARM64" "module_security" \
    "Enable module signature verification"
check_option "MODULE_SIG_ALL"             "y"        "3.9"  "any"  "X86_32 X86_64 ARM ARM64" "module_security" \
    "Auto-sign all modules on modules_install"
check_option "MODULE_SIG_SHA512"          "y"        "3.7"  "any"  "X86_32 X86_64 ARM ARM64" "module_security" \
    "Sign modules with SHA-512"
check_option "MODULE_SIG_FORCE"           "y"        "3.7"  "any"  "X86_32 X86_64 ARM ARM64" "module_security" \
    "Require validly signed modules"

# ─────────────────────────────────────────────
banner "10. Reducing Attack Surface — Syscall Exposure"
# ─────────────────────────────────────────────

check_option "SECCOMP"                    "y"        "any"  "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Enable seccomp sandboxing"
check_option "SECCOMP_FILTER"             "y"        "3.5"  "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "BPF-based syscall filtering"
check_option "USELIB"                     "is not set" "4.5" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Remove obsolete libc5 uselib() syscall"
check_option "MODIFY_LDT_SYSCALL"         "is not set" "4.3" "any"  "X86_32 X86_64"          "attack_surface" \
    "Remove modify_ldt() syscall (legacy 16-bit/Wine only)"
check_option "LEGACY_VSYSCALL_NONE"       "y"        "4.4"  "any"  "X86_32 X86_64"           "attack_surface" \
    "No vsyscall mapping (eliminates ASLR bypass vector)"
check_option "X86_VSYSCALL_EMULATION"     "is not set" "3.19" "any" "X86_32 X86_64"          "attack_surface" \
    "No legacy vsyscall page emulation"
check_option "CHECKPOINT_RESTORE"         "is not set" "3.3" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable checkpoint/restore functionality"
check_option "USERFAULTFD"                "is not set" "4.3" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable userfaultfd() syscall"
check_option "IO_URING"                   "is not set" "5.1" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable io_uring interface"
check_option "BPF_SYSCALL"                "is not set" "3.18" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable bpf() syscall unless explicitly needed"
check_option "BPF_JIT"                    "is not set" "3.0"  "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No JIT compilation for BPF"
check_option "USER_NS"                    "is not set" "3.9" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable user namespaces (root privesc vector in containers)"
check_option "OABI_COMPAT"                "is not set" "2.6.16" "any" "ARM"                  "attack_surface" \
    "No older ABI binaries (prevents seccomp filter bypass)"
check_option "IA32_EMULATION"             "is not set" "2.6.24" "any" "X86_64"               "attack_surface" \
    "Disable 32-bit program emulation (if no 32-bit programs used)"
check_option "X86_X32"                    "is not set" "3.9" "5.17" "X86_32 X86_64"          "attack_surface" \
    "Disable x32 ABI (pre-5.18 name)"
# Renamed to X86_X32_ABI in 5.18
check_option "X86_X32_ABI"               "is not set" "5.18" "any" "X86_32 X86_64"          "attack_surface" \
    "Disable x32 ABI (5.18+ name)"
check_option "LDISC_AUTOLOAD"             "is not set" "5.1" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No automatic TTY line discipline loading"

# ─────────────────────────────────────────────
banner "11. Reducing Attack Surface — Misc Disabled Features"
# ─────────────────────────────────────────────

check_option "DEVMEM"                     "is not set" "4.0" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No /dev/mem physical memory access"
check_option "DEVKMEM"                    "is not set" "2.6.26" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No /dev/kmem device"
check_option "IO_STRICT_DEVMEM"           "y"        "4.5"  "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Strict /dev/mem IO restrictions"
check_option "STRICT_DEVMEM"              "y"        "2.6.27" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Strict /dev/mem access (no all-memory root access)"
check_option "ACPI_CUSTOM_METHOD"         "is not set" "3.0" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No ACPI custom method (arbitrary kernel memory write)"
check_option "BINFMT_MISC"                "is not set" "2.5.73" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No wrapper-driven binary formats"
check_option "BINFMT_AOUT"                "is not set" "2.5.73" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No a.out/ECOFF binary support (legacy)"
check_option "ZSMALLOC"                   "is not set" "3.16" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No compressed-page memory allocator"
check_option "ZSMALLOC_STAT"              "is not set" "4.0" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No ZSMALLOC stats leak"
check_option "LEGACY_PTYS"                "is not set" "2.6.39" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No legacy BSD pseudo terminal support (security issues)"
check_option "KSM"                        "is not set" "2.6.32" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No kernel same-page merging (shared memory exploit)"
check_option "RANDOM_TRUST_BOOTLOADER"    "is not set" "5.4" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Don't trust bootloader-supplied entropy"
check_option "RANDOM_TRUST_CPU"           "is not set" "4.19" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Don't trust CPU manufacturer for CRNG init"
check_option "ACPI_TABLE_UPGRADE"         "is not set" "4.7" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No ACPI tables passed in via initrd"
check_option "MAGIC_SYSRQ"                "is not set" "2.6.9" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable magic SysRq keys (too much system access)"
check_option "EFI_CUSTOM_SSDT_OVERLAYS"   "is not set" "5.8" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No EFI variable ACPI SSDT overlay loading"
check_option "STAGING"                    "is not set" "2.6.28" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No staging/unstable drivers"
check_option "AIO"                        "is not set" "2.6.28" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable AIO (SELinux W+X bypass history)"
check_option "VT"                         "is not set" "2.6.39" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable virtual terminal devices"
check_option "FB"                         "is not set" "2.6.12" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable legacy framebuffer (old security practices)"
check_option "DRM_LEGACY"                 "is not set" "4.9" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable legacy DRI1 (unsafe userspace APIs)"
check_option "INPUT_EVBUG"                "is not set" "2.5.45" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No input event logging (keylogger risk)"
check_option "IP_DCCP"                    "is not set" "3.9" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable DCCP protocol unless needed"
check_option "IP_SCTP"                    "is not set" "3.8" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable SCTP protocol unless needed"
check_option "USB_USBNET"                 "is not set" "2.6.22" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable USB networking subsystem"
check_option "BLK_DEV_FD"                "is not set" "2.5.45" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable floppy disk driver"

# ─────────────────────────────────────────────
banner "12. Reducing Attack Surface — Debug/Tracing"
# ─────────────────────────────────────────────

check_option "KPROBES"                    "is not set" "2.6.25" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable kprobes (trap at kernel addresses)"
check_option "UPROBES"                    "is not set" "3.15" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable uprobes (user-space kprobes)"
check_option "GENERIC_TRACER"             "is not set" "2.6.31" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable generic tracing"
check_option "TRACING"                    "is not set" "2.6.27" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable tracing capabilities"
check_option "TRACING_SUPPORT"            "is not set" "2.6.30" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable tracing support"
check_option "FTRACE"                     "is not set" "2.6.31" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable function tracer"
check_option "DEBUG_KMEMLEAK"             "is not set" "2.6.31" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable kernel memory leak detector"
check_option "PAGE_OWNER"                 "is not set" "5.1" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable page owner tracking"
check_option "HWPOISON_INJECT"            "is not set" "2.6.33" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable hwpoison memory injector"
check_option "MEM_SOFT_DIRTY"             "is not set" "3.11" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No soft-dirty PTE tracking"
check_option "DEVPORT"                    "is not set" "4.11" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable /dev/port"
check_option "NOTIFIER_ERROR_INJECTION"   "is not set" "3.6" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No notifier error injection"
check_option "PTDUMP_DEBUGFS"             "is not set" "5.6" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Don't expose kernel pagetable layout in debugfs"
check_option "MMIOTRACE"                  "is not set" "2.6.29" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable MMIO tracing"
check_option "MMIOTRACE_TEST"             "is not set" "2.6.29" "any" "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "No MMIO trace test module (writes garbage to IO memory)"
check_option "LIVEPATCH"                  "is not set" "4.0" "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Disable live kernel patching"
check_option "COMPAT_VDSO"                "is not set" "2.6.24" "any" "X86_32 X86_64 ARM64"   "attack_surface" \
    "No legacy vDSO mapping"

# ─────────────────────────────────────────────
banner "13. Security Policy — Linux Security Modules"
# ─────────────────────────────────────────────

check_option "SECURITY"                   "y"        "2.5.50" "any" "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Enable LSM framework"
check_option "SECURITY_YAMA"              "y"        "3.4"  "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Enable Yama LSM (ptrace scope restriction)"
check_option "SECURITY_WRITABLE_HOOKS"    "is not set" "4.12" "any" "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Make LSM hooks read-only after init"
check_option "SECURITY_SELINUX_DISABLE"   "is not set" "2.6.6" "any" "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Prevent runtime SELinux disable"
check_option "SECURITY_LOCKDOWN_LSM"      "y"        "5.4"  "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Enable lockdown LSM"
check_option "SECURITY_LOCKDOWN_LSM_EARLY" "y"       "5.4"  "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Enable lockdown LSM early in init"
check_option "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY" "y" "5.4" "any" "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Kernel runs in confidentiality mode by default"
check_option "SECURITY_SAFESETID"         "y"        "5.1"  "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "SafeSetID LSM: whitelist-restricted UID/GID transitions"
check_option "SECURITY_LOADPIN"           "y"        "4.7"  "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "LoadPin: pin kernel files to first filesystem"
check_option "SECURITY_LOADPIN_ENFORCE"   "y"        "4.20" "any"  "X86_32 X86_64 ARM ARM64" "security_policy" \
    "Enforce LoadPin at boot"

# ─────────────────────────────────────────────
banner "14. GCC Plugins"
# ─────────────────────────────────────────────

check_option "GCC_PLUGINS"                "y"        "4.8"  "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Enable GCC security plugins"
check_option "GCC_PLUGIN_LATENT_ENTROPY"  "y"        "4.9"  "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Generate additional boot/fork/irq entropy"
check_option "GCC_PLUGIN_STRUCTLEAK"      "y"        "5.2"  "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Zero-initialize stack variables before use"
# _BYREF_ALL, _BYREF, _USER are a CHOICE — only the selected mode is =y; the others are unset
check_option "GCC_PLUGIN_STRUCTLEAK_BYREF_ALL" "y"   "5.2"  "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Zero-init all structs passed by reference (strongest — select this)"
check_option "GCC_PLUGIN_STRUCTLEAK_BYREF" "is not set" "5.2" "any" "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "BYREF disabled (BYREF_ALL is preferred)"
check_option "GCC_PLUGIN_STRUCTLEAK_USER" "is not set" "5.2" "any" "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "USER mode disabled (BYREF_ALL is preferred)"
check_option "CFI_CLANG"                  "y"        "5.13" "any"  "X86_32 X86_64 ARM ARM64" "gcc_plugin" \
    "Clang CFI: forward-edge indirect call checking"

# ─────────────────────────────────────────────
banner "15. Architecture-Specific — x86"
# ─────────────────────────────────────────────

check_option "RETPOLINE"                  "y"        "4.15" "6.1"  "X86_32 X86_64"           "arch_x86" \
    "Spectre v2 mitigation: retpoline (pre-6.2 name)"
# Renamed to MITIGATION_RETPOLINE in 6.2 as part of the CONFIG_MITIGATION_* reorganisation
check_option "MITIGATION_RETPOLINE"      "y"        "6.2"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Spectre v2 mitigation: retpoline (6.2+ name)"
check_option "X86_SMAP"                   "y"        "3.7"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Supervisor Mode Access Prevention (SMAP)"
check_option "PAGE_TABLE_ISOLATION"       "y"        "4.15" "6.1"  "X86_32 X86_64"           "arch_x86" \
    "Meltdown mitigation: isolate kernel page table from userspace (pre-6.2 name)"
# Renamed to MITIGATION_PAGE_TABLE_ISOLATION in 6.2
check_option "MITIGATION_PAGE_TABLE_ISOLATION" "y"  "6.2"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Meltdown mitigation: isolate kernel page table from userspace (6.2+ name)"
check_option "MICROCODE"                  "y"        "4.4"  "any"  "X86_32 X86_64"           "arch_x86" \
    "CPU microcode loading (mitigates CPU bugs)"
check_option "INTEL_IOMMU"                "y"        "3.2"  "any"  "X86_64"                  "arch_x86" \
    "Intel IOMMU DMA remapping"
check_option "INTEL_IOMMU_DEFAULT_ON"     "y"        "3.2"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Enable Intel IOMMU by default at boot"
check_option "INTEL_IOMMU_SVM"            "y"        "4.4"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Intel IOMMU Shared Virtual Memory (PASID)"
check_option "AMD_IOMMU"                  "y"        "3.1"  "any"  "X86_64"                  "arch_x86" \
    "AMD IOMMU DMA remapping"
check_option "AMD_IOMMU_V2"               "y"        "3.9"  "any"  "X86_64"                  "arch_x86" \
    "AMD IOMMUv2 (PRI + PASID)"
check_option "X86_INTEL_TSX_MODE_OFF"     "y"        "5.4"  "any"  "X86_32 X86_64"           "arch_x86" \
    "Disable Intel TSX by default (tsx=off)"
check_option "X86_MSR"                    "is not set" "2.6.24" "any" "X86_32 X86_64"        "arch_x86" \
    "No /dev/cpu/*/msr (MSR access for privileged processes)"
check_option "X86_CPUID"                  "is not set" "2.6.24" "any" "X86_32 X86_64"        "arch_x86" \
    "No /dev/cpu/*/cpuid"
check_option "X86_IOPL_IOPERM"            "is not set" "5.5" "any"  "X86_32 X86_64"          "arch_x86" \
    "Disable ioperm()/iopl() syscalls (legacy I/O port access)"
check_option "X86_PAE"                    "y"        "2.6.24" "any" "X86_32"                 "arch_x86" \
    "PAE: required for NX; enables larger swapspace"
check_option "HIGHMEM64G"                 "y"        "2.6.24" "any" "X86_32"                 "arch_x86" \
    "64-bit highmem for >4GB RAM on 32-bit"
check_option "VMSPLIT_3G"                 "y"        "2.6.24" "any" "X86_32"                 "arch_x86" \
    "3G/1G memory split for maximal userspace memory"

# ─────────────────────────────────────────────
banner "16. Architecture-Specific — ARM / ARM64"
# ─────────────────────────────────────────────

check_option "HARDEN_BRANCH_PREDICTOR"    "y"        "4.16" "any"  "ARM ARM64"               "arch_arm" \
    "Spectre: clear branch predictor state on context switch"
check_option "ARM64_PAN"                  "y"        "4.3"  "any"  "ARM64"                   "arch_arm" \
    "ARMv8.1 PAN: kernel cannot access EL0 memory directly"
check_option "UNMAP_KERNEL_AT_EL0"        "y"        "4.16" "any"  "ARM64"                   "arch_arm" \
    "Meltdown mitigation: unmap kernel when running in userspace"
check_option "HARDEN_EL2_VECTORS"         "y"        "4.17" "5.8"  "ARM64"                   "arch_arm" \
    "Map EL2 vectors to fixed location (VBAR_EL2 disclosure)"
check_option "ARM64_SW_TTBR0_PAN"         "y"        "4.10" "any"  "ARM64"                   "arch_arm" \
    "Software PAN emulation (point TTBR0 to zero area)"
check_option "CPU_SW_DOMAIN_PAN"          "y"        "4.3"  "any"  "ARM"                     "arch_arm" \
    "Software domain-based PAN for ARM"
check_option "RODATA_FULL_DEFAULT_ENABLED" "y"        "5.0"  "any"  "ARM64"                   "arch_arm" \
    "Apply RO attributes to linear alias of rodata pages"
check_option "ARM64_PTR_AUTH"             "y"        "5.0"  "any"  "ARM64"                   "arch_arm" \
    "ARMv8.3 pointer authentication at EL0"
check_option "ARM64_PTR_AUTH_KERNEL"      "y"        "5.14" "any"  "ARM64"                   "arch_arm" \
    "Compile kernel with pointer authentication (return addr)"
check_option "ARM64_BTI_KERNEL"           "y"        "5.8"  "any"  "ARM64"                   "arch_arm" \
    "Branch Target Identification enforcement for kernel code"
check_option "ARM64_MTE"                  "y"        "5.10" "any"  "ARM64"                   "arch_arm" \
    "Memory Tagging Extension support at EL0"
check_option "ARM64_EPAN"                 "y"        "5.13" "any"  "ARM64"                   "arch_arm" \
    "Enhanced PAN with execute-only mappings"
check_option "KASAN_HW_TAGS"              "y"        "5.11" "any"  "ARM64"                   "arch_arm" \
    "Hardware tag-based KASAN (uses MTE)"

# ─────────────────────────────────────────────
banner "17. Filesystem / Storage Hardening"
# ─────────────────────────────────────────────

check_option "DM_CRYPT"                   "y"        "2.6.4" "any"  "X86_32 X86_64 ARM ARM64" "filesystem" \
    "Device mapper: block-level encryption (dm-crypt)"
check_option "DM_VERITY"                  "y"        "3.4"  "any"  "X86_32 X86_64 ARM ARM64" "filesystem" \
    "Device mapper: verity (cryptographic block device integrity)"
check_option "DM_INTEGRITY"               "y"        "4.12" "any"  "X86_32 X86_64 ARM ARM64" "filesystem" \
    "Device mapper: integrity (data integrity for block devices)"
check_option "IMA"                        "y"        "2.6.30" "any" "X86_32 X86_64 ARM ARM64" "filesystem" \
    "Integrity Measurement Architecture"
check_option "EVM"                        "y"        "3.2"  "any"  "X86_32 X86_64 ARM ARM64" "filesystem" \
    "Extended Verification Module (file metadata HMAC)"

# ─────────────────────────────────────────────
banner "18. Panic / Reliability"
# ─────────────────────────────────────────────

check_option "SYN_COOKIES"                "y"        "2.6.35" "any" "X86_32 X86_64 ARM ARM64" "network" \
    "TCP SYN flood mitigation via SYN cookies"
check_option "TRIM_UNUSED_KSYMS"          "y"        "4.7"  "any"  "X86_32 X86_64 ARM ARM64" "attack_surface" \
    "Drop unused exported symbols (smaller attack surface)"
check_option "UBSAN_BOUNDS"               "y"        "5.7"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "UBSAN: detect out-of-bounds array accesses"
check_option "UBSAN_SANITIZE_ALL"         "y"        "5.7"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "UBSAN instrumentation for entire kernel"
check_option "UBSAN_TRAP"                 "y"        "5.7"  "any"  "X86_32 X86_64 ARM ARM64" "memory_protection" \
    "UBSAN: trap on violation (reduces overhead)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
banner "Summary"
echo -e "  Config: ${BOLD}${WORK_FILE}${NC}"
echo -e "  Kernel: ${BOLD}${KERNEL_MAJOR}.${KERNEL_MINOR}.${KERNEL_PATCH}${NC}  |  Arch: ${BOLD}${ARCH}${NC}"
echo ""
echo -e "  Total  checks : ${BOLD}${TOTAL}${NC}"
echo -e "  ${GREEN}Passed${NC}         : ${BOLD}${PASSED}${NC}"
echo -e "  ${RED}Failed${NC}         : ${BOLD}${FAILED}${NC}"
echo -e "  ${YELLOW}Skipped${NC}        : ${BOLD}${SKIPPED}${NC}"
if $FIX_MODE || [[ -n "$OUTPUT_FILE" ]]; then
echo -e "  ${CYAN}Fixed${NC}          : ${BOLD}${FIXED}${NC}"
fi
echo ""

if (( FAILED == 0 )); then
    echo -e "  ${GREEN}${BOLD}All applicable checks passed!${NC}"
else
    echo -e "  ${RED}${BOLD}${FAILED} check(s) failed.${NC}"
    if ! $FIX_MODE && [[ -z "$OUTPUT_FILE" ]]; then
        echo -e "  ${YELLOW}Tip:${NC} run with ${BOLD}--fix${NC} to apply hardening changes, or ${BOLD}-o hardened.config${NC} to write a copy."
    fi
fi
echo ""
