# Security Hardening Scripts

A collection of advanced Linux security hardening scripts for Debian-based systems.

---

## Scripts

### `advanced-ddos-security.sh`
**Advanced DDoS Protection & Mitigation**

Comprehensive DDoS defence for Debian 11/12 and Ubuntu 20.04+.

**Features:**
- SYN, UDP, and ICMP flood protection via iptables/nftables
- HTTP/HTTPS Layer-7 rate limiting
- Connection tracking abuse prevention
- IP reputation blacklisting with `ipset`
- Geographic IP blocking (optional)
- `fail2ban` jail configuration
- Suricata IDS integration (optional)
- Traffic shaping with `tc`/`iproute2`
- Kernel sysctl tuning for DDoS resilience
- Real-time alerting (email/Slack)
- Auto-ban via cron and rollback/flush support

**Usage:**
```bash
sudo bash advanced-ddos-security.sh [OPTIONS]

  --install        Full install: packages, rules, services, crons
  --rules-only     Apply iptables/nftables rules only
  --sysctl-only    Apply kernel sysctl tuning only
  --status         Show current protection status
  --flush          Remove all DDoS rules (rollback)
  --report         Generate DDoS activity report
  --uninstall      Remove all changes made by this script
```

---

### `advanced-selinux-hardening.sh`
**Advanced SELinux Hardening**

Implements a layered SELinux security posture for Debian 11/12. Based on NSA/Red Hat SELinux guides, CIS Debian Benchmark, and NIST SP 800-123.

**Features:**
- SELinux installation and mode configuration (enforcing/permissive)
- Policy type selection: `targeted` or `mls`
- SELinux boolean tuning for common services
- Strict user confinement and system user mapping
- Port labelling for non-standard service ports
- Advanced audit logging integration
- Custom policy module generation for common services
- Full SELinux posture report mode (no changes)

**Usage:**
```bash
sudo bash advanced-selinux-hardening.sh [OPTIONS]

  -m, --mode MODE     Set SELinux mode: enforcing|permissive|disabled (default: enforcing)
  -p, --policy TYPE   Policy type: targeted|mls (default: targeted)
  -u, --users         Apply strict user confinement
  -a, --audit         Configure advanced audit logging
  -c, --custom        Build and load custom policy modules
  -r, --report        Generate posture report (read-only)
  -y, --yes           Non-interactive mode
```

> **Warning:** Always test in permissive mode before enforcing on a remote host.

---

### `timesys-kernel-hardening.sh`
**Kernel Configuration Hardening**

Audits and hardens a Linux kernel `.config` file based on the [Timesys Corporation Kernel Hardening Guide](https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf) (Nathan Barrett-Morrison, 2022).

**Features:**
- Audits kernel config for insecure or missing hardening options
- Covers: exploit mitigations, attack surface reduction, memory protections, and speculative execution defences
- Supports in-place patching (`--fix`) or writing a hardened copy (`--output`)
- Works with `.config`, `/boot/config-$(uname -r)`, or `/proc/config.gz`

**Usage:**
```bash
bash timesys-kernel-hardening.sh [OPTIONS] [CONFIG_FILE]

  -f, --fix       Apply hardening changes in-place
  -o, --output F  Write hardened config to file F
  -h, --help      Show help
```

---

### `timesys_kernel_hardening.txt`
Reference document — Timesys Corporation's *"Securing your Linux Configuration (Kernel Hardening)"* guide. Covers kernel configuration categories, option tables, and rationale for each hardening decision. Used as the basis for `timesys-kernel-hardening.sh`.

---

## References

- [madaidan's Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
- [Timesys Kernel Hardening Guide](https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf)
- [Debian SELinux Wiki](https://wiki.debian.org/SELinux)
- [NSA SELinux User's and Administrator's Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/)
- [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
