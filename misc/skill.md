# Lab App Deployment Script Skill

## Overview

This skill guides the creation of deployment scripts for the `vdarkobar/lab` repository. All scripts follow consistent patterns for Debian 13 (Trixie) servers in Proxmox VE lab environments.

**Repository**: https://github.com/vdarkobar/lab  
**Target OS**: Debian 13 (Trixie), also compatible with Debian 12 (Bookworm)  
**Execution Context**: Non-root user with sudo privileges  
**Deployment Target**: VMs or LXC containers on Proxmox VE (NEVER on PVE host itself)

---

## Repository Conventions

### File Placement and Naming

- App installers live in: `apps/<app>.sh`
- Server base scripts live in: `server/<name>.sh`
- Use a lowercase script ID for filenames and log names (e.g., `cloudflared`, `npm-docker`)

### Script Metadata (Mandatory)

At top of every script:
```bash
readonly SCRIPT_VERSION="X.Y.Z"
readonly SCRIPT_NAME="<app-id>"  # lowercase, matches filename without .sh
```

---

## Target Environment Details

### Proxmox VE Context

Scripts run inside VMs or LXC containers managed by Proxmox VE, NOT on the PVE host itself.

### VM Environment (Debian 13 Cloud Image)

VMs are typically created from Debian 13 cloud images with cloud-init.

**Available by default:**
- `systemd` (full init system, PID 1)
- `systemd-resolved` (DNS resolution)
- `cloud-init` (runs on first boot)
- `openssh-server`
- `apt` package manager
- Basic coreutils
- Full kernel access
- All sysctls writable
- UFW works normally

**Typically NOT available (must install):**
- `curl`, `wget` (minimal cloud images)
- `sudo` (user may need to be added to sudo group)
- `ufw`, `fail2ban`
- `vim`, `nano`
- `git`, build tools
- `docker`

### LXC Environment (Debian 13 Container Template)

**Constraints (unprivileged LXC):**
- Limited `/proc` and `/sys` access
- Cannot load kernel modules
- Some sysctls are read-only
- `systemd-detect-virt` returns `lxc`

### VM vs LXC Compatibility Matrix

| Feature | VM | LXC (Unprivileged) | LXC (Privileged) |
|---------|----|--------------------|------------------|
| UFW Firewall | ✓ Works | ✓ Works | ✓ Works |
| Docker | ✓ Works | ✓ With nesting | ✓ Works |
| iptables | ✓ Works | ⚠ Limited | ✓ Works |
| Kernel modules | ✓ Can load | ✗ Cannot | ✗ Cannot |
| systemd services | ✓ Full | ✓ Full | ✓ Full |
| apt packages | ✓ Works | ✓ Works | ✓ Works |

**IMPORTANT**: Do NOT add special LXC detection logic to skip or modify firewall handling. Scripts should attempt UFW operations uniformly and handle failures gracefully regardless of environment type.

---

## Command-Line Interface Contract (Standard)

Every app script MUST support:

| Command | Description |
|---------|-------------|
| `--help` / `-h` | Print usage and exit 0 |
| `--status` | Show service/app status + access info |
| `--logs [N]` | Show logs (default 50 lines) |
| `--configure` | Re-run config prompts / token setup (optional but recommended) |
| `--uninstall` | Remove app (safe + interactive unless silent) |
| *(no args)* | Install (default action) |
| `--version` / `-v` | Print version and exit 0 |

### Non-Interactive Controls (Environment Variables)

Scripts are driven by app-prefixed environment variables:

```bash
<APP>_SILENT=true        # Non-interactive mode (no prompts, safe defaults)
<APP>_SKIP_UFW=true      # Skip firewall changes
<APP>_PORT=...           # Override default port (if applicable)
```

---

## Mandatory Safety Checks

### Refuse Proxmox Host Execution (Mandatory)

```bash
if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
    die "This script must not run on the Proxmox VE host. Run inside a VM or LXC."
fi
```

### Refuse Root Execution (Mandatory)

The script MUST exit if run as root. It must instruct the user to run it as a regular user and rely on sudo internally.

### Sudo Presence + Privileges (Mandatory)

Do not assume sudo exists on minimal images. Check early, before any logging:

```bash
# Early check: Verify sudo is available before we do anything
if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo is not installed or not in PATH" >&2
    echo "This script requires sudo. Please install it first:" >&2
    echo "  apt update && apt install sudo" >&2
    exit 1
fi

# Verify user has sudo access before creating log file
if [[ ${EUID} -eq 0 ]]; then
    echo "ERROR: This script must NOT be run as root!" >&2
    echo "Run as a regular user with sudo privileges:" >&2
    echo "  ./$(basename "$0")" >&2
    exit 1
fi

if ! sudo -v 2>/dev/null; then
    echo "ERROR: Current user $(whoami) does not have sudo privileges" >&2
    echo "Please add user to sudo group:" >&2
    echo "  usermod -aG sudo $(whoami)" >&2
    echo "Then logout and login again" >&2
    exit 1
fi
```

### Target Environment Notes (VM vs LXC)

- `systemd` is required; scripts should refuse non-systemd environments

---

## Standardized Components (Copy Verbatim)

These components MUST be identical across all app scripts.

### Terminal Formatting (Identical Across Scripts)

```bash
#############################################################################
# Terminal Formatting (embedded - no external dependency)                   #
#############################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_CYAN=$(tput setaf 6)
    readonly C_WHITE=$(tput setaf 7)
    
    readonly C_BRIGHT_GREEN=$(tput setaf 10 2>/dev/null || tput setaf 2)
    readonly C_BRIGHT_RED=$(tput setaf 9 2>/dev/null || tput setaf 1)
    readonly C_BRIGHT_YELLOW=$(tput setaf 11 2>/dev/null || tput setaf 3)
    readonly C_BRIGHT_BLUE=$(tput setaf 12 2>/dev/null || tput setaf 4)
else
    COLORS_SUPPORTED=false
    readonly C_RESET=""
    readonly C_BOLD=""
    readonly C_DIM=""
    readonly C_RED=""
    readonly C_GREEN=""
    readonly C_YELLOW=""
    readonly C_BLUE=""
    readonly C_CYAN=""
    readonly C_WHITE=""
    readonly C_BRIGHT_GREEN=""
    readonly C_BRIGHT_RED=""
    readonly C_BRIGHT_YELLOW=""
    readonly C_BRIGHT_BLUE=""
fi

# Unicode symbols (with ASCII fallbacks)
if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SYMBOL_SUCCESS="✓"
    readonly SYMBOL_ERROR="✗"
    readonly SYMBOL_WARNING="⚠"
    readonly SYMBOL_INFO="ℹ"
    readonly SYMBOL_ARROW="→"
    readonly SYMBOL_BULLET="•"
else
    readonly SYMBOL_SUCCESS="+"
    readonly SYMBOL_ERROR="x"
    readonly SYMBOL_WARNING="!"
    readonly SYMBOL_INFO="i"
    readonly SYMBOL_ARROW=">"
    readonly SYMBOL_BULLET="*"
fi
```

### Output Functions (Identical Across Scripts)

```bash
#############################################################################
# Output Functions                                                          #
#############################################################################

print_success() {
    local msg="$*"
    echo "${C_BRIGHT_GREEN}${C_BOLD}${SYMBOL_SUCCESS}${C_RESET} ${C_GREEN}${msg}${C_RESET}"
}

print_error() {
    local msg="$*"
    echo "${C_BRIGHT_RED}${C_BOLD}${SYMBOL_ERROR}${C_RESET} ${C_RED}${msg}${C_RESET}" >&2
}

print_warning() {
    local msg="$*"
    echo "${C_BRIGHT_YELLOW}${C_BOLD}${SYMBOL_WARNING}${C_RESET} ${C_YELLOW}${msg}${C_RESET}"
}

print_info() {
    local msg="$*"
    echo "${C_BRIGHT_BLUE}${C_BOLD}${SYMBOL_INFO}${C_RESET} ${C_BLUE}${msg}${C_RESET}"
}

print_step() {
    local msg="$*"
    echo "${C_CYAN}${C_BOLD}${SYMBOL_ARROW}${C_RESET} ${C_CYAN}${msg}${C_RESET}"
}

print_header() {
    local msg="$*"
    echo
    echo "${C_BOLD}${C_CYAN}━━━ ${msg} ━━━${C_RESET}"
}

print_subheader() {
    local msg="$*"
    echo "${C_DIM}${SYMBOL_BULLET} ${msg}${C_RESET}"
}

print_kv() {
    local key="$1"
    local value="$2"
    printf "${C_CYAN}%-20s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$key:" "$value"
}
```

### Visual Elements (Identical Across Scripts)

```bash
#############################################################################
# Visual Elements                                                           #
#############################################################################

draw_box() {
    local text="$1"
    local width=68
    local padding=$(( (width - ${#text} - 2) / 2 ))
    
    echo "${C_CYAN}"
    echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
    printf "║%*s%s%*s║\n" $padding "" "$text" $padding ""
    echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
    echo "${C_RESET}"
}

draw_separator() {
    echo "${C_DIM}$(printf '─%.0s' $(seq 1 70))${C_RESET}"
}
```

### Samba Configuration Template (For Future Samba Scripts)

Security-hardened smb.conf template with SMB3 encryption:

```bash
cat > "$temp_config" << EOF
#======================= Global Settings =======================
# Managed by lab/samba.sh - do not edit manually

[global]
   workgroup = ${WORKGROUP}
   server string = Samba File Server %v
   ${netbios_config}
   
   security = user
   passdb backend = tdbsam
   map to guest = never
   
   server min protocol = ${MIN_PROTOCOL}
   client min protocol = ${MIN_PROTOCOL}
   server signing = ${SERVER_SIGNING}
   client signing = ${SERVER_SIGNING}
   smb encrypt = ${SMB_ENCRYPTION}
   server smb3 encryption algorithms = AES-256-GCM, AES-256-CCM
   server smb3 signing algorithms = AES-256-GMAC
   ntlm auth = ntlmv2-only
   
   log file = /var/log/samba/log.%m
   max log size = 5000
   log level = 1
   logging = syslog@1 file
   
   load printers = no
   printcap name = /dev/null
   disable spoolss = yes
   show add printer wizard = no
   
   dns proxy = no
   
   unix extensions = no
   follow symlinks = no
   wide links = no

#======================= Share Definitions =======================

[${SHARE_NAME}]
   comment = Shared Directory
   path = ${SHARE_PATH}
   browseable = yes
   writable = yes
   guest ok = no
   valid users = @${SAMBA_GROUP}
   create mask = 0664
   directory mask = 2775
   force group = ${SAMBA_GROUP}
   
   oplocks = yes
   level2 oplocks = yes
   
   vfs objects = acl_xattr
   inherit acls = yes
   inherit permissions = yes
   ea support = yes
   store dos attributes = yes
   map archive = no
   map hidden = no
   map readonly = no
   map system = no
EOF
```

**Variables used:**
- `${WORKGROUP}` — SMB workgroup (default: WORKGROUP)
- `${netbios_config}` — Either `netbios name = ${SERVER_NAME}` or `# NetBIOS disabled`
- `${MIN_PROTOCOL}` — Minimum SMB version (default: SMB3)
- `${SERVER_SIGNING}` — Signing requirement (hardcoded: mandatory)
- `${SMB_ENCRYPTION}` — Encryption requirement (hardcoded: mandatory)
- `${SHARE_NAME}` — Share name visible to clients
- `${SHARE_PATH}` — Filesystem path for shared files
- `${SAMBA_GROUP}` — Linux group with access

### Unbound DNS Configuration Template (For Future DNS Scripts)

Security-hardened unbound.conf template with DNS-over-TLS upstream forwarding, DNSSEC validation, and local authoritative zones:

```bash
cat > "$temp_config" << EOF
# Unbound configuration file for Debian.
#
# See the unbound.conf(5) man page.
#
# See /usr/share/doc/unbound/examples/unbound.conf for a commented
# reference config file.
#
# The following line includes additional configuration files from the
# /etc/unbound/unbound.conf.d directory.

include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"

# ============================================================================
#                         Static DNS host records
# ----------------------------------------------------------------------------
# All local A and PTR records are maintained in:
#
#             /etc/unbound/unbound.conf.d/30-static-hosts.conf
#
# Do NOT add local-data entries in this file.
# Modify the file above instead.
#
# ============================================================================
# Authoritative, validating, recursive caching DNS with DNS-Over-TLS support
# ============================================================================
server:

    # ------------------------------------------------------------------------
    # Runtime environment
    # ------------------------------------------------------------------------

    # Limit permissions
    username: "unbound"

    # Working directory
    directory: "/etc/unbound"

    # Chain of Trust (system CA bundle for DNS-over-TLS upstream validation)
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt


    # ------------------------------------------------------------------------
    # Privacy
    # ------------------------------------------------------------------------

    # Send minimal amount of information to upstream servers to enhance privacy
    qname-minimisation: yes


    # ------------------------------------------------------------------------
    # Centralized logging
    # ------------------------------------------------------------------------

    use-syslog: yes
    # Increase to get more logging.
    verbosity: 1
    # For every user query that fails a line is printed
    val-log-level: 1
    # Logging of DNS queries
    log-queries: no


    # ------------------------------------------------------------------------
    # Root trust and DNSSEC
    # ------------------------------------------------------------------------

    # Root hints (note: unused when forwarding "."; kept as reference/fallback)
    root-hints: /usr/share/dns/root.hints
    harden-dnssec-stripped: yes


    # ------------------------------------------------------------------------
    # Network interfaces
    # ------------------------------------------------------------------------

    # Listen on all interfaces, answer queries from allowed subnets (ACLs below)
    interface: 0.0.0.0
    interface: ::0

    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes


    # ------------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------------

    # Standard DNS
    port: 53

    # Local DNS-over-TLS port (for clients to unbound, only useful if you configure server cert/key)
    # tls-port: 853


    # ------------------------------------------------------------------------
    # Upstream communication
    # ------------------------------------------------------------------------

    # Use TCP connections for all upstream communications
    # when using DNS-over-TLS, otherwise default (no)
    tcp-upstream: yes


    # ------------------------------------------------------------------------
    # Cache behaviour
    # ------------------------------------------------------------------------

    # Perform prefetching of almost expired DNS cache entries.
    prefetch: yes

    # Serve expired cache entries if upstream DNS is temporarily unreachable
    # (RFC 8767 – improves resilience during ISP / upstream outages)
    serve-expired: yes
    serve-expired-ttl: 3600

    # Enable DNS cache (TTL limits)
    cache-max-ttl: 14400
    cache-min-ttl: 1200


    # ------------------------------------------------------------------------
    # Unbound privacy and security
    # ------------------------------------------------------------------------

    aggressive-nsec: yes
    hide-identity: yes
    hide-version: yes
    use-caps-for-id: yes


    # =========================================================================
    # Define Private Network and Access Control Lists (ACLs)
    # =========================================================================

    # Define private address ranges (RFC1918/ULA/link-local)
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10


    # ------------------------------------------------------------------------
    # Control which clients are allowed to make (recursive) queries
    # ------------------------------------------------------------------------

    # Administrative access (localhost only)
    access-control: 127.0.0.1/32 allow_snoop
    access-control: ::1/128 allow_snoop

    # Normal DNS access from loopback
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow


    # ------------------------------------------------------------------------
    # UniFi networks (VLAN's)
    # ------------------------------------------------------------------------

    # data located > /etc/unbound/unbound.conf.d/vlans.conf


    # ------------------------------------------------------------------------
    # Default deny (critical)
    # ------------------------------------------------------------------------

    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse


    # =========================================================================
    # Setup Local Domain
    # =========================================================================

    # Internal DNS namespace
    private-domain: "${DOMAIN_NAME}"

    # Local authoritative zone
    local-zone: "${DOMAIN_NAME}." static

    # A Records Local
    
    # data located > /etc/unbound/unbound.conf.d/30-static-hosts.conf

    # =========================================================================
    # Reverse DNS (per VLAN / subnet)
    # =========================================================================
    # Define reverse zones for each VLAN subnet so PTR answers are authoritative.
    # PTR records are defined using local-data-ptr (simple and readable).

    # Reverse zones for /24 networks *(don't change: in-addr.arpa.)

    # data located in > /etc/unbound/unbound.conf.d/30-static-hosts.conf

    # Reverse Lookups Local (PTR records)
    
    # data located in > /etc/unbound/unbound.conf.d/30-static-hosts.conf


    # =========================================================================
    # Unbound Performance Tuning and Tweak
    # =========================================================================

    num-threads: ${NUM_THREADS}
    msg-cache-slabs: ${CACHE_SLABS}
    rrset-cache-slabs: ${CACHE_SLABS}
    infra-cache-slabs: ${CACHE_SLABS}
    key-cache-slabs: ${CACHE_SLABS}
    rrset-cache-size: ${RRSET_CACHE_SIZE}
    msg-cache-size: ${MSG_CACHE_SIZE}
    so-rcvbuf: ${SO_RCVBUF}


# ============================================================================
# Use DNS over TLS (Upstream Forwarding)
# ============================================================================
forward-zone:
    name: "."
    forward-tls-upstream: yes

    # Quad9 DNS
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-addr: 2620:fe::11@853#dns.quad9.net
    forward-addr: 2620:fe::fe:11@853#dns.quad9.net

    # Quad9 DNS (Malware Blocking + Privacy) slower
    # forward-addr: 9.9.9.11@853#dns11.quad9.net
    # forward-addr: 149.112.112.11@853#dns11.quad9.net
    # forward-addr: 2620:fe::11@853#dns11.quad9.net
    # forward-addr: 2620:fe::fe:11@853#dns11.quad9.net

    # Cloudflare DNS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com

    # Cloudflare DNS (Malware Blocking) slower
    # forward-addr: 1.1.1.2@853#cloudflare-dns.com
    # forward-addr: 2606:4700:4700::1112@853#cloudflare-dns.com
    # forward-addr: 1.0.0.2@853#cloudflare-dns.com
    # forward-addr: 2606:4700:4700::1002#cloudflare-dns.com

    # Google
    # forward-addr: 8.8.8.8@853#dns.google
    # forward-addr: 8.8.4.4@853#dns.google
    # forward-addr: 2001:4860:4860::8888@853#dns.google
    # forward-addr: 2001:4860:4860::8844@853#dns.google
EOF
```

**Variables used:**
- `${DOMAIN_NAME}` — Internal DNS domain (e.g., home.arpa, lab.local)
- `${NUM_THREADS}` — Number of worker threads (default: 4, match CPU cores)
- `${CACHE_SLABS}` — Cache slab count, should be power of 2 ≥ NUM_THREADS (default: 8)
- `${RRSET_CACHE_SIZE}` — RRset cache size (default: 256m)
- `${MSG_CACHE_SIZE}` — Message cache size (default: 128m)
- `${SO_RCVBUF}` — Socket receive buffer size (default: 8m)

**Companion files** (referenced via `include-toplevel`):
- `/etc/unbound/unbound.conf.d/vlans.conf` — VLAN-specific ACL rules
- `/etc/unbound/unbound.conf.d/30-static-hosts.conf` — Local DNS records (A and PTR)

**Key features:**
- DNS-over-TLS to upstream resolvers (Quad9 + Cloudflare by default)
- DNSSEC validation with `harden-dnssec-stripped`
- QNAME minimisation for upstream privacy
- Stale cache serving (RFC 8767) for resilience
- Default-deny ACLs (must explicitly allow client subnets)
- Local authoritative zone for internal names

### Drop-in Configuration Templates (Copy Verbatim)

Drop-in files override vendor configs and survive package upgrades. Use numbered prefixes to control load order.

**Naming convention**: `99-lab-hardening.conf` (or `52lab-...` for apt)

**Common pattern**:
```bash
local dropin_file="/etc/<service>/<dir>/99-lab-hardening.conf"
sudo mkdir -p "$(dirname "$dropin_file")"
sudo tee "$dropin_file" > /dev/null << 'EOF'
# Managed by lab/<script>.sh - do not edit manually
...config...
EOF
log SUCCESS "Drop-in config created: $dropin_file"
```

#### Unattended-Upgrades Drop-in

**File**: `/etc/apt/apt.conf.d/52lab-unattended-upgrades`

```bash
configure_unattended_upgrades() {
    print_header "Configuring Automatic Security Updates"
    
    # Enable unattended-upgrades
    print_step "Enabling unattended-upgrades..."
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | \
        sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1
    
    # Use drop-in file instead of modifying vendor config (survives package upgrades)
    local dropin_file="/etc/apt/apt.conf.d/52lab-unattended-upgrades"
    
    print_step "Creating unattended-upgrades drop-in configuration..."
    
    sudo tee "$dropin_file" > /dev/null << 'EOF'
// Managed by lab/hardening.sh - do not edit manually
// Overrides settings in 50unattended-upgrades

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    
    log SUCCESS "Unattended-upgrades drop-in config created: $dropin_file"
    print_info "System will automatically reboot at 02:00 if needed"
    echo
}
```

#### Fail2Ban Drop-in

**File**: `/etc/fail2ban/jail.d/99-lab-hardening.conf`

```bash
configure_fail2ban() {
    print_header "Configuring Fail2Ban Intrusion Prevention"
    
    if ! command -v fail2ban-server >/dev/null 2>&1; then
        die "Fail2Ban is not installed"
    fi
    
    # Use drop-in config instead of editing jail.local
    local dropin_dir="/etc/fail2ban/jail.d"
    local dropin_file="${dropin_dir}/99-lab-hardening.conf"
    
    print_step "Creating Fail2Ban drop-in configuration..."
    sudo mkdir -p "$dropin_dir"
    
    sudo tee "$dropin_file" > /dev/null << 'EOF'
# Managed by lab/hardening.sh - do not edit manually
# User customizations belong in jail.local or other jail.d/ files

[DEFAULT]
# Use systemd backend (fixes Debian bug with auto backend)
backend = systemd

# Stricter limits: 3 attempts, 15 minute ban
bantime = 15m
maxretry = 3
findtime = 10m

[sshd]
enabled = true
EOF
    
    log SUCCESS "Fail2Ban drop-in config created: $dropin_file"
    
    # Restart Fail2Ban to apply changes
    print_step "Restarting Fail2Ban service..."
    if sudo systemctl restart fail2ban; then
        log SUCCESS "Fail2Ban configured and running"
    else
        print_warning "Fail2Ban restart failed, may need manual intervention"
    fi
    echo
}
```

#### SSH Hardening Drop-in

**File**: `/etc/ssh/sshd_config.d/99-lab-hardening.conf`

```bash
configure_sshd() {
    print_header "Hardening SSH Configuration"
    
    local sshd_config="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="${dropin_dir}/99-lab-hardening.conf"
    local backup="/tmp/sshd_lab_backup_$$"
    local user=$(whoami)
    
    # Ensure drop-in directory exists
    sudo mkdir -p "$dropin_dir"
    
    # Check if Include directive exists in main config
    print_step "Checking SSH Include directive..."
    if ! grep -qE '^[[:space:]]*Include.*/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
        print_warning "Adding Include directive to $sshd_config"
        local include_line="Include /etc/ssh/sshd_config.d/*.conf"
        local tmpfile="${sshd_config}.labtmp"
        { printf '%s\n' "$include_line"; sudo cat "$sshd_config"; } | sudo tee "$tmpfile" > /dev/null
        sudo mv "$tmpfile" "$sshd_config"
    else
        print_success "Include directive already present"
    fi
    
    # Backup current drop-in if exists
    [[ -f "$dropin_file" ]] && sudo cp "$dropin_file" "$backup"
    
    print_step "Creating SSH hardening drop-in configuration..."
    
    sudo tee "$dropin_file" > /dev/null << EOF
# Managed by lab/hardening.sh - do not edit manually
# SSH security hardening settings

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM no

# Security limits
MaxAuthTries 3
MaxSessions 2
X11Forwarding no
StrictModes yes
IgnoreRhosts yes
GSSAPIAuthentication no

# Connection timeouts
ClientAliveInterval 300
ClientAliveCountMax 2

# Rate limiting
MaxStartups 10:30:60
LoginGraceTime 30

# Security hardening
PermitUserEnvironment no
LogLevel VERBOSE

# Allowed ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Restrict SSH access to current user
AllowUsers ${user}
EOF
    
    log SUCCESS "SSH drop-in config created: $dropin_file"
    
    # Validate SSH configuration before restart
    print_step "Validating SSH configuration..."
    local validation_output
    if ! validation_output=$(sudo sshd -t -f "$sshd_config" 2>&1); then
        print_error "SSH configuration has errors, rolling back..."
        print_error "Validation error: $validation_output"
        if [[ -f "$backup" ]]; then
            sudo mv "$backup" "$dropin_file"
        else
            sudo rm -f "$dropin_file"
        fi
        sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
        die "SSH configuration validation failed"
    fi
    log SUCCESS "SSH configuration is valid"
    
    # Restart SSH service
    print_step "Restarting SSH service..."
    local svc=""
    if systemctl list-unit-files ssh.service &>/dev/null; then
        svc="ssh"
    elif systemctl list-unit-files sshd.service &>/dev/null; then
        svc="sshd"
    fi
    
    if [[ -n "$svc" ]] && sudo systemctl restart "$svc"; then
        sleep 1
        if systemctl is-active --quiet "$svc"; then
            log SUCCESS "SSH service restarted and running"
        else
            print_error "SSH service not active after restart, rolling back..."
            if [[ -f "$backup" ]]; then
                sudo mv "$backup" "$dropin_file"
            else
                sudo rm -f "$dropin_file"
            fi
            sudo systemctl restart "$svc" || true
            die "SSH service failed after restart"
        fi
    else
        print_warning "Failed to restart SSH service"
    fi
    
    rm -f "$backup"
    echo
}
```

**Note**: SSH drop-in uses unquoted heredoc (`<< EOF`) because `${user}` must be expanded.

#### Sysctl Hardening Drop-in

**File**: `/etc/sysctl.d/99-lab-hardening.conf`

```bash
configure_sysctl() {
    print_header "Applying Network Security Settings"
    
    local sysctl_file="/etc/sysctl.d/99-lab-hardening.conf"
    
    print_step "Creating sysctl drop-in configuration..."
    
    sudo tee "$sysctl_file" > /dev/null << 'EOF'
# Managed by lab/hardening.sh - do not edit manually
# Network security hardening settings

# Note: ip_forward not disabled here (breaks Docker/WireGuard)
# Add manually if this server will never need forwarding

# Reverse path filtering
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
EOF

    log SUCCESS "Sysctl drop-in config created: $sysctl_file"

    # Apply settings (may fail in unprivileged containers)
    print_step "Applying sysctl settings..."
    if sudo sysctl -p "$sysctl_file" >/dev/null 2>&1; then
        log SUCCESS "Network security settings applied"
    else
        print_warning "Some settings failed (expected in unprivileged containers)"
        sudo sysctl -p "$sysctl_file" 2>&1 | grep -i "permission denied" | \
        while read -r line; do
            print_subheader "Denied: $(echo "$line" | awk '{print $2}')"
        done || true
    fi
    echo
}
```

### Server Setup Patterns (Copy Verbatim)

These patterns are used for initial server configuration. Useful for hardening scripts and base system setup.

#### Backup Directory and File Backup

```bash
readonly BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"

create_backup_dir() {
    if ! sudo mkdir -p "$BACKUP_DIR"; then
        die "Failed to create backup directory: $BACKUP_DIR"
    fi
    # Give ownership to current user so they can access backups
    sudo chown "$(whoami):$(id -gn)" "$BACKUP_DIR"
    log SUCCESS "Backup directory created"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="$BACKUP_DIR$(dirname "$file")"
        sudo mkdir -p "$backup_path"
        sudo cp -a "$file" "$backup_path/" || log WARN "Failed to backup $file"
        log INFO "Backed up: ${C_DIM}${file}${C_RESET}"
    fi
}
```

#### Network Detection

Detects hostname, domain, and IP address with multiple fallback methods:

```bash
detect_network_info() {
    print_header "Network Configuration"
    
    # Get hostname
    HOSTNAME=$(hostname -s) || HOSTNAME="unknown"
    
    # Detect domain name (resolvectl first, then resolv.conf)
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved; then
        DOMAIN_LOCAL=$(resolvectl status | awk '/DNS Domain:/ {print $3; exit}' | head -n1)
    fi
    
    # Fallback to /etc/resolv.conf
    if [[ -z "${DOMAIN_LOCAL:-}" ]]; then
        DOMAIN_LOCAL=$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    fi
    
    # Final fallback
    DOMAIN_LOCAL=${DOMAIN_LOCAL:-"local"}
    
    # Detect primary IP address
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    # Fallback IP detection
    if [[ -z "$LOCAL_IP" ]] || [[ "$LOCAL_IP" == "127.0.0.1" ]]; then
        LOCAL_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    fi
    
    # Final fallback
    LOCAL_IP=${LOCAL_IP:-"127.0.0.1"}
    
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "FQDN" "$HOSTNAME.$DOMAIN_LOCAL"
    echo
}
```

**Variables set:**
- `HOSTNAME` — Short hostname (e.g., `server1`)
- `DOMAIN_LOCAL` — Domain name (e.g., `local` or `home.lan`)
- `LOCAL_IP` — Primary IP address

#### Hosts File Configuration

Configures `/etc/hosts` with proper FQDN format. Requires `detect_network_info()` to be called first.

```bash
configure_hosts() {
    print_header "Configuring System Hosts File"
    
    backup_file "/etc/hosts"
    
    # Create new hosts file
    local temp_hosts=$(mktemp)
    
    {
        echo "127.0.0.1       localhost"
        echo "::1             localhost ip6-localhost ip6-loopback"
        echo "ff02::1         ip6-allnodes"
        echo "ff02::2         ip6-allrouters"
        echo ""
        echo "# Host configuration (FQDN first, then shortname)"
        echo "$LOCAL_IP       $HOSTNAME.$DOMAIN_LOCAL $HOSTNAME"
        echo ""
        echo "# Existing entries (if any)"
        grep -v -E '^(127\.0\.0\.1|::1|ff02::|#.*|^$)' /etc/hosts 2>/dev/null | \
        grep -v "$HOSTNAME" || true
    } > "$temp_hosts"
    
    if sudo mv "$temp_hosts" /etc/hosts; then
        sudo chmod 644 /etc/hosts
        log SUCCESS "Hosts file configured"
    else
        die "Failed to update /etc/hosts"
    fi
    echo
}
```

**Hosts file format:**
```
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# Host configuration (FQDN first, then shortname)
192.168.1.100       server1.local server1

# Existing entries (if any)
...
```

**Key points:**
- FQDN comes before shortname (required by many services)
- Preserves existing custom entries
- Backs up original file before modification

---

## Logging Contract (Standard)

### Log Location and Naming (Mandatory)

```bash
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"
```

### log(), die(), setup_logging() (Mandatory)

```bash
#############################################################################
# Logging                                                                   #
#############################################################################

log() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Write plain text to log file (strip ANSI color codes)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" || -w "$(dirname "${LOG_FILE:-/tmp}")" ]]; then
        echo "[$timestamp] [$level] $message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null || true
    fi

    # Display to console with formatting
    case "$level" in
        SUCCESS) print_success "$message" ;;
        ERROR)   print_error "$message" ;;
        WARN)    print_warning "$message" ;;
        INFO)    print_info "$message" ;;
        STEP)    print_step "$message" ;;
        *)       echo "$message" ;;
    esac
}

die() {
    local msg="$*"
    log ERROR "$msg"
    exit 1
}

setup_logging() {
    # Note: sudo existence check should be done BEFORE calling this function
    
    # Create log directory with sudo
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
    fi

    # Create log file and set ownership to current user
    sudo touch "$LOG_FILE" 2>/dev/null || true
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE" 2>/dev/null || true
    sudo chmod 644 "$LOG_FILE" 2>/dev/null || true

    log INFO "=== ${SCRIPT_NAME} Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
}
```

### ERR Trap (Recommended)

After `print_error` exists, add the ERR trap for debugging:

```bash
# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR
```

---

## Cleanup Contract (Standard)

Track services stopped during install and restore them on exit:

```bash
# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restarted unattended-upgrades service"
        fi
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM
```

---

## Helper Functions (Standard)

```bash
#############################################################################
# Helper Functions                                                          #
#############################################################################

is_silent() {
    [[ "${SILENT:-false}" == "true" ]]
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

# Uses ip route first, hostname -I as fallback
get_local_ip() {
    local ip_address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [[ -z "$ip_address" ]] && ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip_address=${ip_address:-"localhost"}
    echo "$ip_address"
}
```

---

## Interactive Input Patterns (Templates)

These patterns ensure consistent user interaction across scripts. Copy and adapt as needed.

### Yes/No Confirmation

Used for: Installation start, uninstall confirmation, dangerous actions.

```bash
while true; do
    echo -n "${C_BOLD}${C_CYAN}Proceed with installation? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
    read -r choice
    choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
    
    case "$choice" in
        yes|y)
            log INFO "User confirmed"
            break
            ;;
        no|n)
            print_info "Cancelled by user"
            exit 0
            ;;
        *)
            print_error "Invalid input. Please enter 'yes' or 'no'"
            ;;
    esac
done
```

### Yes/No with Default

Used for: Optional steps where a default makes sense.

```bash
echo -ne "${C_CYAN}Create a user now? (yes/no) [default: yes]: ${C_RESET}"
read -r response
response="${response:-yes}"

case "${response,,}" in
    yes|y)
        # proceed
        ;;
    no|n)
        print_info "Skipping"
        return 0
        ;;
    *)
        print_error "Please answer yes or no"
        ;;
esac
```

### Input with Default

Used for: Configuration values with sensible defaults.

```bash
echo
print_info "Enter the directory path for shared files"
echo -ne "${C_CYAN}Share path [default: /srv/samba/Data]: ${C_RESET}"
read -r input
SHARE_PATH="${input:-/srv/samba/Data}"
print_success "Share path: $SHARE_PATH"
```

### Input with Validation

Used for: Values that must match a specific format.

```bash
while true; do
    echo -ne "${C_CYAN}Share name [default: Share]: ${C_RESET}"
    read -r input
    SHARE_NAME="${input:-Share}"
    
    # Validate: letters, numbers, underscore, dash only
    if [[ "$SHARE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        break
    else
        print_error "Share name can only contain letters, numbers, underscore, and dash"
    fi
done
print_success "Share name: $SHARE_NAME"
```

### Username Input with Validation

Used for: System/application usernames.

```bash
while true; do
    echo -ne "${C_CYAN}Username: ${C_RESET}"
    read -r username
    
    if [[ -z "$username" ]]; then
        print_error "Username cannot be empty"
        continue
    fi
    
    # Validate: lowercase, starts with letter/underscore
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        break
    else
        print_error "Invalid username format (lowercase letters, numbers, underscore, dash)"
    fi
done
```

### Port Input with Validation

Used for: Network ports within allowed range.

```bash
while true; do
    echo -ne "${C_CYAN}Admin Port: ${C_RESET}"
    read -r port
    
    # Validate port number range
    if [[ "$port" =~ ^[0-9]+$ ]] && \
       [[ "$port" -ge 49152 ]] && \
       [[ "$port" -le 65535 ]]; then
        
        # Check if port is in use
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            print_warning "Port $port is already in use"
            continue
        fi
        
        print_success "Port selected: $port"
        break
    else
        print_error "Invalid port. Enter a number between 49152 and 65535"
    fi
done
```

### Secret/Token Input

Used for: API tokens, passwords that shouldn't be displayed.

```bash
while true; do
    echo
    print_info "Paste your tunnel token (input hidden for security)"
    echo -ne "${C_CYAN}Token: ${C_RESET}"
    read -r TOKEN
    
    if [[ -z "$TOKEN" ]]; then
        print_error "Token cannot be empty"
        continue
    fi
    
    # Basic format validation (adjust regex as needed)
    if [[ ! "$TOKEN" =~ ^eyJ ]]; then
        print_warning "Token format looks unusual (should start with 'eyJ')"
        echo -n "${C_CYAN}Continue anyway? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            continue
        fi
    fi
    
    # Confirm
    echo
    print_info "Token received (${#TOKEN} characters)"
    echo -n "${C_CYAN}Is this correct? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
    read -r confirm
    if [[ "$confirm" =~ ^[Yy] ]] || [[ -z "$confirm" ]]; then
        break
    fi
done
log INFO "Token configured (${#TOKEN} chars)"
```

### Create Another Loop

Used for: Repeating an action (create users, add shares, etc.).

```bash
while true; do
    # ... do the thing (create user, etc.) ...
    
    echo
    echo -ne "${C_CYAN}Create another? (yes/no) [default: no]: ${C_RESET}"
    read -r create_another
    create_another="${create_another:-no}"
    
    if [[ ! "${create_another,,}" =~ ^(yes|y)$ ]]; then
        break
    fi
done
```

### System User Creation (Samba-style)

Used for: Creating Linux users for service authentication.

```bash
if id "$username" &>/dev/null; then
    print_warning "User '$username' already exists in the system"
    
    # Check if already in required group
    if id -nG "$username" | grep -qw "$APP_GROUP"; then
        print_info "User already in $APP_GROUP group"
    else
        print_step "Adding user to $APP_GROUP group..."
        sudo usermod -aG "$APP_GROUP" "$username"
    fi
else
    # Create system user (no home dir, no login shell)
    print_step "Creating system user: $username"
    if sudo useradd -M -s /usr/sbin/nologin -G "$APP_GROUP" "$username"; then
        print_success "System user created"
    else
        print_error "Failed to create system user"
        continue
    fi
fi

# Set application password (e.g., smbpasswd)
print_step "Setting password for: $username"
if sudo smbpasswd -a "$username"; then
    sudo smbpasswd -e "$username"
    log SUCCESS "User '$username' created and enabled"
else
    print_error "Failed to set password"
fi
```

### Skip Pattern for Silent Mode

Wrap interactive sections to support automation:

```bash
configure_interactive() {
    # Use environment variable if set, otherwise prompt
    if [[ -z "$SHARE_NAME" ]]; then
        if is_silent; then
            SHARE_NAME="Share"  # default for silent mode
        else
            # ... interactive prompt ...
        fi
    fi
    print_success "Share name: $SHARE_NAME"
}
```

---

## Pre-flight Checks (Standard)

Preflight MUST:
- Enforce non-root
- Verify sudo exists + privileges  
- Block PVE host
- Require systemctl (systemd)
- Detect OS from /etc/os-release and warn if non-Debian
- Validate internet connectivity using the best available tool (curl/wget/dev-tcp)

```bash
preflight_checks() {
    print_header "Pre-flight Checks"

    # CRITICAL: Enforce non-root execution
    if [[ ${EUID} -eq 0 ]]; then
        echo
        print_error "This script must NOT be run as root!"
        echo
        print_info "Correct usage:"
        echo "  ${C_CYAN}./$(basename "$0")${C_RESET}"
        echo
        print_info "The script will use sudo internally when needed."
        echo
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"

    # sudo must exist on minimal images
    if ! command -v sudo >/dev/null 2>&1; then
        echo
        print_error "sudo is not installed. This script requires sudo."
        echo
        print_info "Fix (run as root):"
        echo "  apt-get update && apt-get install -y sudo"
        echo "  usermod -aG sudo $(whoami)"
        echo "  # then logout/login"
        echo
        die "Execution blocked: sudo not installed"
    fi

    # Verify sudo access (may prompt)
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access (run as root):"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# then logout/login${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"

    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command_exists pveversion; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on Proxmox host"

    # Check for systemd (required)
    if ! command_exists systemctl; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    print_success "systemd available"

    # Check OS (warn if not Debian)
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${ID:-}" != "debian" ]]; then
            print_warning "Designed for Debian. Detected: ${ID:-unknown}"
        else
            print_success "Debian detected: ${VERSION:-unknown}"
        fi
    else
        print_warning "Cannot determine OS version (/etc/os-release missing)"
    fi

    # Check internet connectivity (multiple methods for minimal systems)
    print_step "Testing internet connectivity..."
    local internet_ok=false

    if command_exists curl; then
        if curl -s --max-time 5 --head https://deb.debian.org >/dev/null 2>&1; then
            print_success "Internet connectivity verified (curl)"
            internet_ok=true
        fi
    fi

    if [[ "$internet_ok" == false ]] && command_exists wget; then
        if wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
            print_success "Internet connectivity verified (wget)"
            internet_ok=true
        fi
    fi

    if [[ "$internet_ok" == false ]]; then
        # Bash built-in TCP check (no external tools)
        if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/deb.debian.org/80' 2>/dev/null; then
            print_success "Internet connectivity verified (dev/tcp)"
            internet_ok=true
        fi
    fi

    if [[ "$internet_ok" == false ]]; then
        print_warning "Could not verify internet with available tools"
        print_info "Will verify connectivity during package installation..."
    fi

    echo
}
```

---

## APT Lock Handling (Recommended)

Before package installs, stop unattended-upgrades (best-effort) and wait briefly for dpkg locks:

```bash
prepare_apt() {
    # Stop unattended-upgrades to avoid apt locks (best-effort)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi

    # Wait for dpkg lock (best-effort)
    local wait_count=0
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt/dpkg lock..."
        fi
        wait_count=$((wait_count + 1))
        sleep 2
        if [[ $wait_count -ge 60 ]]; then
            print_warning "Still waiting for apt lock (60s+) — continuing anyway"
            break
        fi
    done
}
```

---

## Port Availability Checks (Recommended for Services That Bind Ports)

If the app binds ports (80/443/custom), validate availability:

```bash
check_port_availability() {
    local ports=("$@")
    local ports_in_use=()
    
    print_step "Checking port availability..."
    
    if command_exists ss; then
        for port in "${ports[@]}"; do
            if ss -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    elif command_exists netstat; then
        for port in "${ports[@]}"; do
            if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
                ports_in_use+=("$port")
            fi
        done
    else
        print_warning "Cannot check ports (ss/netstat not available)"
        return 0
    fi
    
    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        print_warning "Ports already in use: ${ports_in_use[*]}"
        print_info "Ensure these ports are free before starting the service."
        return 1
    fi
    
    print_success "Required ports are available: ${ports[*]}"
    return 0
}
```

---

## APT + Dependency Management (Standard)

- Always `export DEBIAN_FRONTEND=noninteractive`
- Prefer `apt-get` over `apt`
- Install missing dependencies in one go; minimize repeated `apt-get update`

---

## Third-Party APT Repo Pattern (Standard When Needed)

When using external repos (Docker, Cloudflare, NodeSource, etc.):

1. Allow override env var for codename (e.g., `DOCKER_DIST`)
2. Detect codename via `/etc/os-release`
3. Probe the repo Release URL; fall back (usually bookworm)
4. Use keyring + signed-by in sources list

```bash
get_docker_codename() {
    # Check for manual override first
    local override_val="${DOCKER_DIST:-}"
    if [[ -n "$override_val" ]]; then
        echo "$override_val"
        return 0
    fi
    
    # Detect system codename from /etc/os-release
    local detected=""
    if [[ -f /etc/os-release ]]; then
        detected="$(grep '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    fi
    
    # Fallback to lsb_release if os-release didn't work
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "")"
    
    # Test if Docker repo exists for detected codename
    if [[ -n "$detected" ]]; then
        local test_url="https://download.docker.com/linux/debian/dists/${detected}/Release"
        if curl -sSf --head --max-time 5 "$test_url" >/dev/null 2>&1; then
            echo "$detected"
            return 0
        fi
        echo "INFO: Docker repo not found for '$detected', falling back to bookworm" >&2
    fi
    
    echo "bookworm"
}
```

---

## Config Write Contract (Mandatory When Writing Config Files)

Whenever the script writes a config file under `/etc`:

1. Write to a temp file (`mktemp`)
2. Compare with existing (`cmp -s`)
3. Backup existing only if changed
4. Install new file with correct perms
5. Validate (if validator exists)
6. Restart/reload only when needed

```bash
write_config_atomic() {
    local target_conf="$1"
    local temp_config
    temp_config=$(mktemp)
    
    # ... write file content into "$temp_config" ...
    
    local config_changed=false
    if [[ -f "$target_conf" ]]; then
        if ! cmp -s "$temp_config" "$target_conf"; then
            config_changed=true
            local backup="${target_conf}.backup.$(date +%Y%m%d_%H%M%S)"
            sudo cp "$target_conf" "$backup"
            log INFO "Config changed - backed up to: $backup"
        else
            log INFO "Configuration unchanged"
        fi
    else
        config_changed=true
        log INFO "Creating new configuration"
    fi

    if [[ "$config_changed" == "true" ]]; then
        sudo cp "$temp_config" "$target_conf"
        sudo chmod 644 "$target_conf"
        log SUCCESS "Configuration updated"
    fi

    rm -f "$temp_config"
    
    # Example validation hook (app-specific):
    # sudo testparm -s "$target_conf" >/dev/null 2>&1 || die "Validation failed"
    
    # Export for use in service restart logic
    export CONFIG_CHANGED="$config_changed"
}
```

---

## Firewall Contract (Standardized, App-Safe)

**CRITICAL**: App scripts MUST NOT enable UFW or change default policies. They may only add rules if UFW is already active.

### configure_firewall() Reference Implementation

Pattern for **inbound services** (web apps, SMB, etc.):

```bash
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        log INFO "Required ports: 80/tcp, 443/tcp, ${ADMIN_PORT}/tcp"
        echo
        return 0
    fi
    
    # Check if UFW is active
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        log INFO "UFW is not active - skipping firewall configuration"
        log INFO "To enable UFW manually: sudo ufw enable"
        echo
        return 0
    fi
    
    log SUCCESS "UFW is active"
    print_step "Adding firewall rules..."
    
    # Allow HTTP (port 80)
    if echo "$ufw_status" | grep -qE "80/tcp.*ALLOW"; then
        log SUCCESS "Port 80/tcp already allowed"
    else
        if sudo ufw allow 80/tcp comment "AppName HTTP" >/dev/null 2>&1; then
            log SUCCESS "Allowed port 80/tcp (AppName HTTP)"
        else
            if sudo ufw allow 80/tcp >/dev/null 2>&1; then
                log SUCCESS "Allowed port 80/tcp"
            else
                log WARN "Failed to add UFW rule for port 80/tcp"
            fi
        fi
    fi
    
    # Allow HTTPS (port 443)
    if echo "$ufw_status" | grep -qE "443/tcp.*ALLOW"; then
        log SUCCESS "Port 443/tcp already allowed"
    else
        if sudo ufw allow 443/tcp comment "AppName HTTPS" >/dev/null 2>&1; then
            log SUCCESS "Allowed port 443/tcp (AppName HTTPS)"
        else
            if sudo ufw allow 443/tcp >/dev/null 2>&1; then
                log SUCCESS "Allowed port 443/tcp"
            else
                log WARN "Failed to add UFW rule for port 443/tcp"
            fi
        fi
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}
```

Pattern for **outbound-only services** (cloudflared, etc.):

```bash
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status verbose 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        echo
        return 0
    fi
    
    # Check if UFW is active
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        log INFO "UFW is not active - skipping firewall configuration"
        log INFO "To enable UFW manually: sudo ufw enable"
        echo
        return 0
    fi
    
    log SUCCESS "UFW is active"
    log INFO "AppName uses outbound connections only - no inbound rules needed"
    
    # Check if outbound is blocked (rare, but possible)
    if echo "$ufw_status" | grep -q "deny (outgoing)"; then
        log STEP "Adding outbound rules for AppName..."
        
        if sudo ufw allow out 443/tcp comment "AppName HTTPS" >> "$LOG_FILE" 2>&1; then
            log SUCCESS "Allowed outbound 443/tcp (AppName HTTPS)"
        else
            log WARN "Failed to add outbound rule for 443/tcp"
        fi
        
        if sudo ufw allow out 7844/udp comment "AppName QUIC" >> "$LOG_FILE" 2>&1; then
            log SUCCESS "Allowed outbound 7844/udp (AppName QUIC)"
        else
            log WARN "Failed to add outbound rule for 7844/udp"
        fi
    else
        log SUCCESS "Default outbound policy allows AppName traffic"
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}
```

### Optional: Helper Function for Multiple Rules

When adding many rules, use a helper (from samba.sh):

```bash
# Helper: Add UFW rule with comment (fallback to without comment if unsupported)
add_ufw_rule() {
    local rule="$1"
    local comment="$2"
    
    # Check if rule already exists
    if echo "$ufw_status" | grep -qE "${rule}.*ALLOW"; then
        log SUCCESS "Rule already exists: $rule"
        return 0
    fi
    
    # Try with comment first (UFW 0.35+)
    if sudo ufw allow "$rule" comment "$comment" >> "$LOG_FILE" 2>&1; then
        log SUCCESS "Allowed $rule ($comment)"
        return 0
    fi
    
    # Fallback: try without comment
    if sudo ufw allow "$rule" >> "$LOG_FILE" 2>&1; then
        log SUCCESS "Allowed $rule"
        return 0
    fi
    
    log WARN "Failed to add rule for $rule"
    return 1
}

# Usage:
add_ufw_rule "445/tcp" "Samba SMB"
add_ufw_rule "139/tcp" "Samba NetBIOS"
```

### Optional: Skip Firewall Environment Variable

Some scripts support skipping firewall configuration:

```bash
if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
    log INFO "Firewall configuration skipped (APPNAME_SKIP_UFW=true)"
    echo
    return 0
fi
```

### Uninstall Rule Removal (Best-Effort)

Only attempt deletions if UFW is active; ignore errors:

```bash
# Remove firewall rules during uninstall
if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    print_step "Removing firewall rules..."
    sudo ufw delete allow 80/tcp 2>/dev/null || true
    sudo ufw delete allow 443/tcp 2>/dev/null || true
fi
```

---

## Secrets Handling (Standard When Generating Credentials/Tokens)

If the installer generates passwords, tokens, or other secrets:

1. Add `umask 077` near the top of the script
2. Store secrets in a dedicated directory with proper permissions
3. Never print secrets to the terminal
4. Do not regenerate secrets if the file already exists and is non-empty

```bash
# Secure file creation by default (near top of script)
umask 077

# Secrets directory setup
SECRETS_DIR="${WORK_DIR}/.secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Generate secure password
generate_password() {
    local length="${1:-35}"
    local password=""
    while [[ ${#password} -lt $length ]]; do
        password+=$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' 2>/dev/null || true)
    done
    printf '%s' "${password:0:$length}"
}

# Secret file creation (idempotent)
secret_file="$SECRETS_DIR/mysql_pwd.secret"
if [[ -f "$secret_file" ]] && [[ -s "$secret_file" ]]; then
    log INFO "Secret already exists (not regenerating)"
else
    generate_password 35 > "$secret_file"
    chmod 600 "$secret_file"
    log SUCCESS "Generated secret"
fi
```

---

## File Generation (Compose/Env) Best Practices

### Single-Quoted Heredocs for Files Containing ${VARS}

When generating Docker Compose YAML or other files that must retain `${...}` placeholders, use single-quoted heredocs:

```bash
cat > docker-compose.yml << 'EOF'
services:
  app:
    environment:
      - ADMIN_PORT=${APP_ADMIN_PORT}
EOF
```

This prevents Bash from expanding `${...}` at script runtime.

---

## Systemd Service Contract (Standard)

If the app runs as a systemd service:

1. Unit file in `/etc/systemd/system/<name>.service`
2. `systemctl daemon-reload`
3. `systemctl enable --now <service>`
4. `--status` shows: is-active, is-enabled

---

## Post-Install Commands (Standard)

### cmd_status

```bash
cmd_status() {
    print_header "AppName Status"
    
    local version
    version=$(appname --version 2>/dev/null | head -1 || echo "unknown")
    
    print_kv "Version" "$version"
    print_kv "Service Status" "$(systemctl is-active appname 2>/dev/null || echo 'unknown')"
    print_kv "Enabled" "$(systemctl is-enabled appname 2>/dev/null || echo 'unknown')"
    
    echo
    print_header "Access Information"
    print_kv "URL" "http://$(get_local_ip):${APP_PORT}"
    
    echo
}
```

### cmd_logs

```bash
cmd_logs() {
    local lines="${1:-50}"
    
    print_header "AppName Logs (last $lines lines)"
    echo
    
    # For systemd services:
    sudo journalctl -u appname -n "$lines" --no-pager
    
    # Or for Docker:
    # cd "$WORK_DIR" && sudo docker compose logs --tail="$lines"
}
```

### cmd_configure (Optional but Recommended)

For apps with token/config re-prompt workflows:

```bash
cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure AppName"
    
    print_warning "This will replace the current configuration."
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_CYAN}Continue? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Reconfiguration cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Re-run configuration and apply config write contract
    get_user_configuration
    generate_config
    restart_service
    
    log SUCCESS "Configuration updated successfully"
}
```

### cmd_uninstall

```bash
cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall AppName"
    
    if ! command_exists appname; then
        print_info "AppName is not installed"
        exit 0
    fi
    
    print_warning "This will remove:"
    print_subheader "Application and configuration"
    print_subheader "Systemd service"
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_RED}Are you sure? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Uninstall cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Stop and disable service
    print_step "Stopping service..."
    sudo systemctl stop appname 2>/dev/null || true
    sudo systemctl disable appname 2>/dev/null || true
    
    # Remove package/files
    print_step "Removing application..."
    # ... app-specific removal ...
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow "${APP_PORT}/tcp" 2>/dev/null || true
    fi
    
    log SUCCESS "AppName has been removed"
    echo
}
```

---

## Installation Summary (Standard)

At the end, print a boxed "Installation Complete" summary:

```bash
show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Access Information"
    print_kv "URL" "http://${ip_address}:${APP_PORT}"
    print_kv "Install Directory" "$INSTALL_DIR"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./appname.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./appname.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
    printf "  %b\n" "${C_CYAN}./appname.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart appname${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./appname.sh --uninstall${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Application" "$INSTALL_DIR"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    draw_separator
    echo
    
    log INFO "=== AppName Installation Completed ==="
}
```

---

## Help Text Best Practices

Include these sections in `--help` output:

1. **Usage**: Basic command syntax
2. **Requirements**: Non-root, sudo, internet, etc.
3. **Installation**: How to run (standalone or via hardening.sh)
4. **Environment variables**: All `<APP>_*` overrides
5. **Post-install commands**: `--status`, `--logs`, `--configure`, `--uninstall`
6. **Network requirements**: Ports needed (inbound/outbound)
7. **Files created**: Config files, data directories, logs

Example from cloudflared.sh:
```bash
echo "Network requirements:"
echo "  Outbound 443/tcp   HTTPS to Cloudflare edge"
echo "  Outbound 7844/udp  QUIC protocol (optional, faster)"
echo
echo "Files created:"
echo "  /etc/cloudflared/                       Configuration directory"
echo "  /etc/apt/sources.list.d/cloudflared.list  APT repository"
echo "  /usr/share/keyrings/cloudflare-main.gpg   GPG key"
echo "  /var/log/lab/cloudflared-*.log            Installation log"
```

---

## Script Skeleton (Mandatory Structure)

```bash
#!/bin/bash
readonly SCRIPT_VERSION="X.Y.Z"
readonly SCRIPT_NAME="appname"

# Handle --help early (before defining functions)
case "${1:-}" in
  --help|-h)
    echo "AppName Installer v${SCRIPT_VERSION}"
    echo
    echo "Usage: $0 [--help] [--status] [--logs [N]] [--configure] [--uninstall]"
    echo
    echo "Requirements:"
    echo "  - Must run as NON-ROOT user with sudo privileges"
    echo
    echo "Environment variables:"
    echo "  APPNAME_SILENT=true    Non-interactive mode"
    echo "  APPNAME_SKIP_UFW=true  Skip firewall configuration"
    echo "  APPNAME_PORT=8080      Override default port"
    echo
    echo "Post-install commands:"
    echo "  --status      Show service status"
    echo "  --logs [N]    Show last N lines of logs (default: 50)"
    echo "  --configure   Reconfigure application"
    echo "  --uninstall   Remove application"
    echo
    echo "Network requirements:"
    echo "  Inbound <PORT>/tcp    Application access"
    echo
    echo "Files created:"
    echo "  /path/to/config       Configuration file"
    echo "  /var/log/lab/*.log    Installation logs"
    exit 0
    ;;
esac

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Optional: umask 077 (if secrets are generated)
umask 077

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# App config (env overrides)
APPNAME_SILENT="${APPNAME_SILENT:-false}"; SILENT="$APPNAME_SILENT"
APPNAME_SKIP_UFW="${APPNAME_SKIP_UFW:-false}"; SKIP_FIREWALL="$APPNAME_SKIP_UFW"
APPNAME_PORT="${APPNAME_PORT:-8080}"; APP_PORT="$APPNAME_PORT"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Formatting + output functions (verbatim from skill)
# ... Terminal Formatting block ...
# ... Output Functions block ...
# ... Visual Elements block ...

# Logging + helper functions (verbatim from skill)
# ... log(), die(), setup_logging() ...
# ... Helper Functions block ...

# Error trap (after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

# Cleanup trap
cleanup() { ... }
trap cleanup EXIT INT TERM

# Pre-flight checks (verbatim from skill)
preflight_checks() { ... }

# App-specific functions
install_app() { ... }
configure_firewall() { ... }
show_summary() { ... }

# Post-install commands
cmd_status() { ... }
cmd_logs() { ... }
cmd_configure() { ... }
cmd_uninstall() { ... }

# Main execution
main() {
    # Handle post-install commands
    case "${1:-}" in
        --status)    cmd_status; exit 0 ;;
        --logs)      cmd_logs "${2:-50}"; exit 0 ;;
        --configure) cmd_configure; exit 0 ;;
        --uninstall) cmd_uninstall; exit 0 ;;
        --version|-v) echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"; exit 0 ;;
        "") ;;  # Continue with installation
        *) die "Unknown option: $1 (use --help for usage)" ;;
    esac
    
    # Early sudo check (before logging)
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed" >&2
        exit 1
    fi
    if [[ ${EUID} -eq 0 ]]; then
        echo "ERROR: Do not run as root" >&2
        exit 1
    fi
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: No sudo privileges" >&2
        exit 1
    fi
    
    # Check if already installed (idempotency)
    if command_exists appname; then
        # Show management menu
        exit 0
    fi
    
    # Setup logging
    setup_logging
    
    # Run installation
    preflight_checks
    install_app
    configure_firewall
    show_summary
}

main "$@"
```

---

## Versioning Rules (SemVer)

- **Patch**: Bugfix, better checks, refactor without behavior change
- **Minor**: New options, new features, improved Debian handling
- **Major**: Breaking changes to CLI/env vars, directory structure, or service behavior

Start new scripts at `1.0.0`.

---

## Checklist for New Scripts

**Script Structure:**
- [ ] Shebang is `#!/bin/bash`
- [ ] `readonly SCRIPT_VERSION` and `readonly SCRIPT_NAME` are set
- [ ] `--help` handler is BEFORE any function definitions
- [ ] `set -euo pipefail` is present
- [ ] `export DEBIAN_FRONTEND=noninteractive`
- [ ] `UNATTENDED_UPGRADES_WAS_ACTIVE=false` is initialized
- [ ] Environment variables are prefixed with app name

**Mandatory Safety Checks:**
- [ ] Refuses root execution (`EUID -eq 0`)
- [ ] Refuses Proxmox host execution
- [ ] Handles missing sudo cleanly (early check before logging)
- [ ] Requires sudo privileges

**Standardized Functions (must be identical):**
- [ ] Terminal formatting block (colors, symbols)
- [ ] All output functions (print_success, print_error, etc.)
- [ ] `draw_box()` and `draw_separator()`
- [ ] `log()` function with levels: SUCCESS, ERROR, WARN, INFO, STEP
- [ ] `die()` uses `log ERROR` (not `print_error`)
- [ ] `setup_logging()` function
- [ ] `get_local_ip()` using ip route + hostname -I fallback
- [ ] `command_exists()`, `service_is_active()`, `is_silent()`
- [ ] `cleanup()` trap for unattended-upgrades
- [ ] ERR trap for debugging

**Logging:**
- [ ] Log file goes to `/var/log/lab/${SCRIPT_NAME}-{timestamp}.log`
- [ ] ANSI codes stripped from log file

**CLI Interface:**
- [ ] Has `--help`, `--status`, `--logs`, `--configure`, `--uninstall`, `--version` commands

**Firewall Logic:**
- [ ] Never enables UFW
- [ ] Never changes default policies
- [ ] Only adds rules if UFW is active
- [ ] Idempotent (checks if rule exists before adding)
- [ ] Comment fallback (tries with comment, falls back to without)

**Config Files:**
- [ ] Uses config write contract (atomic, backup-on-change, validate)
- [ ] Restart services only when config changed

**Secrets (if applicable):**
- [ ] `umask 077` set
- [ ] Secrets directory has 700 permissions
- [ ] Secret files have 600 permissions
- [ ] Secrets not regenerated if already exist

**Idempotency:**
- [ ] Checks for previous installation
- [ ] Shows management menu if already installed
- [ ] Safe to run multiple times

**Summary Output:**
- [ ] Access URLs
- [ ] Install directory
- [ ] Log file path
- [ ] Management commands

---

## Repository Integration

After creating a new script:

1. Place in `apps/` directory
2. Add to `hardening.sh` APP_REGISTRY array
3. Update `CHECKSUMS.txt`: `sha256sum apps/newapp.sh >> CHECKSUMS.txt`
4. Add to README.md documentation
