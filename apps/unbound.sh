#!/bin/bash

#############################################################################
# Unbound DNS Resolver Installer                                            #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Installs Unbound DNS resolver                                        #
#   2. Configures DNS-over-TLS with Quad9 and Cloudflare                    #
#   3. Sets up local domain resolution                                      #
#   4. Configures automatic root hints updates via cron                     #
#   5. Configures UFW firewall rules                                        #
#                                                                           #
# REQUIREMENTS:                                                             #
#   - Debian 13 (or compatible)                                             #
#   - Run as non-root user with sudo privileges                             #
#   - Internet connection for package installation                          #
#                                                                           #
# ENVIRONMENT VARIABLES (for non-interactive mode):                         #
#   UNBOUND_DOMAIN         - Local domain name (default: from resolv.conf)  #
#   UNBOUND_SKIP_REBOOT    - Set to "true" to skip reboot prompt            #
#   UNBOUND_UPSTREAM       - Upstream DNS: "quad9", "cloudflare", "both"    #
#############################################################################

set -Eeuo pipefail

#################################################################
# Resolve Script Directory and Load Formatting Library          #
#################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)" || REPO_ROOT="$SCRIPT_DIR"

# Try multiple locations for formatting library
if [[ -f "$REPO_ROOT/lib/formatting.sh" ]]; then
    source "$REPO_ROOT/lib/formatting.sh"
elif [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/../lib/formatting.sh"
elif [[ -f "$HOME/lab/lib/formatting.sh" ]]; then
    source "$HOME/lab/lib/formatting.sh"
else
    # Minimal fallback formatting
    C_GREEN='\033[0;32m'
    C_RED='\033[0;31m'
    C_YELLOW='\033[0;33m'
    C_CYAN='\033[0;36m'
    C_RESET='\033[0m'
    print_header() { echo -e "\n${C_CYAN}━━━ $1 ━━━${C_RESET}"; }
    print_success() { echo -e "${C_GREEN}✓${C_RESET} $1"; }
    print_error() { echo -e "${C_RED}✗${C_RESET} $1" >&2; }
    print_warning() { echo -e "${C_YELLOW}⚠${C_RESET} $1"; }
    print_info() { echo -e "${C_CYAN}ℹ${C_RESET} $1"; }
    draw_separator() { echo -e "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"; }
fi

#################################################################
# Configuration                                                 #
#################################################################

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="$LOG_DIR/unbound.log"
readonly VERSION="1.0.0"

# Working directory (cleaned up on exit)
WORK_DIR=""

# Domain name (detected or provided via env)
DOMAIN_NAME=""

#################################################################
# Logging Functions                                             #
#################################################################

setup_logging() {
    sudo mkdir -p "$LOG_DIR"
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    echo "========================================" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "unbound.sh started at $(date)" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "========================================" | sudo tee -a "$LOG_FILE" >/dev/null
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | sudo tee -a "$LOG_FILE" >/dev/null
}

#################################################################
# Cleanup and Error Handling                                    #
#################################################################

cleanup() {
    local exit_code=$?
    
    # Clean up temporary directory
    if [[ -n "${WORK_DIR:-}" ]] && [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Script failed with exit code: $exit_code"
        print_warning "Check log file: $LOG_FILE"
    fi
    
    log "Script exited with code: $exit_code"
}

trap cleanup EXIT

die() {
    print_error "$1"
    log "FATAL: $1"
    exit 1
}

#################################################################
# Preflight Checks                                              #
#################################################################

preflight_checks() {
    print_header "Preflight Checks"
    
    # Check for sudo/root access
    if [[ $EUID -ne 0 ]]; then
        if ! command -v sudo &>/dev/null; then
            die "sudo is required but not installed"
        fi
        if ! sudo -v &>/dev/null; then
            die "User does not have sudo privileges"
        fi
        print_success "Running as non-root user: $(whoami)"
        print_success "sudo access verified"
    else
        print_success "Running as root"
    fi
    
    # Check for required commands
    local required_cmds=("apt" "systemctl" "wget")
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            die "Required command not found: $cmd"
        fi
    done
    print_success "Required commands available"
    
    # Check if Debian-based
    if [[ ! -f /etc/debian_version ]]; then
        die "This script requires a Debian-based system"
    fi
    print_success "Debian-based system detected"
    
    # Check internet connectivity
    if ! wget -q --spider http://deb.debian.org; then
        die "No internet connection available"
    fi
    print_success "Internet connectivity verified"
    
    log "Preflight checks passed"
}

#################################################################
# Domain Name Detection                                         #
#################################################################

detect_domain_name() {
    print_header "Domain Name Detection"
    
    # Check if provided via environment
    if [[ -n "${UNBOUND_DOMAIN:-}" ]]; then
        DOMAIN_NAME="$UNBOUND_DOMAIN"
        print_success "Using provided domain: $DOMAIN_NAME"
        return 0
    fi
    
    # Try to extract from /etc/resolv.conf
    print_info "Detecting domain name from /etc/resolv.conf..."
    
    # Method 1: domain line with awk
    DOMAIN_NAME=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
    if [[ -n "$DOMAIN_NAME" ]]; then
        print_success "Domain found (domain line): $DOMAIN_NAME"
        return 0
    fi
    
    # Method 2: search line with awk
    DOMAIN_NAME=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
    if [[ -n "$DOMAIN_NAME" ]]; then
        print_success "Domain found (search line): $DOMAIN_NAME"
        return 0
    fi
    
    # Interactive fallback
    print_warning "Could not auto-detect domain name"
    echo -ne "Enter your local domain name (e.g., home.local): "
    read -r DOMAIN_NAME
    
    if [[ -z "$DOMAIN_NAME" ]]; then
        die "Domain name is required"
    fi
    
    print_success "Using domain: $DOMAIN_NAME"
}

#################################################################
# Install Unbound                                               #
#################################################################

install_unbound() {
    print_header "Installing Unbound"
    
    # Check if already installed
    if dpkg -l | grep -q "^ii.*unbound "; then
        print_warning "Unbound is already installed"
        print_info "Proceeding with configuration update..."
    else
        print_info "Installing unbound package..."
        if ! sudo apt-get update -y; then
            die "Failed to update package lists"
        fi
        
        if ! sudo apt-get install -y unbound; then
            die "Failed to install unbound"
        fi
        print_success "Unbound installed successfully"
    fi
    
    log "Unbound installation completed"
}

#################################################################
# Create Configuration File                                     #
#################################################################

create_config() {
    print_header "Creating Unbound Configuration"
    
    # Create working directory
    WORK_DIR=$(mktemp -d)
    print_info "Working directory: $WORK_DIR"
    
    local config_file="$WORK_DIR/unbound.conf"
    
    print_info "Generating unbound.conf..."
    
    cat > "$config_file" <<'UNBOUND_CONFIG'
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
    private-domain: "DOMAIN_NAME_PLACEHOLDER"

    # Local authoritative zone
    local-zone: "DOMAIN_NAME_PLACEHOLDER." static

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

    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 256m
    msg-cache-size: 128m
    so-rcvbuf: 8m


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
    # forward-addr: 2606:4700:4700::1002@853#cloudflare-dns.com

    # Google
    # forward-addr: 8.8.8.8@853#dns.google
    # forward-addr: 8.8.4.4@853#dns.google
    # forward-addr: 2001:4860:4860::8888@853#dns.google
    # forward-addr: 2001:4860:4860::8844@853#dns.google
UNBOUND_CONFIG

    # Replace domain placeholder
    sed -i "s/DOMAIN_NAME_PLACEHOLDER/$DOMAIN_NAME/g" "$config_file"
    
    print_success "Configuration generated with domain: $DOMAIN_NAME"
    log "Configuration created with domain: $DOMAIN_NAME"
}

#################################################################
# Update Root Hints                                             #
#################################################################

update_root_hints() {
    print_header "Updating Root Hints"
    
    print_info "Downloading latest root hints from internic.net..."
    
    if wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints >/dev/null; then
        print_success "Root hints updated successfully"
    else
        print_warning "Failed to update root hints (will use existing)"
    fi
    
    log "Root hints update attempted"
}

#################################################################
# Install Configuration                                         #
#################################################################

install_config() {
    print_header "Installing Configuration"
    
    local config_file="$WORK_DIR/unbound.conf"
    
    # Backup existing config if present
    if [[ -f /etc/unbound/unbound.conf ]]; then
        local backup="/etc/unbound/unbound.conf.backup.$(date +%Y%m%d%H%M%S)"
        print_info "Backing up existing config to: $backup"
        sudo cp /etc/unbound/unbound.conf "$backup"
    fi
    
    # Install new config
    print_info "Installing new configuration..."
    if sudo cp "$config_file" /etc/unbound/unbound.conf; then
        print_success "Configuration installed to /etc/unbound/unbound.conf"
    else
        die "Failed to install configuration"
    fi
    
    # Validate configuration
    print_info "Validating configuration..."
    if sudo unbound-checkconf /etc/unbound/unbound.conf; then
        print_success "Configuration validation passed"
    else
        print_warning "Configuration validation had warnings (may still work)"
    fi
    
    log "Configuration installed"
}

#################################################################
# Setup Cron Job for Root Hints                                 #
#################################################################

setup_cron() {
    print_header "Setting Up Automatic Root Hints Updates"
    
    local cron_command="wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints > /dev/null && sudo systemctl restart unbound"
    local cron_entry="0 0 1 */3 * $cron_command"
    local cron_comment="# Update root hints and restart unbound DNS resolver (lab/unbound.sh)"
    
    # Check if already exists
    if crontab -l 2>/dev/null | grep -q "root.hints.*unbound"; then
        print_warning "Cron entry for root hints already exists"
        return 0
    fi
    
    # Add cron entry
    print_info "Adding quarterly root hints update to crontab..."
    
    local temp_file
    temp_file=$(mktemp)
    
    # Get existing crontab (or empty if none)
    crontab -l 2>/dev/null > "$temp_file" || true
    
    # Add new entry
    echo "" >> "$temp_file"
    echo "$cron_comment" >> "$temp_file"
    echo "$cron_entry" >> "$temp_file"
    
    if crontab "$temp_file"; then
        print_success "Cron job added (runs quarterly on 1st of month)"
    else
        print_warning "Failed to add cron job (manual updates required)"
    fi
    
    rm -f "$temp_file"
    log "Cron setup completed"
}

#################################################################
# Configure Firewall                                            #
#################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Check if UFW is available
    if ! command -v ufw &>/dev/null; then
        print_warning "UFW not installed, skipping firewall configuration"
        return 0
    fi
    
    local rules=(
        "53/tcp:Unbound-DNS-TCP"
        "53/udp:Unbound-DNS-UDP"
        "853/tcp:Unbound-DoT"
    )
    
    for rule in "${rules[@]}"; do
        local port="${rule%%:*}"
        local comment="${rule##*:}"
        
        print_info "Allowing $port ($comment)..."
        if sudo ufw allow "$port" comment "$comment" &>/dev/null; then
            print_success "Allowed: $port"
        else
            print_warning "Failed to add rule for $port"
        fi
    done
    
    # Reload UFW
    print_info "Reloading firewall..."
    sudo systemctl restart ufw 2>/dev/null || true
    
    print_success "Firewall configured"
    log "Firewall rules added"
}

#################################################################
# Start Service                                                 #
#################################################################

start_service() {
    print_header "Starting Unbound Service"
    
    print_info "Enabling unbound service..."
    sudo systemctl enable unbound
    
    print_info "Restarting unbound service..."
    if sudo systemctl restart unbound; then
        print_success "Unbound service started"
    else
        print_error "Failed to start unbound service"
        print_info "Check status with: sudo systemctl status unbound"
        return 1
    fi
    
    # Verify it's running
    sleep 2
    if systemctl is-active --quiet unbound; then
        print_success "Unbound is running"
    else
        print_warning "Unbound may not be running properly"
    fi
    
    log "Service started"
}

#################################################################
# Show Summary                                                  #
#################################################################

show_summary() {
    echo
    draw_separator
    print_success "Unbound DNS Resolver installed successfully!"
    echo
    print_info "Configuration:"
    echo "  Domain: $DOMAIN_NAME"
    echo "  Config: /etc/unbound/unbound.conf"
    echo "  Log: /var/log/lab/unbound.log"
    echo
    print_info "Unbound listens on all interfaces with access limited to:"
    echo "  - Localhost (127.0.0.0/8)"
    echo "  - Additional VLANs via /etc/unbound/unbound.conf.d/vlans.conf"
    echo
    print_info "Upstream DNS (DNS-over-TLS):"
    echo "  - Quad9 (9.9.9.9, 149.112.112.112)"
    echo "  - Cloudflare (1.1.1.1, 1.0.0.1)"
    echo
    print_info "Static hosts: /etc/unbound/unbound.conf.d/30-static-hosts.conf"
    echo
    print_info "Test with:"
    echo "  dig @127.0.0.1 google.com"
    echo "  dig @127.0.0.1 -x <ip-address>"
    draw_separator
}

#################################################################
# VLAN Configuration Helper                                     #
#################################################################

configure_vlans() {
    print_header "VLAN Access Control Configuration"
    
    echo
    print_info "This configures which network subnets can query this DNS server."
    print_info "By default, only localhost can query Unbound."
    print_info "Add your VLANs/subnets here to allow DNS queries from them."
    echo
    draw_separator
    echo
    print_info "Paste your VLAN subnets below (one per line, CIDR format)."
    print_info "When finished, press Ctrl+D (or Ctrl+Z then Enter on Windows)."
    echo
    print_info "Format: CIDR notation"
    print_info "Examples:"
    echo "  192.168.1.0/24      # Main LAN"
    echo "  192.168.20.0/24     # IoT VLAN"
    echo "  10.10.0.0/24        # Management VLAN"
    echo
    draw_separator
    echo
    
    local vlans_raw
    vlans_raw="$(cat)" || true
    
    # Drop empty lines
    vlans_raw="$(printf '%s\n' "$vlans_raw" | sed -E '/^[[:space:]]*$/d')"
    
    if [[ -z "$vlans_raw" ]]; then
        echo
        print_warning "No VLANs provided. Skipping VLAN configuration."
        return 0
    fi
    
    # Normalize whitespace, strip comments, keep first token, sort/unique
    local vlans
    vlans="$(
        printf '%s\n' "$vlans_raw" |
        sed -E 's/#.*$//' |
        sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' |
        awk '{print $1}' |
        sed -E '/^[[:space:]]*$/d' |
        sort -u
    )"
    
    if [[ -z "$vlans" ]]; then
        echo
        print_warning "No valid VLANs after processing. Skipping."
        return 0
    fi
    
    local outfile="/etc/unbound/unbound.conf.d/vlans.conf"
    declare -A used_subnets
    local tmp_file
    tmp_file=$(mktemp)
    
    local warnings=0
    local loaded=0
    local skipped=0
    local reverse24=0
    local reverse_other=0
    
    {
        echo "# Auto-generated VLAN access-control + reverse zones for Unbound"
        echo "# Generated: $(date -Is)"
        echo
        echo "server:"
        echo
        echo "    # ------------------------------------------------------------------------"
        echo "    # VLAN networks - allowed to query this DNS server"
        echo "    # ------------------------------------------------------------------------"
        echo
        
        while IFS= read -r line; do
            line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
            [[ -z "$line" ]] && continue
            
            line="$(printf '%s' "$line" | sed -E 's/#.*$//')"
            line="$(printf '%s' "$line" | awk '{print $1}')"
            [[ -z "$line" ]] && continue
            
            if [[ ! "$line" =~ ^([^/]+)/([0-9]{1,2})$ ]]; then
                print_warning "Skipping invalid CIDR format: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            local ip="${BASH_REMATCH[1]}"
            local prefix="${BASH_REMATCH[2]}"
            
            # Validate IPv4
            if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                print_warning "Skipping invalid IPv4: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            local a b c d
            IFS=. read -r a b c d <<< "$ip"
            if (( a > 255 || b > 255 || c > 255 || d > 255 )); then
                print_warning "Skipping invalid IP range: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            # Validate prefix
            if (( prefix < 0 || prefix > 32 )); then
                print_warning "Skipping invalid CIDR prefix: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            if [[ -n "${used_subnets[$line]+x}" ]]; then
                print_warning "Duplicate subnet ignored: $line"
                ((++skipped))
                continue
            fi
            used_subnets[$line]=1
            
            echo "    access-control: ${line} allow"
            ((++loaded))
        done <<< "$vlans"
        
        echo
        echo "    # ------------------------------------------------------------------------"
        echo "    # Reverse zones for /24 networks"
        echo "    # ------------------------------------------------------------------------"
        echo
        
        for cidr in $(printf '%s\n' "${!used_subnets[@]}" | sort -V); do
            [[ -z "$cidr" ]] && continue
            local ip="${cidr%/*}"
            local prefix="${cidr#*/}"
            
            if [[ "$prefix" == "24" ]]; then
                local o1 o2 o3 o4
                IFS=. read -r o1 o2 o3 o4 <<< "$ip"
                echo "    local-zone: \"${o3}.${o2}.${o1}.in-addr.arpa.\" static"
                ((++reverse24))
            else
                ((++reverse_other))
            fi
        done
        
        if (( reverse_other > 0 )); then
            echo
            echo "    # Note: ${reverse_other} subnet(s) were not /24, no reverse zone generated."
        fi
        
    } > "$tmp_file"
    
    if (( loaded == 0 )); then
        print_error "No valid VLAN subnets after validation."
        rm -f "$tmp_file"
        return 1
    fi
    
    echo
    print_info "Generated configuration preview:"
    draw_separator
    cat "$tmp_file"
    draw_separator
    echo
    
    echo -ne "Write this configuration to $outfile? (yes/no): "
    read -r confirm
    
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
        print_warning "Aborted. Nothing written."
        rm -f "$tmp_file"
        return 0
    fi
    
    if [[ -f "$outfile" ]]; then
        echo
        print_warning "File already exists: $outfile"
        echo -ne "Overwrite it? (yes/no): "
        read -r overwrite
        
        if [[ "${overwrite,,}" != "y" && "${overwrite,,}" != "yes" ]]; then
            print_warning "Aborted. Existing file preserved."
            rm -f "$tmp_file"
            return 0
        fi
    fi
    
    sudo install -m 0644 -o root -g root "$tmp_file" "$outfile"
    rm -f "$tmp_file"
    
    if ! sudo unbound-checkconf >/dev/null 2>&1; then
        print_error "Unbound configuration has errors!"
        print_warning "File written but Unbound NOT reloaded. Fix errors and reload manually."
        return 1
    fi
    
    sudo systemctl reload unbound
    
    echo
    print_success "VLAN configuration installed: $outfile"
    print_info "Loaded VLANs: $loaded"
    print_info "Reverse zones (/24): $reverse24"
    if (( skipped > 0 )); then
        print_warning "Skipped entries: $skipped"
    fi
    
    log "VLAN configuration completed: $loaded subnets"
}

#################################################################
# Static Hosts Configuration Helper                             #
#################################################################

configure_static_hosts() {
    print_header "Static DNS Hosts Configuration"
    
    echo
    print_info "This creates local DNS records (A and PTR) for your infrastructure."
    print_info "Use this for devices that need stable, predictable DNS names:"
    echo "  - Servers, NAS, file shares"
    echo "  - Printers, scanners"
    echo "  - Network equipment, management interfaces"
    echo "  - Any device that runs services or appears in logs"
    echo
    print_warning "Do NOT add regular clients here - use DHCP for phones, laptops, etc."
    echo
    draw_separator
    echo
    
    # Get domain name
    local domain=""
    while true; do
        echo -ne "Enter your local domain name (e.g., home.local, lan.example.com): "
        read -r domain
        echo
        
        # Convert to lowercase and trim
        domain="${domain,,}"
        domain="$(echo "$domain" | xargs)"
        
        if [[ -z "$domain" ]]; then
            print_error "Domain cannot be empty."
            continue
        fi
        
        if [[ ! "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
            print_error "Invalid domain format. Use: letters, numbers, hyphens, dots"
            continue
        fi
        
        break
    done
    
    print_success "Domain set to: $domain"
    echo
    draw_separator
    echo
    print_info "Now paste your host entries below (one per line)."
    print_info "When finished, press Ctrl+D (or Ctrl+Z then Enter on Windows)."
    echo
    print_info "Format: IP_ADDRESS    HOSTNAME"
    print_info "Examples:"
    echo "  192.168.1.10    nas"
    echo "  192.168.1.20    proxmox"
    echo "  192.168.1.30    printer"
    echo "  192.168.20.5    unifi-controller"
    echo
    draw_separator
    echo
    
    local hosts_raw
    hosts_raw="$(cat)" || true
    
    # Drop empty lines
    hosts_raw="$(printf '%s\n' "$hosts_raw" | sed -E '/^[[:space:]]*$/d')"
    
    if [[ -z "$hosts_raw" ]]; then
        echo
        print_warning "No hosts provided. Skipping static hosts configuration."
        return 0
    fi
    
    # Normalize and sort by IP
    local hosts
    hosts="$(
        printf '%s\n' "$hosts_raw" |
        awk '
            {
                ip=$1;
                $1="";
                sub(/^[ \t]+/,"");
                name=$0;
                split(ip,a,".");
                if (length(a[1]) && length(a[2]) && length(a[3]) && length(a[4])) {
                    key=sprintf("%03d.%03d.%03d.%03d",a[1],a[2],a[3],a[4]);
                } else {
                    key="999.999.999.999";
                }
                print key "\t" ip "\t" name;
            }
        ' |
        sort |
        cut -f2-
    )"
    
    echo
    print_success "Hosts received (sorted by IP)."
    
    # Sanitize label function
    sanitize_label() {
        local s="$1"
        s="$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
        s="${s//_/-}"
        s="${s// /-}"
        s="$(printf '%s' "$s" | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g')"
        [[ -z "$s" ]] && s="host"
        [[ "$s" =~ ^[0-9] ]] && s="h-$s"
        printf '%s' "$s"
    }
    
    local outfile="/etc/unbound/unbound.conf.d/30-static-hosts.conf"
    declare -A used_labels
    declare -A used_ips
    declare -A used_fqdns
    
    local tmp_file
    tmp_file=$(mktemp)
    
    local warnings=0
    local loaded=0
    local skipped=0
    local current_subnet=""
    
    {
        echo "# Auto-generated static hosts for Unbound"
        echo "# Domain: ${domain}"
        echo "# Generated: $(date -Is)"
        echo
        echo "server:"
        echo
        
        while IFS= read -r line; do
            line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^# ]] && continue
            
            local ip name
            ip="$(printf '%s' "$line" | awk '{print $1}')"
            name="$(printf '%s' "$line" | sed -E 's/^[^[:space:]]+[[:space:]]+//')"
            [[ -z "$ip" || -z "$name" ]] && { ((++skipped)); continue; }
            
            # Validate IPv4
            if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                print_warning "Skipping invalid IP format: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            local o1 o2 o3 o4
            IFS=. read -r o1 o2 o3 o4 <<< "$ip"
            if (( o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255 )); then
                print_warning "Skipping invalid IP range: $line"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            local subnet="${o1}.${o2}.${o3}.0/24"
            if [[ "$subnet" != "$current_subnet" ]]; then
                current_subnet="$subnet"
                echo "    # ========================================================================="
                echo "    # Subnet: ${current_subnet}"
                echo "    # ========================================================================="
                echo
            fi
            
            local base label oct fqdn
            base="$(sanitize_label "$name")"
            oct="${ip##*.}"
            
            if [[ -n "${used_labels[$base]+x}" && "${used_labels[$base]}" != "$ip" ]]; then
                label="${base}-${oct}"
            else
                label="$base"
            fi
            
            if [[ -n "${used_labels[$label]+x}" && "${used_labels[$label]}" != "$ip" ]]; then
                local last2
                last2="$(printf '%s' "$ip" | awk -F. '{print $(NF-1)"-"$NF}')"
                label="${base}-${last2}"
            fi
            
            fqdn="${label}.${domain}"
            
            # Reject duplicate IPs
            if [[ -n "${used_ips[$ip]+x}" ]]; then
                print_warning "Duplicate IP rejected: ${ip} (used by ${used_ips[$ip]})"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            # Reject duplicate FQDNs
            if [[ -n "${used_fqdns[$fqdn]+x}" ]]; then
                print_warning "Duplicate hostname rejected: ${fqdn} (used by ${used_fqdns[$fqdn]})"
                ((++warnings)); ((++skipped))
                continue
            fi
            
            used_labels[$label]="$ip"
            used_ips[$ip]="$fqdn"
            used_fqdns[$fqdn]="$ip"
            
            echo "    local-data: \"${fqdn}. IN A ${ip}\""
            echo "    local-data-ptr: \"${ip} ${fqdn}\""
            echo
            
            ((++loaded))
        done <<< "$hosts"
    } > "$tmp_file"
    
    if (( loaded == 0 )); then
        print_error "No valid hosts after validation."
        rm -f "$tmp_file"
        return 1
    fi
    
    echo
    print_info "Generated configuration preview:"
    draw_separator
    cat "$tmp_file"
    draw_separator
    echo
    
    echo -ne "Write this configuration to $outfile? (yes/no): "
    read -r confirm
    
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
        print_warning "Aborted. Nothing written."
        rm -f "$tmp_file"
        return 0
    fi
    
    if [[ -f "$outfile" ]]; then
        echo
        print_warning "File already exists: $outfile"
        echo -ne "Overwrite it? (yes/no): "
        read -r overwrite
        
        if [[ "${overwrite,,}" != "y" && "${overwrite,,}" != "yes" ]]; then
            print_warning "Aborted. Existing file preserved."
            rm -f "$tmp_file"
            return 0
        fi
    fi
    
    sudo install -m 0644 -o root -g root "$tmp_file" "$outfile"
    rm -f "$tmp_file"
    
    if ! sudo unbound-checkconf >/dev/null 2>&1; then
        print_error "Unbound configuration has errors!"
        print_warning "File written but Unbound NOT reloaded. Fix errors and reload manually."
        return 1
    fi
    
    sudo systemctl reload unbound
    
    echo
    print_success "Static hosts configuration installed: $outfile"
    print_info "Loaded hosts: $loaded"
    if (( skipped > 0 )); then
        print_warning "Skipped entries: $skipped"
    fi
    
    log "Static hosts configuration completed: $loaded records"
}

#################################################################
# Post-Installation Configuration Menu                          #
#################################################################

post_install_config() {
    print_header "Additional Configuration"
    
    echo
    print_info "Unbound is now installed and running with default settings."
    print_info "You can optionally configure the following now or later:"
    echo
    echo "  1) Configure VLANs - Allow other network subnets to use this DNS server"
    echo "  2) Configure Static Hosts - Add local DNS records for your infrastructure"
    echo "  3) Skip - Configure these later manually"
    echo
    
    while true; do
        echo -ne "Select option [1-3]: "
        read -r choice
        
        case "$choice" in
            1)
                configure_vlans
                echo
                echo -ne "Would you also like to configure static hosts? (yes/no): "
                read -r also_hosts
                if [[ "${also_hosts,,}" == "y" || "${also_hosts,,}" == "yes" ]]; then
                    configure_static_hosts
                fi
                break
                ;;
            2)
                configure_static_hosts
                echo
                echo -ne "Would you also like to configure VLANs? (yes/no): "
                read -r also_vlans
                if [[ "${also_vlans,,}" == "y" || "${also_vlans,,}" == "yes" ]]; then
                    configure_vlans
                fi
                break
                ;;
            3)
                print_info "Skipping additional configuration."
                print_info "You can configure these later by editing:"
                echo "  VLANs: /etc/unbound/unbound.conf.d/vlans.conf"
                echo "  Hosts: /etc/unbound/unbound.conf.d/30-static-hosts.conf"
                break
                ;;
            *)
                print_error "Invalid choice. Please select 1, 2, or 3."
                ;;
        esac
    done
}

#################################################################
# Prompt for Reboot                                             #
#################################################################

prompt_reboot() {
    # Skip if environment variable set
    if [[ "${UNBOUND_SKIP_REBOOT:-}" == "true" ]]; then
        print_info "Skipping reboot (UNBOUND_SKIP_REBOOT=true)"
        return 0
    fi
    
    echo
    while true; do
        echo -ne "Do you want to reboot the server now (recommended)? (yes/no): "
        read -r response
        echo
        
        case "${response,,}" in
            yes|y)
                print_info "Rebooting the server..."
                log "User requested reboot"
                sudo reboot
                ;;
            no|n)
                print_info "Reboot cancelled"
                print_warning "A reboot is recommended to ensure all changes take effect"
                return 0
                ;;
            *)
                print_error "Invalid response. Please answer yes or no."
                ;;
        esac
    done
}

#################################################################
# Main Function                                                 #
#################################################################

main() {
    clear
    
    echo -e "${C_CYAN:-\033[0;36m}╔════════════════════════════════════════════════════════════╗${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}║          Unbound DNS Resolver Installer v${VERSION}          ║${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}║          https://github.com/vdarkobar/lab                  ║${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}╚════════════════════════════════════════════════════════════╝${C_RESET:-\033[0m}"
    
    setup_logging
    
    # Run all steps
    preflight_checks
    detect_domain_name
    install_unbound
    create_config
    update_root_hints
    install_config
    setup_cron
    configure_firewall
    start_service
    show_summary
    
    log "Unbound installation completed successfully"
    
    # Offer additional configuration
    post_install_config
    
    prompt_reboot
}

# Argument handling
case "${1:-}" in
    --configure|--config|-c)
        setup_logging
        post_install_config
        ;;
    --vlans)
        setup_logging
        configure_vlans
        ;;
    --hosts)
        setup_logging
        configure_static_hosts
        ;;
    --help|-h)
        echo "Unbound DNS Resolver Installer v${VERSION}"
        echo
        echo "Usage: $0 [OPTION]"
        echo
        echo "Options:"
        echo "  (none)        Full installation"
        echo "  --configure   Run configuration menu (VLANs, hosts)"
        echo "  --vlans       Configure VLAN access control only"
        echo "  --hosts       Configure static DNS hosts only"
        echo "  --help        Show this help"
        echo
        echo "Examples:"
        echo "  $0              # Fresh install"
        echo "  $0 --hosts      # Add/update static DNS records"
        echo "  $0 --vlans      # Add/update allowed subnets"
        ;;
    *)
        main "$@"
        ;;
esac