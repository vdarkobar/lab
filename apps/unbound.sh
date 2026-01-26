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
    
    prompt_reboot
}

# Run main
main "$@"