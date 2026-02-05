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
#############################################################################

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="unbound"

#############################################################################
# Handle --help early (before any function definitions)                     #
#############################################################################

case "${1:-}" in
    --help|-h)
        echo "Unbound DNS Resolver Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help] [--status] [--logs [N]] [--configure] [--uninstall]"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Debian 13 (Trixie) or Debian 12 (Bookworm)"
        echo "  - Internet connection for package installation"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Unbound DNS\""
        echo
        echo "Environment variables (for non-interactive mode):"
        echo "  UNBOUND_SILENT=true       Non-interactive mode (safe defaults)"
        echo "  UNBOUND_SKIP_UFW=true     Skip firewall configuration"
        echo "  UNBOUND_DOMAIN=home.local Local domain name (default: from resolv.conf)"
        echo "  UNBOUND_SKIP_REBOOT=true  Skip reboot prompt"
        echo
        echo "Post-install commands:"
        echo "  --status      Show service status and access info"
        echo "  --logs [N]    Show last N lines of logs (default: 50)"
        echo "  --configure   Run configuration menu (VLANs, static hosts)"
        echo "  --vlans       Configure VLAN access control only"
        echo "  --hosts       Configure static DNS hosts only"
        echo "  --uninstall   Remove Unbound"
        echo "  --version     Show version"
        echo
        echo "Network requirements:"
        echo "  Inbound 53/tcp, 53/udp    DNS queries from allowed clients"
        echo "  Outbound 853/tcp          DNS-over-TLS to upstream resolvers"
        echo
        echo "Files created:"
        echo "  /etc/unbound/unbound.conf                       Main configuration"
        echo "  /etc/unbound/unbound.conf.d/vlans.conf          VLAN access control"
        echo "  /etc/unbound/unbound.conf.d/30-static-hosts.conf  Static DNS records"
        echo "  /var/log/lab/unbound-*.log                      Installation logs"
        exit 0
        ;;
esac

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

#############################################################################
# Track services we stop (to restart on cleanup)                            #
#############################################################################

UNATTENDED_UPGRADES_WAS_ACTIVE=false

#############################################################################
# App Configuration (environment variable overrides)                        #
#############################################################################

UNBOUND_SILENT="${UNBOUND_SILENT:-false}"; SILENT="$UNBOUND_SILENT"
UNBOUND_SKIP_UFW="${UNBOUND_SKIP_UFW:-false}"; SKIP_FIREWALL="$UNBOUND_SKIP_UFW"
UNBOUND_DOMAIN="${UNBOUND_DOMAIN:-}"
UNBOUND_SKIP_REBOOT="${UNBOUND_SKIP_REBOOT:-false}"

#############################################################################
# Logging Configuration                                                     #
#############################################################################

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Working directory (cleaned up on exit)
WORK_DIR=""

# Domain name (detected or provided via env)
DOMAIN_NAME=""

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

#############################################################################
# Error trap for better debugging (set after print_error is defined)        #
#############################################################################

trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Clean up temporary directory
    if [[ -n "${WORK_DIR:-}" ]] && [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
    
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

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

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

#############################################################################
# APT Lock Handling                                                         #
#############################################################################

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

#############################################################################
# Domain Name Detection                                                     #
#############################################################################

detect_domain_name() {
    print_header "Domain Name Detection"
    
    # Check if provided via environment
    if [[ -n "${UNBOUND_DOMAIN:-}" ]]; then
        DOMAIN_NAME="$UNBOUND_DOMAIN"
        log SUCCESS "Using provided domain: $DOMAIN_NAME"
        return 0
    fi
    
    # Try to extract from /etc/resolv.conf
    print_step "Detecting domain name from /etc/resolv.conf..."
    
    # Method 1: domain line with awk
    DOMAIN_NAME=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
    if [[ -n "$DOMAIN_NAME" ]]; then
        log SUCCESS "Domain found (domain line): $DOMAIN_NAME"
        return 0
    fi
    
    # Method 2: search line with awk
    DOMAIN_NAME=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
    if [[ -n "$DOMAIN_NAME" ]]; then
        log SUCCESS "Domain found (search line): $DOMAIN_NAME"
        return 0
    fi
    
    # Interactive fallback (or default in silent mode)
    if is_silent; then
        DOMAIN_NAME="local"
        log INFO "Using default domain (silent mode): $DOMAIN_NAME"
        return 0
    fi
    
    print_warning "Could not auto-detect domain name"
    echo -ne "${C_CYAN}Enter your local domain name (e.g., home.local): ${C_RESET}"
    read -r DOMAIN_NAME
    
    if [[ -z "$DOMAIN_NAME" ]]; then
        die "Domain name is required"
    fi
    
    log SUCCESS "Using domain: $DOMAIN_NAME"
}

#############################################################################
# Install Unbound                                                           #
#############################################################################

install_unbound() {
    print_header "Installing Unbound"
    
    # Check if already installed
    if dpkg -l | grep -q "^ii.*unbound "; then
        log WARN "Unbound is already installed"
        log INFO "Proceeding with configuration update..."
    else
        prepare_apt
        
        log STEP "Updating package lists..."
        if ! sudo apt-get update -y; then
            die "Failed to update package lists"
        fi
        
        log STEP "Installing unbound package..."
        if ! sudo apt-get install -y unbound; then
            die "Failed to install unbound"
        fi
        log SUCCESS "Unbound installed successfully"
    fi
    
    log INFO "Unbound installation completed"
}

#############################################################################
# Create Configuration File                                                 #
#############################################################################

create_config() {
    print_header "Creating Unbound Configuration"
    
    # Create working directory
    WORK_DIR=$(mktemp -d)
    print_info "Working directory: $WORK_DIR"
    
    local config_file="$WORK_DIR/unbound.conf"
    
    log STEP "Generating unbound.conf..."
    
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
    
    log SUCCESS "Configuration generated with domain: $DOMAIN_NAME"
}

#############################################################################
# Update Root Hints                                                         #
#############################################################################

update_root_hints() {
    print_header "Updating Root Hints"
    
    log STEP "Downloading latest root hints from internic.net..."
    
    if wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints >/dev/null; then
        log SUCCESS "Root hints updated successfully"
    else
        log WARN "Failed to update root hints (will use existing)"
    fi
}

#############################################################################
# Install Configuration                                                     #
#############################################################################

install_config() {
    print_header "Installing Configuration"
    
    local config_file="$WORK_DIR/unbound.conf"
    local target_conf="/etc/unbound/unbound.conf"
    local config_changed=false
    
    # Check if config changed
    if [[ -f "$target_conf" ]]; then
        if ! cmp -s "$config_file" "$target_conf"; then
            config_changed=true
            local backup="${target_conf}.backup.$(date +%Y%m%d_%H%M%S)"
            log INFO "Config changed - backing up to: $backup"
            sudo cp "$target_conf" "$backup"
        else
            log INFO "Configuration unchanged"
        fi
    else
        config_changed=true
        log INFO "Creating new configuration"
    fi
    
    if [[ "$config_changed" == "true" ]]; then
        log STEP "Installing new configuration..."
        if sudo cp "$config_file" "$target_conf"; then
            sudo chmod 644 "$target_conf"
            log SUCCESS "Configuration installed to $target_conf"
        else
            die "Failed to install configuration"
        fi
    fi
    
    # Validate configuration
    log STEP "Validating configuration..."
    if sudo unbound-checkconf "$target_conf" >/dev/null 2>&1; then
        log SUCCESS "Configuration validation passed"
    else
        log WARN "Configuration validation had warnings (may still work)"
    fi
}

#############################################################################
# Setup Cron Job for Root Hints                                             #
#############################################################################

setup_cron() {
    print_header "Setting Up Automatic Root Hints Updates"
    
    local cron_command="wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints > /dev/null && sudo systemctl restart unbound"
    local cron_entry="0 0 1 */3 * $cron_command"
    local cron_comment="# Update root hints and restart unbound DNS resolver (lab/unbound.sh)"
    
    # Check if already exists
    if crontab -l 2>/dev/null | grep -q "root.hints.*unbound"; then
        log WARN "Cron entry for root hints already exists"
        return 0
    fi
    
    # Add cron entry
    log STEP "Adding quarterly root hints update to crontab..."
    
    local temp_file
    temp_file=$(mktemp)
    
    # Get existing crontab (or empty if none)
    crontab -l 2>/dev/null > "$temp_file" || true
    
    # Add new entry
    echo "" >> "$temp_file"
    echo "$cron_comment" >> "$temp_file"
    echo "$cron_entry" >> "$temp_file"
    
    if crontab "$temp_file"; then
        log SUCCESS "Cron job added (runs quarterly on 1st of month)"
    else
        log WARN "Failed to add cron job (manual updates required)"
    fi
    
    rm -f "$temp_file"
}

#############################################################################
# Configure Firewall                                                        #
#############################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Check if skip firewall is set
    if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
        log INFO "Firewall configuration skipped (UNBOUND_SKIP_UFW=true)"
        echo
        return 0
    fi
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        log INFO "Required ports: 53/tcp, 53/udp (DNS)"
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
    
    add_ufw_rule "53/tcp" "Unbound-DNS-TCP"
    add_ufw_rule "53/udp" "Unbound-DNS-UDP"
    
    log SUCCESS "Firewall configuration complete"
    echo
}

#############################################################################
# Start Service                                                             #
#############################################################################

start_service() {
    print_header "Starting Unbound Service"
    
    log STEP "Enabling unbound service..."
    sudo systemctl enable unbound
    
    log STEP "Restarting unbound service..."
    if sudo systemctl restart unbound; then
        log SUCCESS "Unbound service started"
    else
        log ERROR "Failed to start unbound service"
        log INFO "Check status with: sudo systemctl status unbound"
        return 1
    fi
    
    # Verify it's running
    sleep 2
    if service_is_active unbound; then
        log SUCCESS "Unbound is running"
    else
        log WARN "Unbound may not be running properly"
    fi
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Configuration"
    print_kv "Domain" "$DOMAIN_NAME"
    print_kv "Config File" "/etc/unbound/unbound.conf"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    print_header "Access Information"
    print_kv "DNS Server" "$ip_address"
    print_kv "Port" "53 (TCP/UDP)"
    
    echo
    print_info "Unbound listens on all interfaces with access limited to:"
    print_subheader "Localhost (127.0.0.0/8)"
    print_subheader "Additional VLANs via /etc/unbound/unbound.conf.d/vlans.conf"
    
    echo
    print_info "Upstream DNS (DNS-over-TLS):"
    print_subheader "Quad9 (9.9.9.9, 149.112.112.112)"
    print_subheader "Cloudflare (1.1.1.1, 1.0.0.1)"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./unbound.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./unbound.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Configure VLANs/Hosts${C_RESET}"
    printf "  %b\n" "${C_CYAN}./unbound.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart unbound${C_RESET}"
    
    echo
    print_header "Test Commands"
    printf "  %b\n" "${C_CYAN}dig @127.0.0.1 google.com${C_RESET}"
    printf "  %b\n" "${C_CYAN}dig @127.0.0.1 -x <ip-address>${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "Static Hosts" "/etc/unbound/unbound.conf.d/30-static-hosts.conf"
    print_kv "VLAN Config" "/etc/unbound/unbound.conf.d/vlans.conf"
    
    echo
    draw_separator
    echo
    
    log INFO "=== Unbound Installation Completed ==="
}

#############################################################################
# VLAN Configuration Helper                                                 #
#############################################################################

configure_vlans() {
    print_header "VLAN Access Control Configuration"
    
    echo
    print_info "This configures which network subnets can query this DNS server."
    print_info "By default, only localhost can query Unbound."
    print_info "Add your VLANs/subnets here to allow DNS queries from them."
    echo
    draw_separator
    echo
    print_info "Format: CIDR notation (e.g., 192.168.1.0/24)"
    print_info "Enter each subnet and press Enter."
    print_info "When finished, press Enter on an empty line."
    echo
    print_info "Examples:"
    echo "  192.168.1.0/24      (Main LAN)"
    echo "  192.168.20.0/24     (IoT VLAN)"
    echo "  10.10.0.0/24        (Management VLAN)"
    echo
    draw_separator
    
    local vlans_raw=""
    local line
    local count=0
    
    while true; do
        echo -ne "\n${C_CYAN}Subnet $((count + 1)) (or Enter to finish): ${C_RESET}"
        read -r line
        
        # Empty line = done
        [[ -z "$line" ]] && break
        
        # Strip comments and whitespace
        line="$(printf '%s' "$line" | sed -E 's/#.*$//' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | awk '{print $1}')"
        
        # Skip if empty after stripping
        [[ -z "$line" ]] && continue
        
        # Basic CIDR validation
        if [[ ! "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            print_warning "Invalid format: $line (expected: x.x.x.x/xx)"
            continue
        fi
        
        vlans_raw+="$line"$'\n'
        ((count++)) || true
        print_success "Added: $line"
    done
    
    if [[ -z "$vlans_raw" ]] || [[ $count -eq 0 ]]; then
        echo
        print_warning "No VLANs provided. Skipping VLAN configuration."
        return 0
    fi
    
    # Normalize: sort/unique
    local vlans
    vlans="$(printf '%s' "$vlans_raw" | sed -E '/^[[:space:]]*$/d' | sort -u)"
    
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
        echo "# Managed by lab/unbound.sh - do not edit manually"
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
    
    echo -ne "${C_CYAN}Write this configuration to $outfile? (yes/no): ${C_RESET}"
    read -r confirm
    
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
        print_warning "Aborted. Nothing written."
        rm -f "$tmp_file"
        return 0
    fi
    
    if [[ -f "$outfile" ]]; then
        echo
        print_warning "File already exists: $outfile"
        echo -ne "${C_CYAN}Overwrite it? (yes/no): ${C_RESET}"
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
    log SUCCESS "VLAN configuration installed: $outfile"
    log INFO "Loaded VLANs: $loaded"
    log INFO "Reverse zones (/24): $reverse24"
    if (( skipped > 0 )); then
        log WARN "Skipped entries: $skipped"
    fi
}

#############################################################################
# Static Hosts Configuration Helper                                         #
#############################################################################

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
        echo -ne "${C_CYAN}Enter your local domain name (e.g., home.local, lan.example.com): ${C_RESET}"
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
    
    log SUCCESS "Domain set to: $domain"
    echo
    draw_separator
    echo
    print_info "Now enter your host entries (IP and hostname)."
    print_info "When finished, press Enter on an empty line."
    echo
    print_info "Format: IP_ADDRESS  HOSTNAME"
    print_info "Examples:"
    echo "  192.168.1.10    nas"
    echo "  192.168.1.20    proxmox"
    echo "  192.168.1.30    printer"
    echo
    draw_separator
    
    local hosts_raw=""
    local line
    local count=0
    
    while true; do
        echo -ne "\n${C_CYAN}Host $((count + 1)) (or Enter to finish): ${C_RESET}"
        read -r line
        
        # Empty line = done
        [[ -z "$line" ]] && break
        
        # Strip leading/trailing whitespace
        line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        
        # Skip if empty after stripping
        [[ -z "$line" ]] && continue
        
        # Basic validation: need at least IP and hostname
        local ip hostname
        ip="$(printf '%s' "$line" | awk '{print $1}')"
        hostname="$(printf '%s' "$line" | awk '{print $2}')"
        
        if [[ -z "$ip" ]] || [[ -z "$hostname" ]]; then
            print_warning "Invalid format: need 'IP HOSTNAME'"
            continue
        fi
        
        # Basic IP validation
        if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_warning "Invalid IP format: $ip"
            continue
        fi
        
        hosts_raw+="$ip	$hostname"$'\n'
        ((count++)) || true
        print_success "Added: $ip -> $hostname"
    done
    
    if [[ -z "$hosts_raw" ]] || [[ $count -eq 0 ]]; then
        echo
        print_warning "No hosts provided. Skipping static hosts configuration."
        return 0
    fi
    
    # Normalize and sort by IP
    local hosts
    hosts="$(
        printf '%s' "$hosts_raw" |
        sed -E '/^[[:space:]]*$/d' |
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
    log SUCCESS "Hosts received (sorted by IP)."
    
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
        echo "# Managed by lab/unbound.sh - do not edit manually"
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
    
    echo -ne "${C_CYAN}Write this configuration to $outfile? (yes/no): ${C_RESET}"
    read -r confirm
    
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
        print_warning "Aborted. Nothing written."
        rm -f "$tmp_file"
        return 0
    fi
    
    if [[ -f "$outfile" ]]; then
        echo
        print_warning "File already exists: $outfile"
        echo -ne "${C_CYAN}Overwrite it? (yes/no): ${C_RESET}"
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
    log SUCCESS "Static hosts configuration installed: $outfile"
    log INFO "Loaded hosts: $loaded"
    if (( skipped > 0 )); then
        log WARN "Skipped entries: $skipped"
    fi
}

#############################################################################
# Post-Installation Configuration Menu                                      #
#############################################################################

post_install_config() {
    print_header "Additional Configuration"
    
    # Skip in silent mode
    if is_silent; then
        log INFO "Skipping additional configuration (silent mode)"
        return 0
    fi
    
    echo
    print_info "Unbound is now installed and running with default settings."
    print_info "You can optionally configure the following now or later:"
    echo
    echo "  1) Configure VLANs - Allow other network subnets to use this DNS server"
    echo "  2) Configure Static Hosts - Add local DNS records for your infrastructure"
    echo "  3) Skip - Configure these later manually"
    echo
    
    while true; do
        echo -ne "${C_CYAN}Select option [1-3]: ${C_RESET}"
        read -r choice
        
        case "$choice" in
            1)
                configure_vlans
                echo
                echo -ne "${C_CYAN}Would you also like to configure static hosts? (yes/no): ${C_RESET}"
                read -r also_hosts
                if [[ "${also_hosts,,}" == "y" || "${also_hosts,,}" == "yes" ]]; then
                    configure_static_hosts
                fi
                break
                ;;
            2)
                configure_static_hosts
                echo
                echo -ne "${C_CYAN}Would you also like to configure VLANs? (yes/no): ${C_RESET}"
                read -r also_vlans
                if [[ "${also_vlans,,}" == "y" || "${also_vlans,,}" == "yes" ]]; then
                    configure_vlans
                fi
                break
                ;;
            3)
                print_info "Skipping additional configuration."
                print_info "You can configure these later by running:"
                echo "  ${C_CYAN}./unbound.sh --vlans${C_RESET}"
                echo "  ${C_CYAN}./unbound.sh --hosts${C_RESET}"
                break
                ;;
            *)
                print_error "Invalid choice. Please select 1, 2, or 3."
                ;;
        esac
    done
}

#############################################################################
# Prompt for Reboot                                                         #
#############################################################################

prompt_reboot() {
    # Skip if environment variable set or silent mode
    if [[ "${UNBOUND_SKIP_REBOOT:-}" == "true" ]] || is_silent; then
        log INFO "Skipping reboot prompt"
        return 0
    fi
    
    echo
    while true; do
        echo -ne "${C_CYAN}Do you want to reboot the server now (recommended)? (yes/no): ${C_RESET}"
        read -r response
        echo
        
        case "${response,,}" in
            yes|y)
                log INFO "Rebooting the server..."
                sudo reboot
                exit 0
                ;;
            no|n)
                log INFO "Reboot cancelled"
                print_warning "A reboot is recommended to ensure all changes take effect"
                return 0
                ;;
            *)
                print_error "Invalid response. Please answer yes or no."
                ;;
        esac
    done
}

#############################################################################
# Post-Install Commands                                                     #
#############################################################################

cmd_status() {
    print_header "Unbound DNS Status"
    
    local version
    version=$(unbound -V 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    
    print_kv "Version" "$version"
    print_kv "Service Status" "$(systemctl is-active unbound 2>/dev/null || echo 'unknown')"
    print_kv "Enabled" "$(systemctl is-enabled unbound 2>/dev/null || echo 'unknown')"
    
    echo
    print_header "Access Information"
    print_kv "DNS Server" "$(get_local_ip)"
    print_kv "Port" "53 (TCP/UDP)"
    
    echo
    print_header "Configuration Files"
    print_kv "Main Config" "/etc/unbound/unbound.conf"
    print_kv "VLAN Config" "/etc/unbound/unbound.conf.d/vlans.conf"
    print_kv "Static Hosts" "/etc/unbound/unbound.conf.d/30-static-hosts.conf"
    
    echo
    print_header "Quick Test"
    echo "  ${C_CYAN}dig @127.0.0.1 google.com${C_RESET}"
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "Unbound Logs (last $lines lines)"
    echo
    
    sudo journalctl -u unbound -n "$lines" --no-pager
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    post_install_config
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall Unbound"
    
    if ! command_exists unbound; then
        print_info "Unbound is not installed"
        exit 0
    fi
    
    print_warning "This will remove:"
    print_subheader "Unbound package"
    print_subheader "Configuration files in /etc/unbound/"
    print_subheader "Firewall rules (if UFW active)"
    
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
    sudo systemctl stop unbound 2>/dev/null || true
    sudo systemctl disable unbound 2>/dev/null || true
    
    # Remove package
    print_step "Removing unbound package..."
    sudo apt-get remove --purge -y unbound unbound-anchor 2>/dev/null || true
    sudo apt-get autoremove -y 2>/dev/null || true
    
    # Remove configuration
    print_step "Removing configuration files..."
    sudo rm -rf /etc/unbound 2>/dev/null || true
    
    # Remove cron entry
    print_step "Removing cron entry..."
    if crontab -l 2>/dev/null | grep -q "root.hints.*unbound"; then
        crontab -l 2>/dev/null | grep -v "root.hints.*unbound" | grep -v "# Update root hints" | crontab - 2>/dev/null || true
    fi
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow 53/tcp 2>/dev/null || true
        sudo ufw delete allow 53/udp 2>/dev/null || true
    fi
    
    log SUCCESS "Unbound has been removed"
    echo
}

#############################################################################
# Main Function                                                             #
#############################################################################

main() {
    # Handle post-install commands
    case "${1:-}" in
        --status)
            cmd_status
            exit 0
            ;;
        --logs)
            cmd_logs "${2:-50}"
            exit 0
            ;;
        --configure|--config|-c)
            setup_logging
            cmd_configure
            exit 0
            ;;
        --vlans)
            setup_logging
            configure_vlans
            exit 0
            ;;
        --hosts)
            setup_logging
            configure_static_hosts
            exit 0
            ;;
        --uninstall)
            setup_logging
            cmd_uninstall
            exit 0
            ;;
        --version|-v)
            echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
        "")
            ;; # Continue with installation
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
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
    if command_exists unbound && service_is_active unbound; then
        print_header "Unbound Already Installed"
        print_info "Unbound is already installed and running."
        echo
        print_info "Available options:"
        echo "  ${C_CYAN}./unbound.sh --status${C_RESET}      Show status"
        echo "  ${C_CYAN}./unbound.sh --configure${C_RESET}   Configure VLANs/hosts"
        echo "  ${C_CYAN}./unbound.sh --uninstall${C_RESET}   Remove Unbound"
        echo
        
        if ! is_silent; then
            echo -ne "${C_CYAN}Run configuration menu? (yes/no): ${C_RESET}"
            read -r run_config
            if [[ "${run_config,,}" == "y" || "${run_config,,}" == "yes" ]]; then
                setup_logging
                cmd_configure
            fi
        fi
        exit 0
    fi
    
    clear
    draw_box "Unbound DNS Resolver Installer v${SCRIPT_VERSION}"
    
    # Setup logging
    setup_logging
    
    # Run all installation steps
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
    
    log INFO "Unbound installation completed successfully"
    
    # Offer additional configuration
    post_install_config
    
    prompt_reboot
}

main "$@"
