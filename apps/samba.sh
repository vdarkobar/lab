#!/bin/bash

###################################################################################
# Samba File Server Installer                                                     #
###################################################################################

readonly SCRIPT_VERSION="4.0.0"

# Handle --help flag early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "Samba File Server Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help|--status|--logs|--configure|--uninstall]"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Samba File Server\""
        echo "  Or run directly: ./samba.sh"
        echo
        echo "Interactive mode (default):"
        echo "  Prompts for share name, path, group, workgroup, and user creation"
        echo
        echo "Environment variables (for non-interactive/automation):"
        echo "  SAMBA_SHARE_NAME     Share name (e.g., \"Data\")"
        echo "  SAMBA_SHARE_PATH     Filesystem path (e.g., \"/srv/samba/Data\")"
        echo "  SAMBA_GROUP          Linux group (e.g., \"sambashare\")"
        echo "  SAMBA_WORKGROUP      SMB workgroup (default: WORKGROUP)"
        echo "  SAMBA_SERVER_NAME    NetBIOS name (default: FILESERVER)"
        echo "  SAMBA_MIN_PROTOCOL   Minimum SMB version (default: SMB3)"
        echo "  SAMBA_ENABLE_NETBIOS Enable NetBIOS/nmbd (default: false)"
        echo "  SAMBA_SKIP_UFW       Skip UFW configuration (default: false)"
        echo "  SAMBA_SILENT         Run non-interactively (default: false)"
        echo
        echo "Post-install commands:"
        echo "  --status      Show Samba status, shares, and connected users"
        echo "  --logs [N]    Show last N lines of logs (default: 50)"
        echo "  --configure   Reconfigure share settings"
        echo "  --uninstall   Remove Samba and clean up"
        echo
        echo "Examples:"
        echo "  # Interactive installation"
        echo "  ./samba.sh"
        echo
        echo "  # Automated installation"
        echo "  SAMBA_SHARE_NAME=Data SAMBA_GROUP=team SAMBA_SILENT=true ./samba.sh"
        echo
        echo "Access:"
        echo "  Windows:  \\\\<server-ip>\\<share>"
        echo "  Linux:    smb://<server-ip>/<share>"
        echo
        echo "Files created:"
        echo "  /etc/samba/smb.conf       Samba configuration"
        echo "  /srv/samba/<share>        Share directory"
        echo "  /var/log/samba/           Log files"
        echo "  /var/log/lab/samba-*.log  Installation log"
        exit 0
        ;;
esac

###################################################################################
#                                                                                 #
# DESCRIPTION:                                                                    #
#   Installs and configures Samba file server with security-hardened settings.   #
#   Supports both interactive and automated (silent) installation modes.          #
#                                                                                 #
# LOCATION: lab/apps/samba.sh                                                     #
# REPOSITORY: https://github.com/vdarkobar/lab                                    #
#                                                                                 #
# EXECUTION REQUIREMENTS:                                                         #
#   - Must be run as a NON-ROOT user                                              #
#   - User must have sudo privileges                                              #
#   - Script will use sudo internally for privileged operations                   #
#                                                                                 #
# CORRECT USAGE:                                                                  #
#   ./samba.sh                                                                    #
#                                                                                 #
# INCORRECT USAGE:                                                                #
#   sudo ./samba.sh  ← DO NOT DO THIS                                             #
#   # ./samba.sh     ← DO NOT DO THIS                                             #
#                                                                                 #
# REQUIREMENTS:                                                                   #
#   - Debian 12 (Bookworm) or Debian 13 (Trixie)                                 #
#   - Sudo privileges                                                             #
#   - Minimum 100MB disk space                                                    #
#                                                                                 #
# VERSION: 4.0.0                                                                  #
# LICENSE: MIT                                                                    #
#                                                                                 #
###################################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

###################################################################################
# Script Configuration                                                            #
###################################################################################

readonly SCRIPT_NAME="samba"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Samba paths
readonly SAMBA_CONF="/etc/samba/smb.conf"
readonly SAMBA_CONF_DIR="/etc/samba"

# Security settings (hardcoded for security)
readonly SERVER_SIGNING="auto"
readonly SMB_ENCRYPTION="desired"

# Environment variable defaults (can be overridden)
# Using SAMBA_ prefix to avoid conflicts with shell environment
SHARE_NAME="${SAMBA_SHARE_NAME:-}"
SHARE_PATH="${SAMBA_SHARE_PATH:-}"
SAMBA_GROUP="${SAMBA_GROUP:-}"
WORKGROUP="${SAMBA_WORKGROUP:-WORKGROUP}"
SERVER_NAME="${SAMBA_SERVER_NAME:-FILESERVER}"
MIN_PROTOCOL="${SAMBA_MIN_PROTOCOL:-SMB3}"
ENABLE_NETBIOS="${SAMBA_ENABLE_NETBIOS:-false}"
SKIP_FIREWALL="${SAMBA_SKIP_UFW:-false}"
SILENT_MODE="${SAMBA_SILENT:-false}"

# Export for non-interactive apt
export DEBIAN_FRONTEND=noninteractive

###################################################################################
# Terminal Formatting (embedded - no external dependency)                         #
###################################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    # Colors
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    # Foreground colors
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_CYAN=$(tput setaf 6)
    readonly C_WHITE=$(tput setaf 7)
    
    # Bright colors (if supported)
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

###################################################################################
# Output Functions                                                                #
###################################################################################

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

###################################################################################
# Visual Elements                                                                 #
###################################################################################

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

###################################################################################
# Logging                                                                         #
###################################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
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
    log ERROR "$@"
    exit 1
}

# Error trap for better debugging
trap 'print_error "Error on line $LINENO: $BASH_COMMAND"' ERR

###################################################################################
# Cleanup Handler                                                                 #
###################################################################################

cleanup() {
    local exit_code=$?
    
    # Restore unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restored unattended-upgrades service"
        fi
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

###################################################################################
# Helper Functions                                                                #
###################################################################################

is_silent() {
    [[ "$SILENT_MODE" == "true" ]]
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

get_local_ip() {
    # Better IP detection: use ip route to find the interface that reaches the internet
    local ip_address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    # Fallback to hostname -I if ip route fails
    [[ -z "$ip_address" ]] && ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip_address=${ip_address:-"localhost"}
    echo "$ip_address"
}

###################################################################################
# Setup Logging Directory                                                         #
###################################################################################

setup_logging() {
    # Create log directory with sudo
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
    fi
    
    # Create log file and set ownership to current user
    sudo touch "$LOG_FILE" 2>/dev/null || true
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE" 2>/dev/null || true
    sudo chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    log INFO "=== Samba File Server Installation Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
}

###################################################################################
# Pre-flight Checks                                                               #
###################################################################################

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
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access, run as root:"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# Then logout and login again${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Test sudo authentication
    if ! sudo -n true 2>/dev/null; then
        print_info "Sudo authentication required"
        if ! sudo -v; then
            die "Sudo authentication failed"
        fi
    fi
    print_success "Sudo authentication successful"
    
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command_exists pveversion; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on Proxmox host"
    
    # Check for systemd
    if ! command_exists systemctl; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    print_success "systemd available"
    
    # Check Debian version
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian. Detected: $ID"
        else
            local version_id="${VERSION_ID:-unknown}"
            if [[ ! "$version_id" =~ ^(12|13)$ ]]; then
                print_warning "Script tested on Debian 12/13, you have version $version_id"
            fi
            print_success "Debian system detected: ${VERSION:-unknown}"
        fi
    else
        print_warning "Cannot determine OS version"
    fi
    
    # Detect environment (LXC vs VM)
    local is_lxc=false
    if [[ -f /proc/1/environ ]] && grep -qa "container=lxc" /proc/1/environ 2>/dev/null; then
        is_lxc=true
        print_info "Environment: LXC Container"
    elif systemd-detect-virt -c &>/dev/null; then
        is_lxc=true
        print_info "Environment: Container"
    else
        print_info "Environment: VM or Bare Metal"
    fi
    export IS_LXC="$is_lxc"
    
    # Check disk space (need at least 100MB free)
    local free_space
    free_space=$(df / | awk 'NR==2 {print $4}')
    local free_mb=$((free_space / 1024))
    if [[ $free_space -lt 102400 ]]; then
        die "Insufficient disk space. Need at least 100MB free, have ${free_mb}MB"
    fi
    print_success "Sufficient disk space available (${free_mb}MB free)"
    
    echo
}

###################################################################################
# Show Introduction                                                               #
###################################################################################

show_intro() {
    clear
    
    draw_box "Samba File Server Installer v${SCRIPT_VERSION}"
    
    echo
    print_header "System Information"
    print_kv "IP Address" "$(get_local_ip)"
    print_kv "Hostname" "$(hostname -s)"
    print_kv "Executing User" "$(whoami)"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_kv "OS" "${PRETTY_NAME:-$ID}"
    fi
    
    echo
    print_header "Installation Steps"
    print_subheader "Install Samba packages"
    print_subheader "Configure share directory"
    print_subheader "Generate secure configuration"
    print_subheader "Configure firewall rules"
    print_subheader "Start Samba services"
    print_subheader "Create Samba users (optional)"
    
    echo
    print_header "Requirements"
    print_warning "Script must run as non-root user (currently: $(whoami))"
    print_warning "User must have sudo privileges"
    
    echo
    print_info "Logs will be saved to: ${C_DIM}${LOG_FILE}${C_RESET}"
    echo
}

###################################################################################
# Confirm Script Execution                                                        #
###################################################################################

confirm_start() {
    draw_separator
    echo
    while true; do
        echo -n "${C_BOLD}${C_CYAN}Proceed with installation? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r choice
        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        
        case "$choice" in
            yes|y)
                log INFO "User confirmed, starting installation..."
                echo
                return 0
                ;;
            no|n)
                log INFO "User cancelled installation"
                print_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                print_error "Invalid input. Please enter 'yes' or 'no'"
                ;;
        esac
    done
}

###################################################################################
# Interactive Configuration                                                       #
###################################################################################

configure_interactive() {
    print_header "Share Configuration"
    
    # Share name
    if [[ -z "$SHARE_NAME" ]]; then
        echo
        print_info "Enter the name for your SMB share (visible to clients)"
        while true; do
            echo -ne "${C_CYAN}Share name [default: Share]: ${C_RESET}"
            read -r input
            SHARE_NAME="${input:-Share}"
            
            # Validate share name (no spaces or special chars)
            if [[ "$SHARE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                break
            else
                print_error "Share name can only contain letters, numbers, underscore, and dash"
            fi
        done
    fi
    print_success "Share name: $SHARE_NAME"
    
    # Share path
    if [[ -z "$SHARE_PATH" ]]; then
        local default_path="/srv/samba/${SHARE_NAME}"
        echo
        print_info "Enter the directory path on this server where shared files will be stored"
        echo -ne "${C_CYAN}Share path [default: $default_path]: ${C_RESET}"
        read -r input
        SHARE_PATH="${input:-$default_path}"
    fi
    print_success "Share path: $SHARE_PATH"
    
    # Samba group
    if [[ -z "$SAMBA_GROUP" ]]; then
        echo
        print_info "Enter the Linux group that will have access to the share"
        while true; do
            echo -ne "${C_CYAN}Group name [default: sambashare]: ${C_RESET}"
            read -r input
            SAMBA_GROUP="${input:-sambashare}"
            
            # Validate group name
            if [[ "$SAMBA_GROUP" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                break
            else
                print_error "Group name must start with letter/underscore and contain only lowercase letters, numbers, underscore, dash"
            fi
        done
    fi
    print_success "Group: $SAMBA_GROUP"
    
    # Workgroup
    if [[ "$WORKGROUP" == "WORKGROUP" ]] && ! is_silent; then
        echo
        print_info "Enter the SMB workgroup name (should match your network)"
        echo -ne "${C_CYAN}Workgroup [default: WORKGROUP]: ${C_RESET}"
        read -r input
        WORKGROUP="${input:-WORKGROUP}"
    fi
    print_success "Workgroup: $WORKGROUP"
    
    echo
}

###################################################################################
# Install Packages                                                                #
###################################################################################

install_packages() {
    print_header "Installing Packages"
    
    # Stop unattended upgrades if running (track state to restart later)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
    # Wait for apt lock
    local wait_count=0
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt lock to be released..."
        fi
        sleep 2
        ((wait_count++))
        if [[ $wait_count -gt 30 ]]; then
            die "Timed out waiting for apt lock"
        fi
    done
    
    local packages=(samba samba-common-bin smbclient cifs-utils acl attr)
    local packages_to_install=()
    
    # Check which packages need installation (quiet check)
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            packages_to_install+=("$pkg")
        fi
    done
    
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        print_step "Installing ${#packages_to_install[@]} packages..."
        
        if ! sudo apt-get update -qq 2>>"$LOG_FILE"; then
            die "Failed to update package lists"
        fi
        
        if ! sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -qq "${packages_to_install[@]}" 2>>"$LOG_FILE"; then
            die "Package installation failed"
        fi
        log SUCCESS "Packages installed"
    else
        print_success "All packages already installed"
    fi
    
    echo
}

###################################################################################
# Create Share Directory                                                          #
###################################################################################

create_share_directory() {
    print_header "Configuring Share Directory"
    
    print_kv "Share path" "$SHARE_PATH"
    
    # Create directory if it doesn't exist
    if [[ ! -d "$SHARE_PATH" ]]; then
        sudo mkdir -p "$SHARE_PATH"
        print_success "Created directory: $SHARE_PATH"
    else
        print_info "Directory already exists"
    fi
    
    # Create group if it doesn't exist
    if ! getent group "$SAMBA_GROUP" >/dev/null 2>&1; then
        sudo groupadd "$SAMBA_GROUP"
        print_success "Created group: $SAMBA_GROUP"
    else
        print_info "Group already exists: $SAMBA_GROUP"
    fi
    
    # Set ownership and permissions
    print_step "Setting permissions..."
    sudo chown root:"$SAMBA_GROUP" "$SHARE_PATH"
    sudo chmod 2775 "$SHARE_PATH"
    print_success "Ownership set to root:$SAMBA_GROUP with mode 2775"
    
    # Set ACLs for new files/directories
    if command_exists setfacl; then
        print_step "Setting default ACLs..."
        if sudo setfacl -d -m "g:${SAMBA_GROUP}:rwx" "$SHARE_PATH" 2>/dev/null; then
            print_success "Default group ACL set"
        else
            print_warning "Failed to set default group ACL"
        fi
        if sudo setfacl -d -m "m:rwx" "$SHARE_PATH" 2>/dev/null; then
            print_success "Default mask ACL set"
        else
            print_warning "Failed to set default mask"
        fi
    else
        print_warning "setfacl not available, skipping ACL configuration"
    fi
    
    echo
}

###################################################################################
# Generate Samba Configuration                                                    #
###################################################################################

generate_config() {
    print_header "Generating Samba Configuration"
    
    local temp_config
    temp_config=$(mktemp)
    
    # Conditionally include netbios name
    local netbios_config
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        netbios_config="netbios name = ${SERVER_NAME}"
    else
        netbios_config="# NetBIOS disabled"
    fi
    
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
   server max protocol = SMB3
   server signing = ${SERVER_SIGNING}
   client signing = ${SERVER_SIGNING}
   smb encrypt = ${SMB_ENCRYPTION}
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

    # Check if config changed
    local config_changed=false
    if [[ -f "$SAMBA_CONF" ]]; then
        if ! cmp -s "$temp_config" "$SAMBA_CONF"; then
            config_changed=true
            local backup_file="${SAMBA_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
            sudo cp "$SAMBA_CONF" "$backup_file"
            print_info "Config changed - backed up to: $backup_file"
        else
            print_info "Configuration unchanged"
        fi
    else
        config_changed=true
        print_info "Creating new configuration"
    fi
    
    if [[ "$config_changed" == "true" ]]; then
        sudo cp "$temp_config" "$SAMBA_CONF"
        sudo chmod 644 "$SAMBA_CONF"
        log SUCCESS "Configuration updated"
    fi
    
    rm -f "$temp_config"
    
    # Validate configuration
    print_step "Validating configuration..."
    if ! sudo testparm -s "$SAMBA_CONF" >/dev/null 2>&1; then
        die "Samba configuration validation failed - run 'testparm' for details"
    fi
    print_success "Configuration valid"
    
    # Export for later use
    export CONFIG_CHANGED="$config_changed"
    
    echo
}

###################################################################################
# Configure Firewall                                                              #
###################################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    if [[ "$SKIP_FIREWALL" == "true" ]]; then
        print_info "Firewall configuration skipped (SAMBA_SKIP_UFW=true)"
        echo
        return 0
    fi
    
    # Check if in LXC container
    if [[ "$IS_LXC" == "true" ]]; then
        print_warning "LXC container - configure firewall on Proxmox host"
        print_info "Required ports: TCP 445 (SMB)"
        if [[ "$ENABLE_NETBIOS" == "true" ]]; then
            print_info "NetBIOS ports: TCP 139, UDP 137, 138"
        fi
        echo
        return 0
    fi
    
    # Check if UFW command is available
    if ! command_exists ufw; then
        print_info "UFW not installed - skipping firewall configuration"
        echo
        return 0
    fi
    
    # Test if UFW is functional (may fail in unprivileged containers)
    if ! sudo ufw status >/dev/null 2>&1; then
        print_warning "UFW not functional in this environment"
        print_info "Configure firewall on the host instead"
        echo
        return 0
    fi
    
    # Check if UFW is active
    local ufw_status
    ufw_status=$(sudo ufw status 2>/dev/null)
    
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        print_info "UFW not active - skipping firewall configuration"
        echo
        return 0
    fi
    
    print_success "UFW is active"
    
    # Helper: Add UFW rule with comment (fallback to without comment if unsupported)
    add_ufw_rule() {
        local rule="$1"
        local comment="$2"
        
        # Check if rule already exists
        if echo "$ufw_status" | grep -qE "${rule}.*ALLOW"; then
            print_success "Rule already exists: $rule"
            return 0
        fi
        
        # Try with comment first (UFW 0.35+)
        if sudo ufw allow "$rule" comment "$comment" >/dev/null 2>&1; then
            print_success "Allowed $rule ($comment)"
            return 0
        fi
        
        # Fallback: try without comment
        if sudo ufw allow "$rule" >/dev/null 2>&1; then
            print_success "Allowed $rule"
            return 0
        fi
        
        print_warning "Failed to add rule for $rule"
        return 1
    }
    
    print_step "Adding firewall rules..."
    
    # Allow SMB (port 445)
    add_ufw_rule "445/tcp" "Samba SMB"
    
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        print_step "Adding NetBIOS ports..."
        add_ufw_rule "139/tcp" "Samba NetBIOS"
        add_ufw_rule "137/udp" "Samba NetBIOS"
        add_ufw_rule "138/udp" "Samba NetBIOS"
    fi
    
    log SUCCESS "Firewall configured"
    echo
}

###################################################################################
# Start Services                                                                  #
###################################################################################

start_services() {
    print_header "Starting Services"
    
    # Ensure log directory exists
    sudo mkdir -p /var/log/samba
    sudo chmod 755 /var/log/samba
    
    local services=("smbd.service")
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        services+=("nmbd.service")
        print_info "NetBIOS enabled - will start nmbd"
    else
        print_info "NetBIOS disabled - only starting smbd"
    fi
    
    # Enable services
    for service in "${services[@]}"; do
        if ! service_is_enabled "$service"; then
            print_step "Enabling $service..."
            sudo systemctl enable "$service" >/dev/null 2>&1 || print_warning "Failed to enable $service"
        fi
    done
    
    # Check if restart needed
    local need_restart=false
    if [[ "$CONFIG_CHANGED" == "true" ]]; then
        need_restart=true
    fi
    
    for service in "${services[@]}"; do
        if ! service_is_active "$service"; then
            need_restart=true
        fi
    done
    
    if [[ "$need_restart" == "true" ]]; then
        for service in "${services[@]}"; do
            print_step "Restarting $service..."
            if ! sudo systemctl restart "$service" 2>&1; then
                die "Failed to start $service - check 'systemctl status $service'"
            fi
        done
        log SUCCESS "Services restarted"
    else
        print_info "Services already running with current config"
    fi
    
    # Wait for services to stabilize
    sleep 2
    
    # Verify smbd is running
    if ! service_is_active smbd.service; then
        die "Samba service (smbd) failed to start"
    fi
    
    print_success "Samba services running"
    echo
}

###################################################################################
# Interactive User Creation                                                       #
###################################################################################

create_user_interactive() {
    if is_silent; then
        return 0
    fi
    
    print_header "Samba User Creation"
    
    echo
    print_info "Samba requires separate user accounts for authentication."
    print_info "Users must be added to the '$SAMBA_GROUP' group to access the share."
    echo
    
    while true; do
        echo -ne "${C_CYAN}Create a Samba user now? (yes/no) [default: yes]: ${C_RESET}"
        read -r response
        response="${response:-yes}"
        
        case "${response,,}" in
            yes|y)
                break
                ;;
            no|n)
                print_info "Skipping user creation"
                print_warning "Remember to create users later:"
                echo "  sudo useradd -M -s /usr/sbin/nologin -G $SAMBA_GROUP <username>"
                echo "  sudo smbpasswd -a <username>"
                echo "  sudo smbpasswd -e <username>"
                return 0
                ;;
            *)
                print_error "Please answer yes or no"
                ;;
        esac
    done
    
    while true; do
        echo
        echo -ne "${C_CYAN}Username: ${C_RESET}"
        read -r username
        
        if [[ -z "$username" ]]; then
            print_error "Username cannot be empty"
            continue
        fi
        
        # Validate username
        if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            print_error "Invalid username format (lowercase letters, numbers, underscore, dash)"
            continue
        fi
        
        if id "$username" &>/dev/null; then
            print_warning "User '$username' already exists in the system"
            
            # Check if already in samba group
            if id -nG "$username" | grep -qw "$SAMBA_GROUP"; then
                print_info "User already in $SAMBA_GROUP group"
            else
                print_step "Adding user to $SAMBA_GROUP group..."
                sudo usermod -aG "$SAMBA_GROUP" "$username"
            fi
            
            # Set Samba password
            print_step "Setting Samba password for: $username"
            echo
            if sudo smbpasswd -a "$username"; then
                sudo smbpasswd -e "$username"
                print_success "User '$username' configured and enabled"
            else
                print_error "Failed to set Samba password"
            fi
        else
            # Create system user
            print_step "Creating system user: $username"
            if sudo useradd -M -s /usr/sbin/nologin -G "$SAMBA_GROUP" "$username"; then
                print_success "System user created"
            else
                print_error "Failed to create system user"
                continue
            fi
            
            # Set Samba password
            print_step "Setting Samba password for: $username"
            echo
            if sudo smbpasswd -a "$username"; then
                sudo smbpasswd -e "$username"
                log SUCCESS "User '$username' created and enabled"
            else
                print_error "Failed to set Samba password"
            fi
        fi
        
        echo
        echo -ne "${C_CYAN}Create another user? (yes/no) [default: no]: ${C_RESET}"
        read -r create_another
        create_another="${create_another:-no}"
        
        if [[ ! "${create_another,,}" =~ ^(yes|y)$ ]]; then
            break
        fi
    done
    
    echo
}

###################################################################################
# Show Summary                                                                    #
###################################################################################

show_summary() {
    local server_ip
    server_ip=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Share Information"
    print_kv "Share Name" "$SHARE_NAME"
    print_kv "Share Path" "$SHARE_PATH"
    print_kv "Group" "$SAMBA_GROUP"
    print_kv "Workgroup" "$WORKGROUP"
    print_kv "Protocol" "$MIN_PROTOCOL minimum"
    print_kv "Server IP" "$server_ip"
    
    echo
    print_header "Access URLs"
    echo "  ${C_DIM}Windows:${C_RESET}  ${C_CYAN}\\\\${server_ip}\\${SHARE_NAME}${C_RESET}"
    echo "  ${C_DIM}Linux:${C_RESET}    ${C_CYAN}smb://${server_ip}/${SHARE_NAME}${C_RESET}"
    echo "  ${C_DIM}macOS:${C_RESET}    ${C_CYAN}smb://${server_ip}/${SHARE_NAME}${C_RESET}"
    
    echo
    print_header "Useful Commands"
    printf "  %b\n" "${C_DIM}# View status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./samba.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./samba.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Create new user${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo useradd -M -s /usr/sbin/nologin -G $SAMBA_GROUP <username>${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo smbpasswd -a <username>${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo smbpasswd -e <username>${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart service${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart smbd${C_RESET}"
    
    echo
    print_header "Service Status"
    print_kv "smbd" "$(systemctl is-active smbd.service 2>/dev/null || echo 'unknown')"
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        print_kv "nmbd" "$(systemctl is-active nmbd.service 2>/dev/null || echo 'unknown')"
    else
        print_kv "NetBIOS" "Disabled"
    fi
    
    echo
    draw_separator
    echo
}

###################################################################################
# Post-Install Commands                                                           #
###################################################################################

cmd_status() {
    print_header "Samba Status"
    
    # Check if installed
    if ! command_exists smbstatus; then
        die "Samba is not installed"
    fi
    
    # Version info
    local version
    version=$(smbd --version 2>/dev/null || echo "unknown")
    print_kv "Version" "$version"
    
    # Service status
    echo
    print_header "Service Status"
    if service_is_active smbd.service; then
        print_success "smbd: running"
    else
        print_warning "smbd: not running"
    fi
    
    if service_is_active nmbd.service; then
        print_success "nmbd: running"
    else
        print_info "nmbd: not running (NetBIOS disabled)"
    fi
    
    if service_is_enabled smbd.service; then
        print_success "Enabled: yes (starts on boot)"
    else
        print_warning "Enabled: no"
    fi
    
    # Show shares
    echo
    print_header "Configured Shares"
    if [[ -f "$SAMBA_CONF" ]]; then
        grep '^\[' "$SAMBA_CONF" | grep -v '\[global\]' | while read -r line; do
            local share_name="${line//[\[\]]/}"
            local share_path
            share_path=$(awk "/\[${share_name}\]/,/^\[/" "$SAMBA_CONF" | grep "path" | awk -F= '{print $2}' | xargs)
            print_kv "$share_name" "${share_path:-unknown}"
        done
    else
        print_warning "No configuration found"
    fi
    
    # Show connected users
    echo
    print_header "Connected Users"
    if sudo smbstatus -b 2>/dev/null | grep -q "^[0-9]"; then
        sudo smbstatus -b 2>/dev/null | tail -n +5
    else
        print_info "No users currently connected"
    fi
    
    # Show Samba users
    echo
    print_header "Configured Samba Users"
    if sudo pdbedit -L 2>/dev/null | head -10; then
        local user_count
        user_count=$(sudo pdbedit -L 2>/dev/null | wc -l)
        if [[ $user_count -gt 10 ]]; then
            print_info "... and $((user_count - 10)) more users"
        fi
    else
        print_info "No Samba users configured"
    fi
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "Samba Logs (last $lines lines)"
    echo
    
    # Check installation log first
    local latest_log
    latest_log=$(ls -t "${LOG_DIR}/${SCRIPT_NAME}"*.log 2>/dev/null | head -1)
    
    if [[ -n "$latest_log" ]] && [[ -f "$latest_log" ]]; then
        print_info "Installation log: $latest_log"
        echo "${C_DIM}"
        tail -n "$lines" "$latest_log"
        echo "${C_RESET}"
    fi
    
    echo
    print_header "Samba Service Logs"
    journalctl -u smbd -n "$lines" --no-pager 2>/dev/null || \
        print_warning "Unable to retrieve systemd logs"
    
    # Also check /var/log/samba if it exists
    if [[ -d /var/log/samba ]]; then
        echo
        print_header "Log Files in /var/log/samba/"
        ls -la /var/log/samba/ 2>/dev/null | head -20
    fi
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure Samba"
    
    print_warning "This will update the Samba configuration."
    print_info "A backup will be created before changes."
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_CYAN}Continue? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y)
                    break
                    ;;
                no|n)
                    print_info "Reconfiguration cancelled"
                    exit 0
                    ;;
                *)
                    print_error "Invalid input. Please enter 'yes' or 'no'"
                    ;;
            esac
        done
    fi
    
    # Clear existing config to force re-prompt
    SHARE_NAME=""
    SHARE_PATH=""
    SAMBA_GROUP=""
    
    # Run configuration steps
    configure_interactive
    create_share_directory
    generate_config
    start_services
    
    log SUCCESS "Samba reconfigured successfully"
    show_summary
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall Samba"
    
    print_warning "This will remove Samba packages and configuration."
    print_warning "Share directories will NOT be deleted."
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_RED}Are you sure? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y)
                    break
                    ;;
                no|n)
                    print_info "Uninstall cancelled"
                    exit 0
                    ;;
                *)
                    print_error "Invalid input. Please enter 'yes' or 'no'"
                    ;;
            esac
        done
    fi
    
    # Stop services
    print_step "Stopping Samba services..."
    sudo systemctl stop smbd 2>/dev/null || true
    sudo systemctl stop nmbd 2>/dev/null || true
    sudo systemctl disable smbd 2>/dev/null || true
    sudo systemctl disable nmbd 2>/dev/null || true
    
    # Remove packages
    print_step "Removing Samba packages..."
    sudo apt-get remove --purge -y samba samba-common-bin smbclient 2>/dev/null || true
    sudo apt-get autoremove -y 2>/dev/null || true
    
    # Backup and remove configuration
    if [[ -f "$SAMBA_CONF" ]]; then
        print_step "Backing up configuration..."
        sudo cp "$SAMBA_CONF" "${SAMBA_CONF}.uninstall.$(date +%Y%m%d_%H%M%S)"
    fi
    
    print_step "Removing configuration files..."
    sudo rm -rf /etc/samba 2>/dev/null || true
    sudo rm -rf /var/lib/samba 2>/dev/null || true
    sudo rm -rf /var/cache/samba 2>/dev/null || true
    
    # Remove firewall rules
    if command_exists ufw && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow 445/tcp 2>/dev/null || true
        sudo ufw delete allow 139/tcp 2>/dev/null || true
        sudo ufw delete allow 137/udp 2>/dev/null || true
        sudo ufw delete allow 138/udp 2>/dev/null || true
    fi
    
    echo
    log SUCCESS "Samba has been removed"
    print_warning "Share directories were preserved - remove manually if needed"
    echo
}

###################################################################################
# Main Execution                                                                  #
###################################################################################

main() {
    # Handle post-install commands (these don't need the full pre-flight)
    case "${1:-}" in
        --status)
            cmd_status
            exit 0
            ;;
        --logs)
            cmd_logs "${2:-50}"
            exit 0
            ;;
        --configure)
            cmd_configure
            exit 0
            ;;
        --uninstall)
            cmd_uninstall
            exit 0
            ;;
        --version|-v)
            echo "samba.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
        "")
            # Continue with installation
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
    
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
    
    # Check if Samba is already installed and running
    if command -v smbd >/dev/null 2>&1 && systemctl is-active --quiet smbd 2>/dev/null; then
        clear
        draw_box "Samba File Server - Already Installed"
        
        local version
        version=$(smbd --version 2>/dev/null || echo "unknown")
        
        echo
        print_header "Current Installation"
        print_kv "Version" "$version"
        print_kv "Service Status" "$(systemctl is-active smbd 2>/dev/null || echo 'unknown')"
        print_kv "Enabled" "$(systemctl is-enabled smbd 2>/dev/null || echo 'unknown')"
        
        # Show configured shares
        if [[ -f "$SAMBA_CONF" ]]; then
            echo
            print_header "Configured Shares"
            grep '^\[' "$SAMBA_CONF" | grep -v '\[global\]' | while read -r line; do
                local share_name="${line//[\[\]]/}"
                local share_path
                share_path=$(awk "/\[${share_name}\]/,/^\[/" "$SAMBA_CONF" | grep "path" | awk -F= '{print $2}' | xargs)
                print_kv "$share_name" "${share_path:-unknown}"
            done
        fi
        
        echo
        print_header "Management Commands"
        printf "  %b\n" "${C_DIM}# View status${C_RESET}"
        printf "  %b\n" "${C_CYAN}./samba.sh --status${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
        printf "  %b\n" "${C_CYAN}./samba.sh --logs${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Reconfigure${C_RESET}"
        printf "  %b\n" "${C_CYAN}./samba.sh --configure${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Add new user${C_RESET}"
        printf "  %b\n" "${C_CYAN}sudo useradd -M -s /usr/sbin/nologin -G <group> <username>${C_RESET}"
        printf "  %b\n" "${C_CYAN}sudo smbpasswd -a <username>${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
        printf "  %b\n" "${C_CYAN}./samba.sh --uninstall${C_RESET}"
        
        echo
        print_info "To reinstall, first uninstall the existing installation:"
        printf "  %b\n" "${C_CYAN}./samba.sh --uninstall${C_RESET}"
        printf "  %b\n" "${C_CYAN}./samba.sh${C_RESET}"
        echo
        exit 0
    fi
    
    # Setup logging
    setup_logging
    
    # Show introduction (unless silent)
    if ! is_silent; then
        show_intro
        confirm_start
    fi
    
    # Run installation steps
    preflight_checks
    configure_interactive
    install_packages
    create_share_directory
    generate_config
    configure_firewall
    start_services
    
    # Show summary
    show_summary
    
    # Interactive user creation
    create_user_interactive
    
    log INFO "=== Samba File Server Installation Completed ==="
}

# Run main function
main "$@"
