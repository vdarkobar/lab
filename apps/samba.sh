#!/bin/bash

#############################################################################
# Samba File Server Installer                                               #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# Compatible with: Debian 12/13 (VM/LXC)                                    #
#############################################################################

readonly VERSION="3.2.0"

# Handle --help flag early (before sourcing libraries)
case "${1:-}" in
    --help|-h)
        echo "Samba File Server Installer v${VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Samba File Server\""
        echo
        echo "Environment variables:"
        echo "  SHARE_NAME        Share name (default: Share)"
        echo "  SHARE_PATH        Filesystem path (default: /srv/samba/\$SHARE_NAME)"
        echo "  SAMBA_GROUP       Linux group (default: sambashare)"
        echo "  WORKGROUP         SMB workgroup (default: WORKGROUP)"
        echo "  SERVER_NAME       NetBIOS name (default: FILESERVER)"
        echo "  MIN_PROTOCOL      Minimum SMB version (default: SMB3)"
        echo "  ENABLE_NETBIOS    Enable NetBIOS/nmbd (default: false)"
        echo "  SKIP_FIREWALL     Skip UFW configuration (default: false)"
        echo "  QUIET_MODE        Minimal output (default: false)"
        echo "  CREATE_SAMBA_USER Interactive user creation (default: false)"
        echo
        echo "Examples:"
        echo "  $0                                    # Basic install"
        echo "  SHARE_NAME=Data WORKGROUP=OFFICE $0  # Custom share"
        echo "  CREATE_SAMBA_USER=true $0            # With user creation"
        echo
        echo "Post-install - Create users:"
        echo "  sudo useradd -M -s /usr/sbin/nologin -G sambashare alice"
        echo "  sudo smbpasswd -a alice"
        echo "  sudo smbpasswd -e alice"
        echo
        echo "Access:"
        echo "  Windows:  \\\\<server-ip>\\Share"
        echo "  Linux:    smb://<server-ip>/Share"
        echo
        echo "Files created:"
        echo "  /etc/samba/smb.conf       Samba configuration"
        echo "  /srv/samba/<share>        Share directory"
        echo "  /var/log/samba/           Log files"
        exit 0
        ;;
esac

set -euo pipefail

#############################################################################
# Resolve Script Directory and Load Formatting Library                      #
#############################################################################

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
    print_header() { echo -e "\n━━━ $1 ━━━"; }
    print_success() { echo "✓ $1"; }
    print_error() { echo "✗ $1" >&2; }
    print_warning() { echo "⚠ $1"; }
    print_info() { echo "ℹ $1"; }
    print_step() { echo "→ $1"; }
    print_subheader() { echo "  • $1"; }
    print_kv() { printf "%-20s %s\n" "$1:" "$2"; }
    draw_separator() { echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
    die() { print_error "$1"; exit 1; }
fi

#############################################################################
# Configuration                                                             #
#############################################################################

SHARE_NAME="${SHARE_NAME:-Share}"
SHARE_PATH="${SHARE_PATH:-/srv/samba/${SHARE_NAME}}"
SAMBA_GROUP="${SAMBA_GROUP:-sambashare}"
WORKGROUP="${WORKGROUP:-WORKGROUP}"
SERVER_NAME="${SERVER_NAME:-FILESERVER}"
MIN_PROTOCOL="${MIN_PROTOCOL:-SMB3}"
ENABLE_NETBIOS="${ENABLE_NETBIOS:-false}"
SKIP_FIREWALL="${SKIP_FIREWALL:-false}"
QUIET_MODE="${QUIET_MODE:-false}"
CREATE_SAMBA_USER="${CREATE_SAMBA_USER:-false}"

# Security settings
readonly SERVER_SIGNING="auto"
readonly SMB_ENCRYPTION="desired"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="$LOG_DIR/samba.log"

#############################################################################
# Logging Functions                                                         #
#############################################################################

setup_logging() {
    sudo mkdir -p "$LOG_DIR"
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    echo "========================================" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "samba.sh started at $(date)" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "========================================" | sudo tee -a "$LOG_FILE" >/dev/null
}

log_msg() {
    local msg="$1"
    [[ "$QUIET_MODE" == "true" ]] && return
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $msg" | sudo tee -a "$LOG_FILE" >/dev/null
    print_info "$msg"
}

#############################################################################
# Preflight Checks                                                          #
#############################################################################

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
    
    # Detect OS
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS - /etc/os-release not found"
    fi
    
    source /etc/os-release
    local os_id="${ID:-unknown}"
    local os_version="${VERSION_ID:-unknown}"
    
    if [[ "$os_id" != "debian" ]]; then
        die "Unsupported OS: $os_id (only Debian supported)"
    fi
    
    if [[ ! "$os_version" =~ ^(12|13)$ ]]; then
        print_warning "Script tested on Debian 12/13, you have version $os_version"
    fi
    print_success "Detected: ${PRETTY_NAME:-Debian $os_version}"
    
    # Detect environment
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
    
    # Export for later use
    export IS_LXC="$is_lxc"
}

#############################################################################
# Package Installation                                                      #
#############################################################################

install_packages() {
    print_header "Installing Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    
    local packages=(samba samba-common-bin smbclient cifs-utils acl attr)
    local packages_to_install=()
    
    for pkg in "${packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            packages_to_install+=("$pkg")
        fi
    done
    
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        print_step "Updating package lists..."
        if ! sudo apt-get update -qq 2>/dev/null; then
            die "Failed to update package lists"
        fi
        
        print_step "Installing: ${packages_to_install[*]}"
        if ! sudo apt-get install -y -qq "${packages_to_install[@]}" 2>/dev/null; then
            die "Package installation failed"
        fi
        print_success "Packages installed successfully"
    else
        print_success "All required packages already installed"
    fi
}

#############################################################################
# Create Share Directory                                                    #
#############################################################################

create_share_directory() {
    print_header "Configuring Share Directory"
    
    print_info "Share path: $SHARE_PATH"
    
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
    sudo chown root:"$SAMBA_GROUP" "$SHARE_PATH"
    sudo chmod 2775 "$SHARE_PATH"
    print_success "Permissions set"
    
    # Set ACLs
    if command -v setfacl >/dev/null 2>&1; then
        print_step "Setting default ACLs..."
        sudo setfacl -d -m "g:${SAMBA_GROUP}:rwx" "$SHARE_PATH" 2>/dev/null || print_warning "Failed to set default group ACL"
        sudo setfacl -d -m "m:rwx" "$SHARE_PATH" 2>/dev/null || print_warning "Failed to set default mask"
        print_success "ACLs configured"
    fi
}

#############################################################################
# Generate Samba Configuration                                              #
#############################################################################

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
    if [[ -f /etc/samba/smb.conf ]]; then
        if ! cmp -s "$temp_config" /etc/samba/smb.conf; then
            config_changed=true
            local backup_file="/etc/samba/smb.conf.backup.$(date +%Y%m%d_%H%M%S)"
            sudo cp /etc/samba/smb.conf "$backup_file"
            print_info "Config changed - backed up to: $backup_file"
        else
            print_info "Configuration unchanged"
        fi
    else
        config_changed=true
        print_info "Creating new configuration"
    fi
    
    if [[ "$config_changed" == "true" ]]; then
        sudo cp "$temp_config" /etc/samba/smb.conf
        print_success "Configuration updated"
    fi
    
    rm -f "$temp_config"
    
    # Validate configuration
    print_step "Validating configuration..."
    if ! sudo testparm -s /etc/samba/smb.conf >/dev/null 2>&1; then
        die "Samba configuration validation failed - run 'testparm' for details"
    fi
    print_success "Configuration valid"
    
    # Export for later use
    export CONFIG_CHANGED="$config_changed"
}

#############################################################################
# Configure Firewall                                                        #
#############################################################################

configure_firewall() {
    print_header "Configuring Firewall"
    
    if [[ "$SKIP_FIREWALL" == "true" ]]; then
        print_info "Firewall configuration skipped (SKIP_FIREWALL=true)"
        return 0
    fi
    
    if [[ "$IS_LXC" == "true" ]]; then
        print_warning "LXC container - configure firewall on Proxmox host"
        print_info "Required ports: TCP 445 (SMB)"
        if [[ "$ENABLE_NETBIOS" == "true" ]]; then
            print_info "NetBIOS ports: TCP 139, UDP 137, 138"
        fi
        return 0
    fi
    
    if ! command -v ufw >/dev/null 2>&1; then
        print_info "UFW not installed - skipping firewall configuration"
        return 0
    fi
    
    if ! sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_info "UFW not active - skipping firewall configuration"
        return 0
    fi
    
    print_step "Opening port 445/tcp (SMB)..."
    sudo ufw allow 445/tcp comment 'Samba SMB' >/dev/null 2>&1 || sudo ufw allow 445/tcp >/dev/null 2>&1 || true
    
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        print_step "Opening NetBIOS ports..."
        sudo ufw allow 139/tcp comment 'Samba NetBIOS' >/dev/null 2>&1 || true
        sudo ufw allow 137/udp comment 'Samba NetBIOS' >/dev/null 2>&1 || true
        sudo ufw allow 138/udp comment 'Samba NetBIOS' >/dev/null 2>&1 || true
    fi
    
    print_success "Firewall configured"
}

#############################################################################
# Start Services                                                            #
#############################################################################

start_services() {
    print_header "Starting Services"
    
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
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            sudo systemctl enable "$service" >/dev/null 2>&1 || print_warning "Failed to enable $service"
        fi
    done
    
    # Check if restart needed
    local need_restart=false
    if [[ "$CONFIG_CHANGED" == "true" ]]; then
        need_restart=true
    fi
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
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
        print_success "Services restarted"
    else
        print_info "Services already running with current config"
    fi
    
    sleep 2
    
    if ! systemctl is-active --quiet smbd.service; then
        die "Samba service (smbd) failed to start"
    fi
    
    print_success "Samba services running"
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./) {print $i; exit}}')
    server_ip="${server_ip:-<server-ip>}"
    
    echo
    draw_separator
    print_success "Samba Installation Complete"
    draw_separator
    echo
    print_kv "Share Name" "$SHARE_NAME"
    print_kv "Share Path" "$SHARE_PATH"
    print_kv "Group" "$SAMBA_GROUP"
    print_kv "Workgroup" "$WORKGROUP"
    print_kv "Protocol" "$MIN_PROTOCOL minimum"
    echo
    print_header "Access"
    echo "  Windows:  \\\\$server_ip\\$SHARE_NAME"
    echo "  Linux:    smb://$server_ip/$SHARE_NAME"
    echo "  macOS:    smb://$server_ip/$SHARE_NAME"
    echo
    print_header "Create Users"
    echo "  sudo useradd -M -s /usr/sbin/nologin -G $SAMBA_GROUP <username>"
    echo "  sudo smbpasswd -a <username>"
    echo "  sudo smbpasswd -e <username>"
    echo
    print_header "Service Status"
    print_kv "smbd" "$(systemctl is-active smbd.service)"
    if [[ "$ENABLE_NETBIOS" == "true" ]]; then
        print_kv "nmbd" "$(systemctl is-active nmbd.service 2>/dev/null || echo 'disabled')"
    else
        print_kv "NetBIOS" "Disabled"
    fi
    echo
    draw_separator
}

#############################################################################
# Interactive User Creation                                                 #
#############################################################################

create_user_interactive() {
    if [[ "$CREATE_SAMBA_USER" != "true" ]] || [[ "$QUIET_MODE" == "true" ]]; then
        return 0
    fi
    
    print_header "Interactive User Creation"
    
    while true; do
        echo
        echo -ne "Create a Samba user (or press Enter to skip): "
        read -r username
        
        if [[ -z "$username" ]]; then
            print_info "Skipping user creation"
            break
        fi
        
        # Validate username
        if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            print_error "Invalid username format"
            continue
        fi
        
        if id "$username" &>/dev/null; then
            print_error "User '$username' already exists"
            continue
        fi
        
        print_step "Creating system user: $username"
        if sudo useradd -M -s /usr/sbin/nologin -G "$SAMBA_GROUP" "$username"; then
            print_success "System user created"
        else
            print_error "Failed to create system user"
            continue
        fi
        
        print_step "Setting Samba password for: $username"
        if sudo smbpasswd -a "$username"; then
            sudo smbpasswd -e "$username"
            print_success "User '$username' created successfully"
        else
            print_error "Failed to set Samba password"
        fi
        
        echo -ne "Create another user? (y/N): "
        read -r create_another
        if [[ ! "$create_another" =~ ^[Yy]$ ]]; then
            break
        fi
    done
}

#############################################################################
# Main                                                                      #
#############################################################################

main() {
    clear
    
    echo -e "\n━━━ Samba File Server Installer v${VERSION} ━━━\n"
    
    setup_logging
    preflight_checks
    install_packages
    create_share_directory
    generate_config
    configure_firewall
    start_services
    show_summary
    create_user_interactive
    
    log_msg "Samba installation completed successfully"
}

main "$@"
