#!/bin/bash

#############################################################################
# Debian LXC Template Creator for Proxmox VE                                #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Downloads the latest Debian LXC template                             #
#   2. Creates an unprivileged container with nesting                       #
#   3. Configures non-root user with sudo                                   #
#   4. Sets up Cloud-Init for SSH key regeneration                          #
#   5. Converts the container to a reusable template                        #
#                                                                           #
# REQUIREMENTS:                                                             #
#   - Proxmox VE host                                                       #
#   - SSH keys at /root/.ssh/authorized_keys                                #
#   - Storage configured for templates and rootfs                           #
#                                                                           #
# ENVIRONMENT VARIABLES (for non-interactive mode):                         #
#   DEBLXC_TEMPLATE_STORAGE  - Storage for templates (e.g., "local")        #
#   DEBLXC_ROOTFS_STORAGE    - Storage for rootfs (e.g., "local-lvm")       #
#   DEBLXC_CONTAINER_ID      - Container ID (e.g., "9000")                  #
#   DEBLXC_HOSTNAME          - Container hostname (e.g., "deblxc")          #
#   DEBLXC_USERNAME          - Non-root username                            #
#   DEBLXC_PASSWORD          - User password                                #
#   DEBLXC_BRIDGE            - Network bridge (e.g., "vmbr0")               #
#   DEBLXC_CORES             - CPU cores (default: 4)                       #
#   DEBLXC_MEMORY            - Memory in MB (default: 4096)                 #
#   DEBLXC_DISK              - Disk size in GB (default: 8)                 #
#############################################################################

set -Eeuo pipefail

#################################################################
# Resolve Script Directory and Load Formatting Library          #
#################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Try multiple locations for formatting library
if [[ -f "$REPO_ROOT/lib/formatting.sh" ]]; then
    source "$REPO_ROOT/lib/formatting.sh"
elif [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/../lib/formatting.sh"
elif [[ -f "/root/lab/lib/formatting.sh" ]]; then
    source "/root/lab/lib/formatting.sh"
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
readonly LOG_FILE="$LOG_DIR/deblxc.log"
readonly VERSION="1.0.0"

# Defaults (can be overridden via environment variables)
DEFAULT_HOSTNAME="deblxc"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_CORES="${DEBLXC_CORES:-4}"
DEFAULT_MEMORY="${DEBLXC_MEMORY:-4096}"
DEFAULT_SWAP="512"
DEFAULT_DISK="${DEBLXC_DISK:-8}"

# Reserved hostnames
RESERVED_NAMES=("localhost" "domain" "local" "host" "broadcasthost" "localdomain" "loopback" "wpad" "gateway" "dns" "mail" "ftp" "web")

#################################################################
# Logging Functions                                             #
#################################################################

setup_logging() {
    mkdir -p "$LOG_DIR"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "========================================" >> "$LOG_FILE"
    echo "deblxc.sh started at $(date)" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

#################################################################
# Cleanup and Error Handling                                    #
#################################################################

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Script failed with exit code: $exit_code"
        print_warning "Check log file: $LOG_FILE"
        
        # Clean up partial container if it exists and failed
        if [[ -n "${CONTAINER_ID:-}" ]] && pct status "$CONTAINER_ID" &>/dev/null; then
            print_warning "Partial container $CONTAINER_ID may exist - check manually"
        fi
    fi
    log "Script exited with code: $exit_code"
}

trap cleanup EXIT

die() {
    print_error "$1"
    exit 1
}

#################################################################
# Validation Functions                                          #
#################################################################

is_reserved_hostname() {
    local input_name="$1"
    for name in "${RESERVED_NAMES[@]}"; do
        if [[ "$input_name" == "$name" ]]; then
            return 0
        fi
    done
    return 1
}

validate_hostname() {
    local hostname="$1"
    
    if is_reserved_hostname "$hostname"; then
        return 1
    fi
    
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        return 0
    fi
    
    return 1
}

validate_username() {
    local username="$1"
    
    if [[ "$username" == "root" ]]; then
        return 1
    fi
    
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        return 0
    fi
    
    return 1
}

validate_password() {
    local password="$1"
    
    # Minimum 8 characters
    if [[ ${#password} -lt 8 ]]; then
        return 1
    fi
    
    # Must contain at least one number
    if ! [[ "$password" =~ [0-9] ]]; then
        return 1
    fi
    
    # Must contain at least one special character
    if ! [[ "$password" =~ [^a-zA-Z0-9] ]]; then
        return 1
    fi
    
    return 0
}

#################################################################
# Preflight Checks                                              #
#################################################################

preflight_checks() {
    print_header "Preflight Checks"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        die "This script must run on a Proxmox VE host"
    fi
    print_success "Proxmox VE detected"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        die "This script must run as root"
    fi
    print_success "Running as root"
    
    # Check for required commands
    local required_cmds=("pct" "pvesm" "pveam" "pvesh")
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            die "Required command not found: $cmd"
        fi
    done
    print_success "Required commands available"
    
    # Check for SSH keys
    if [[ ! -f /root/.ssh/authorized_keys ]]; then
        print_warning "No SSH keys found at /root/.ssh/authorized_keys"
        print_warning "Container will be created without SSH key injection"
        SSH_KEYS_AVAILABLE=false
    else
        print_success "SSH keys found"
        SSH_KEYS_AVAILABLE=true
    fi
    
    log "Preflight checks passed"
}

#################################################################
# Storage Selection                                             #
#################################################################

select_template_storage() {
    print_header "Template Storage Selection"
    
    local storage_list
    storage_list=$(pvesm status -content vztmpl | awk 'NR>1 {print NR-1 " " $1}')
    
    if [[ -z "$storage_list" ]]; then
        die "No template storage found"
    fi
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_TEMPLATE_STORAGE:-}" ]]; then
        if echo "$storage_list" | grep -qw "$DEBLXC_TEMPLATE_STORAGE"; then
            TEMPLATE_STORAGE="$DEBLXC_TEMPLATE_STORAGE"
            print_success "Using template storage: $TEMPLATE_STORAGE"
            return 0
        else
            die "Specified template storage not found: $DEBLXC_TEMPLATE_STORAGE"
        fi
    fi
    
    # Interactive mode
    print_info "Available template storage:"
    echo "$storage_list"
    echo
    
    local default_storage
    default_storage=$(echo "$storage_list" | awk 'NR==1 {print $2}')
    
    while true; do
        echo -ne "Select template storage [default: $default_storage]: "
        read -r selection
        selection=${selection:-1}
        
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            TEMPLATE_STORAGE=$(echo "$storage_list" | awk -v num="$selection" '$1 == num {print $2}')
        else
            TEMPLATE_STORAGE="$selection"
        fi
        
        if [[ -n "$TEMPLATE_STORAGE" ]] && echo "$storage_list" | grep -qw "$TEMPLATE_STORAGE"; then
            print_success "Selected template storage: $TEMPLATE_STORAGE"
            break
        else
            print_error "Invalid selection, please try again"
        fi
    done
}

select_rootfs_storage() {
    print_header "Rootfs Storage Selection"
    
    local storage_list
    storage_list=$(pvesm status -content rootdir | awk 'NR>1 {print NR-1 " " $1}')
    
    if [[ -z "$storage_list" ]]; then
        die "No rootfs storage found"
    fi
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_ROOTFS_STORAGE:-}" ]]; then
        if echo "$storage_list" | grep -qw "$DEBLXC_ROOTFS_STORAGE"; then
            ROOTFS_STORAGE="$DEBLXC_ROOTFS_STORAGE"
            print_success "Using rootfs storage: $ROOTFS_STORAGE"
            return 0
        else
            die "Specified rootfs storage not found: $DEBLXC_ROOTFS_STORAGE"
        fi
    fi
    
    # Interactive mode
    print_info "Available rootfs storage:"
    echo "$storage_list"
    echo
    
    local default_storage
    default_storage=$(echo "$storage_list" | awk 'NR==1 {print $2}')
    
    while true; do
        echo -ne "Select rootfs storage [default: $default_storage]: "
        read -r selection
        selection=${selection:-1}
        
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            ROOTFS_STORAGE=$(echo "$storage_list" | awk -v num="$selection" '$1 == num {print $2}')
        else
            ROOTFS_STORAGE="$selection"
        fi
        
        if [[ -n "$ROOTFS_STORAGE" ]] && echo "$storage_list" | grep -qw "$ROOTFS_STORAGE"; then
            print_success "Selected rootfs storage: $ROOTFS_STORAGE"
            break
        else
            print_error "Invalid selection, please try again"
        fi
    done
}

#################################################################
# Container Configuration                                       #
#################################################################

select_container_id() {
    print_header "Container ID Selection"
    
    local next_id
    next_id=$(pvesh get /cluster/nextid) || die "Failed to get next container ID"
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_CONTAINER_ID:-}" ]]; then
        if pct status "$DEBLXC_CONTAINER_ID" &>/dev/null; then
            die "Container ID already exists: $DEBLXC_CONTAINER_ID"
        fi
        CONTAINER_ID="$DEBLXC_CONTAINER_ID"
        print_success "Using container ID: $CONTAINER_ID"
        return 0
    fi
    
    # Interactive mode
    print_info "Next available container ID: $next_id"
    echo -ne "Enter container ID [default: $next_id]: "
    read -r selection
    CONTAINER_ID="${selection:-$next_id}"
    
    if pct status "$CONTAINER_ID" &>/dev/null; then
        die "Container ID already exists: $CONTAINER_ID"
    fi
    
    print_success "Selected container ID: $CONTAINER_ID"
}

select_hostname() {
    print_header "Hostname Configuration"
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_HOSTNAME:-}" ]]; then
        if validate_hostname "$DEBLXC_HOSTNAME"; then
            HOSTNAME="$DEBLXC_HOSTNAME"
            print_success "Using hostname: $HOSTNAME"
            return 0
        else
            die "Invalid hostname: $DEBLXC_HOSTNAME"
        fi
    fi
    
    # Interactive mode
    while true; do
        echo -ne "Enter hostname [default: $DEFAULT_HOSTNAME]: "
        read -r selection
        HOSTNAME="${selection:-$DEFAULT_HOSTNAME}"
        
        if is_reserved_hostname "$HOSTNAME"; then
            print_error "Invalid hostname: reserved name"
        elif validate_hostname "$HOSTNAME"; then
            print_success "Selected hostname: $HOSTNAME"
            break
        else
            print_error "Invalid hostname format (use alphanumeric and hyphens)"
        fi
    done
}

select_user_credentials() {
    print_header "User Configuration"
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_USERNAME:-}" ]] && [[ -n "${DEBLXC_PASSWORD:-}" ]]; then
        if ! validate_username "$DEBLXC_USERNAME"; then
            die "Invalid username: $DEBLXC_USERNAME"
        fi
        if ! validate_password "$DEBLXC_PASSWORD"; then
            die "Invalid password: must be 8+ chars with number and special character"
        fi
        USERNAME="$DEBLXC_USERNAME"
        PASSWORD="$DEBLXC_PASSWORD"
        print_success "Using username: $USERNAME"
        print_success "Password validated"
        return 0
    fi
    
    # Interactive mode - Username
    while true; do
        echo -ne "Enter username for non-root user: "
        read -r USERNAME
        
        if [[ "$USERNAME" == "root" ]]; then
            print_error "Username 'root' is not allowed"
        elif validate_username "$USERNAME"; then
            print_success "Username accepted: $USERNAME"
            break
        else
            print_error "Invalid username (use lowercase, digits, dashes, underscores)"
        fi
    done
    
    # Interactive mode - Password
    while true; do
        echo -ne "Enter password for '$USERNAME': "
        read -rs PASSWORD
        echo
        
        echo -ne "Confirm password: "
        read -rs PASSWORD2
        echo
        
        if [[ "$PASSWORD" != "$PASSWORD2" ]]; then
            print_error "Passwords do not match"
        elif ! validate_password "$PASSWORD"; then
            print_error "Password must be 8+ chars with at least one number and special character"
        else
            print_success "Password accepted"
            break
        fi
    done
}

select_network_bridge() {
    print_header "Network Configuration"
    
    local bridges
    bridges=$(ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr' || true)
    
    if [[ -z "$bridges" ]]; then
        die "No network bridges found (vmbr*)"
    fi
    
    # Non-interactive mode
    if [[ -n "${DEBLXC_BRIDGE:-}" ]]; then
        if echo "$bridges" | grep -qw "$DEBLXC_BRIDGE"; then
            BRIDGE="$DEBLXC_BRIDGE"
            print_success "Using network bridge: $BRIDGE"
            return 0
        else
            die "Specified bridge not found: $DEBLXC_BRIDGE"
        fi
    fi
    
    # Interactive mode
    print_info "Available network bridges:"
    echo "$bridges" | nl -s ') '
    echo
    
    echo -ne "Enter network bridge [default: $DEFAULT_BRIDGE]: "
    read -r selection
    selection="${selection:-$DEFAULT_BRIDGE}"
    
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        BRIDGE=$(echo "$bridges" | sed -n "${selection}p")
    else
        BRIDGE="$selection"
    fi
    
    if [[ -z "$BRIDGE" ]] || ! echo "$bridges" | grep -qw "$BRIDGE"; then
        BRIDGE="$DEFAULT_BRIDGE"
    fi
    
    print_success "Selected network bridge: $BRIDGE"
}

#################################################################
# Template Download                                             #
#################################################################

download_template() {
    print_header "Downloading Debian Template"
    
    # Update template list
    print_info "Updating template list..."
    if ! pveam update; then
        die "Failed to update template list"
    fi
    
    # Get latest Debian template
    local latest_template
    latest_template=$(pveam available --section system | awk '/debian/ {print $2}' | sort -V | tail -n 1)
    
    if [[ -z "$latest_template" ]]; then
        die "No Debian templates available"
    fi
    
    print_info "Latest template: $latest_template"
    
    # Download template
    print_info "Downloading to $TEMPLATE_STORAGE..."
    if ! pveam download "$TEMPLATE_STORAGE" "$latest_template"; then
        die "Failed to download template"
    fi
    
    print_success "Template downloaded: $latest_template"
    
    # Locate template path
    TEMPLATE_PATH=$(pvesm path "${TEMPLATE_STORAGE}:vztmpl/${latest_template}" 2>/dev/null || true)
    
    if [[ -z "$TEMPLATE_PATH" ]]; then
        TEMPLATE_PATH=$(find /var/lib/vz/template/cache -maxdepth 1 -name "$latest_template" 2>/dev/null | head -n 1)
    fi
    
    if [[ -z "$TEMPLATE_PATH" ]]; then
        die "Failed to locate downloaded template"
    fi
    
    print_success "Template path: $TEMPLATE_PATH"
}

#################################################################
# Container Creation                                            #
#################################################################

create_container() {
    print_header "Creating LXC Container"
    
    print_info "Creating container $CONTAINER_ID ($HOSTNAME)..."
    
    # Build pct create command
    local pct_args=(
        "$CONTAINER_ID"
        "$TEMPLATE_PATH"
        --arch amd64
        --ostype debian
        --hostname "$HOSTNAME"
        --unprivileged 1
        --features nesting=1
        --password "$PASSWORD"
        --ignore-unpack-errors
        --storage "$ROOTFS_STORAGE"
        --rootfs "$ROOTFS_STORAGE:$DEFAULT_DISK"
        --cores "$DEFAULT_CORES"
        --memory "$DEFAULT_MEMORY"
        --swap "$DEFAULT_SWAP"
        --net0 "name=eth0,bridge=$BRIDGE,firewall=1,ip=dhcp"
        --start 1
    )
    
    # Add SSH keys if available
    if [[ "$SSH_KEYS_AVAILABLE" == true ]]; then
        pct_args+=(--ssh-public-keys /root/.ssh/authorized_keys)
    fi
    
    if ! pct create "${pct_args[@]}"; then
        die "Failed to create container"
    fi
    
    print_success "Container created and started"
    
    # Wait for container to initialize
    print_info "Waiting for container to initialize..."
    sleep 5
}

#################################################################
# Container Configuration                                       #
#################################################################

configure_container() {
    print_header "Configuring Container"
    
    # Configure locales
    print_info "Configuring locales..."
    pct exec "$CONTAINER_ID" -- bash -c "
        export DEBIAN_FRONTEND=noninteractive
        export LANG=C.UTF-8 LC_ALL=C.UTF-8
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y locales
        sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
        locale-gen en_US.UTF-8
        update-locale LANG=en_US.UTF-8
        echo 'LANG=en_US.UTF-8' >> /etc/environment
        echo 'LC_ALL=en_US.UTF-8' >> /etc/environment
    " || die "Failed to configure locales"
    print_success "Locales configured"
    
    # Install packages and create user
    print_info "Installing packages and creating user..."
    pct exec "$CONTAINER_ID" -- bash -c "
        apt-get install -y sudo cloud-init
        adduser --gecos ',,,,' --disabled-password '$USERNAME'
        usermod -aG sudo '$USERNAME'
        echo '$USERNAME:$PASSWORD' | chpasswd
        passwd -l root
    " || die "Failed to configure user"
    print_success "User '$USERNAME' created with sudo access"
    
    # Configure Cloud-Init for SSH key regeneration
    print_info "Configuring Cloud-Init..."
    pct exec "$CONTAINER_ID" -- bash -lc '
        set -e
        for u in cloud-init-local.service cloud-init-main.service cloud-init-network.service cloud-config.service cloud-final.service cloud-init.target; do
            systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl enable "$u" >/dev/null 2>&1 || true
        done
    ' || print_warning "Some Cloud-Init services may not be available"
    
    pct exec "$CONTAINER_ID" -- bash -c "
        mkdir -p /var/lib/cloud/seed/nocloud
        cat > /var/lib/cloud/seed/nocloud/user-data <<EOF
#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: [ \"rsa\", \"ecdsa\", \"ed25519\" ]
EOF
        touch /var/lib/cloud/seed/nocloud/meta-data
    " || die "Failed to configure Cloud-Init"
    print_success "Cloud-Init configured for SSH key regeneration"
    
    # Clean up for template
    print_info "Preparing for template conversion..."
    pct exec "$CONTAINER_ID" -- bash -c "
        apt-get clean
        rm -f /etc/ssh/ssh_host_*
        rm -f /etc/machine-id
        touch /etc/machine-id
        truncate -s 0 /var/log/*log 2>/dev/null || true
    " || die "Failed to clean up container"
    print_success "Container prepared for template conversion"
}

#################################################################
# Template Conversion                                           #
#################################################################

convert_to_template() {
    print_header "Converting to Template"
    
    # Add description
    cat <<'EOF' >> "/etc/pve/lxc/${CONTAINER_ID}.conf"
description: <img src="https://github.com/vdarkobar/cloud/blob/main/misc/debian-logo.png?raw=true" alt="Debian Logo"/><br><details><summary>Click to expand</summary>Debian LXC Template - Created by lab/deblxc.sh</details>
EOF
    
    # Stop and convert
    print_info "Stopping container..."
    if ! pct stop "$CONTAINER_ID"; then
        die "Failed to stop container"
    fi
    
    print_info "Converting to template..."
    if ! pct template "$CONTAINER_ID"; then
        die "Failed to convert to template"
    fi
    
    print_success "Container $CONTAINER_ID converted to template"
}

#################################################################
# Main Function                                                 #
#################################################################

main() {
    clear
    
    echo -e "${C_CYAN:-\033[0;36m}╔════════════════════════════════════════════════════════════╗${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}║         Debian LXC Template Creator v${VERSION}            ║${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}║          https://github.com/vdarkobar/lab                  ║${C_RESET:-\033[0m}"
    echo -e "${C_CYAN:-\033[0;36m}╚════════════════════════════════════════════════════════════╝${C_RESET:-\033[0m}"
    
    setup_logging
    
    # Run all steps
    preflight_checks
    select_template_storage
    select_rootfs_storage
    select_container_id
    select_hostname
    select_user_credentials
    select_network_bridge
    download_template
    create_container
    configure_container
    convert_to_template
    
    # Summary
    echo
    draw_separator
    print_success "Debian LXC Template created successfully!"
    echo
    print_info "Template ID: $CONTAINER_ID"
    print_info "Hostname: $HOSTNAME"
    print_info "Username: $USERNAME"
    print_info "Storage: $ROOTFS_STORAGE"
    print_info "Bridge: $BRIDGE"
    echo
    print_info "Clone with:"
    echo "  pct clone $CONTAINER_ID <new-id> --hostname <name> --full"
    echo
    print_info "SSH keys will be regenerated automatically via Cloud-Init on first boot"
    draw_separator
    
    log "Template creation completed successfully: ID=$CONTAINER_ID"
}

# Argument handling
case "${1:-}" in
    --help|-h)
        echo "Debian LXC Template Creator v${VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → Select \"Create Debian LXC Template\""
        echo
        echo "Environment variables (for non-interactive mode):"
        echo "  DEBLXC_TEMPLATE_STORAGE   Storage for templates (e.g., \"local\")"
        echo "  DEBLXC_ROOTFS_STORAGE     Storage for rootfs (e.g., \"local-lvm\")"
        echo "  DEBLXC_CONTAINER_ID       Container ID (e.g., \"9000\")"
        echo "  DEBLXC_HOSTNAME           Hostname (default: deblxc)"
        echo "  DEBLXC_USERNAME           Non-root username"
        echo "  DEBLXC_PASSWORD           User password"
        echo "  DEBLXC_BRIDGE             Network bridge (default: vmbr0)"
        echo "  DEBLXC_CORES              CPU cores (default: 4)"
        echo "  DEBLXC_MEMORY             Memory in MB (default: 4096)"
        echo "  DEBLXC_DISK               Disk size in GB (default: 8)"
        echo
        echo "Example (fully automated):"
        echo "  DEBLXC_TEMPLATE_STORAGE=local \\"
        echo "  DEBLXC_ROOTFS_STORAGE=local-lvm \\"
        echo "  DEBLXC_CONTAINER_ID=9000 \\"
        echo "  DEBLXC_HOSTNAME=debian-tpl \\"
        echo "  DEBLXC_USERNAME=admin \\"
        echo "  DEBLXC_PASSWORD='SecurePass1!' \\"
        echo "  DEBLXC_BRIDGE=vmbr0 \\"
        echo "  $0"
        echo
        echo "Files created:"
        echo "  /etc/pve/lxc/<id>.conf    Container/template config"
        echo "  /var/log/lab/deblxc.log   Installation log"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac