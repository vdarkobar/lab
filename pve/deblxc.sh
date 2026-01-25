#!/bin/bash

###################################################################################
# Proxmox LXC Template Creator - Debian                                          #
###################################################################################
#
# DESCRIPTION:
#   Creates a Proxmox LXC template from Debian images with security
#   hardening, cloud-init support, and proper user configuration.
#
# LOCATION: lab/pve/deblxc.sh
# REPOSITORY: https://github.com/vdarkobar/lab
#
# USAGE:
#   Interactive mode:
#     ./deblxc.sh
#
#   Non-interactive mode:
#     CT_USERNAME=admin CT_PASSWORD='pass' ./deblxc.sh
#
# VERSION: 2.0.0
# LICENSE: MIT
#
###################################################################################

set -euo pipefail

###################################################################################
# CONFIGURATION
###################################################################################

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source formatting library
if [[ -f "${SCRIPT_DIR}/../lib/formatting.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/formatting.sh"
else
    echo "ERROR: formatting.sh not found at ${SCRIPT_DIR}/../lib/formatting.sh" >&2
    exit 1
fi

# Set up logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/deblxc-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"

# Default configuration
readonly DEFAULT_HOSTNAME="deblxc"
readonly DEFAULT_CORES=4
readonly DEFAULT_MEMORY=4096
readonly DEFAULT_SWAP=512
readonly DEFAULT_DISK=8
readonly DEFAULT_BRIDGE="vmbr0"
readonly MIN_PASSWORD_LENGTH=8

# Reserved hostnames
readonly RESERVED_NAMES=(
    "localhost" "domain" "local" "host" "broadcasthost" 
    "localdomain" "loopback" "wpad" "gateway" "dns" 
    "mail" "ftp" "web" "router" "proxy"
)

# Global variables
CREATED_CT_ID=""
IS_INTERACTIVE=true

###################################################################################
# UTILITY FUNCTIONS
###################################################################################

show_header() {
    draw_box "Proxmox LXC Template Creator v${SCRIPT_VERSION}"
    log INFO "Creates security-hardened Debian LXC templates"
    echo
}

detect_interactive_mode() {
    if [[ -n "${CT_USERNAME:-}" ]] && [[ -n "${CT_PASSWORD:-}" ]]; then
        IS_INTERACTIVE=false
        log INFO "Running in non-interactive mode"
    else
        IS_INTERACTIVE=true
        log INFO "Running in interactive mode"
    fi
}

check_privileges() {
    if [[ "$EUID" -ne 0 ]]; then
        die "This script must be run as root or with sudo"
    fi
}

check_environment() {
    if [[ -f /proc/1/cgroup ]] && grep -q "/lxc/" /proc/1/cgroup 2>/dev/null; then
        die "Cannot run LXC template creator inside an LXC container"
    fi
    
    if ! command -v pct >/dev/null 2>&1; then
        die "Proxmox VE environment not detected (pct command not found)"
    fi
}

check_dependencies() {
    log STEP "Checking dependencies"
    
    local missing_deps=()
    local required_commands=(
        "pct" "pvesm" "pvesh" "pveam" "awk" "grep" "sed"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    [[ ${#missing_deps[@]} -gt 0 ]] && die "Missing commands: ${missing_deps[*]}"
    
    log SUCCESS "All dependencies satisfied"
}

cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]] && [[ -n "$CREATED_CT_ID" ]]; then
        log WARN "Script failed after creating container $CREATED_CT_ID"
        log INFO "Remove with: pct destroy $CREATED_CT_ID"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

###################################################################################
# VALIDATION FUNCTIONS
###################################################################################

is_reserved_hostname() {
    local hostname="$1"
    for name in "${RESERVED_NAMES[@]}"; do
        [[ "${hostname,,}" = "${name,,}" ]] && return 0
    done
    return 1
}

validate_hostname() {
    local hostname="$1"
    is_reserved_hostname "$hostname" && log ERROR "Reserved hostname: $hostname" && return 1
    [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && log ERROR "Invalid hostname: $hostname" && return 1
    return 0
}

validate_username() {
    local username="$1"
    [[ "$username" == "root" ]] && log ERROR "Username 'root' is not allowed" && return 1
    [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]] && log ERROR "Invalid username: $username" && return 1
    return 0
}

validate_password() {
    local password="$1"
    [[ ${#password} -lt $MIN_PASSWORD_LENGTH ]] && log ERROR "Password must be at least ${MIN_PASSWORD_LENGTH} characters" && return 1
    [[ ! "$password" =~ [0-9] ]] && log ERROR "Password must contain at least one number" && return 1
    [[ ! "$password" =~ [^a-zA-Z0-9] ]] && log ERROR "Password must contain at least one special character" && return 1
    return 0
}

validate_memory() {
    local memory="$1"
    [[ ! "$memory" =~ ^[0-9]+$ ]] && log ERROR "Memory must be a number" && return 1
    [[ "$memory" -lt 512 ]] && log ERROR "Memory must be at least 512MB" && return 1
    return 0
}

validate_cores() {
    local cores="$1"
    local max_cores=$(nproc)
    [[ ! "$cores" =~ ^[0-9]+$ ]] && log ERROR "Cores must be a number" && return 1
    [[ "$cores" -lt 1 ]] && log ERROR "Must have at least 1 core" && return 1
    [[ "$cores" -gt "$max_cores" ]] && log ERROR "Cores exceed $max_cores" && return 1
    return 0
}

check_ct_exists() {
    local ct_id="$1"
    pct status "$ct_id" >/dev/null 2>&1 && log ERROR "Container $ct_id already exists" && return 1
    return 0
}

###################################################################################
# INPUT FUNCTIONS
###################################################################################

get_next_ct_id() { pvesh get /cluster/nextid 2>/dev/null || echo "100"; }
get_network_bridges() { ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr' || echo "vmbr0"; }
get_template_storages() { pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 {print $1}' || echo "local"; }
get_rootfs_storages() { pvesm status -content rootdir 2>/dev/null | awk 'NR>1 {print $1}' || echo "local-lvm"; }

prompt_ct_id() {
    local default_id=$(get_next_ct_id)
    echo
    print_info "Next available CT ID: $default_id"
    echo -n "Enter Container ID [default: $default_id]: "
    read -r ct_id
    ct_id="${ct_id:-$default_id}"
    [[ ! "$ct_id" =~ ^[0-9]+$ ]] && log ERROR "Container ID must be a number" && return 1
    check_ct_exists "$ct_id" || return 1
    echo "$ct_id"
}

prompt_hostname() {
    while true; do
        echo
        echo -n "Enter hostname [default: $DEFAULT_HOSTNAME]: "
        read -r hostname
        hostname="${hostname:-$DEFAULT_HOSTNAME}"
        validate_hostname "$hostname" && echo "$hostname" && return 0
    done
}

prompt_username() {
    while true; do
        echo
        echo -n "Enter username for non-root user: "
        read -r username
        [[ -z "$username" ]] && log ERROR "Username cannot be empty" && continue
        validate_username "$username" && echo "$username" && return 0
    done
}

prompt_password() {
    while true; do
        echo
        echo -n "Enter password: "
        read -rs password
        echo
        [[ -z "$password" ]] && log ERROR "Password cannot be empty" && continue
        validate_password "$password" || continue
        echo -n "Confirm password: "
        read -rs password_confirm
        echo
        [[ "$password" = "$password_confirm" ]] && echo "$password" && return 0
        log ERROR "Passwords do not match"
    done
}

prompt_memory() {
    echo
    echo -n "Enter memory in MB [default: $DEFAULT_MEMORY]: "
    read -r memory
    memory="${memory:-$DEFAULT_MEMORY}"
    validate_memory "$memory" || return 1
    echo "$memory"
}

prompt_cores() {
    local max_cores=$(nproc)
    echo
    print_info "Cores range: 1 to $max_cores"
    echo -n "Enter cores [default: $DEFAULT_CORES]: "
    read -r cores
    cores="${cores:-$DEFAULT_CORES}"
    validate_cores "$cores" || return 1
    echo "$cores"
}

prompt_bridge() {
    local bridges
    mapfile -t bridges < <(get_network_bridges)
    [[ ${#bridges[@]} -eq 0 ]] && log ERROR "No bridges found" && return 1
    
    echo
    print_info "Available bridges:"
    printf '%s\n' "${bridges[@]}" | nl -s ') '
    echo -n "Enter bridge [default: $DEFAULT_BRIDGE]: "
    read -r bridge_input
    local bridge="${bridge_input:-$DEFAULT_BRIDGE}"
    
    [[ "$bridge_input" =~ ^[0-9]+$ ]] && bridge="${bridges[$((bridge_input-1))]}"
    printf '%s\n' "${bridges[@]}" | grep -qx "$bridge" || { log ERROR "Invalid bridge"; return 1; }
    echo "$bridge"
}

prompt_template_storage() {
    local storages
    mapfile -t storages < <(get_template_storages)
    [[ ${#storages[@]} -eq 0 ]] && log ERROR "No template storage found" && return 1
    
    echo
    print_info "Available template storages:"
    printf '%s\n' "${storages[@]}" | nl -s ') '
    local default_storage="${storages[0]}"
    echo -n "Select template storage [default: $default_storage]: "
    read -r storage_input
    local storage="${storage_input:-$default_storage}"
    
    [[ "$storage_input" =~ ^[0-9]+$ ]] && storage="${storages[$((storage_input-1))]}"
    printf '%s\n' "${storages[@]}" | grep -qx "$storage" || { log ERROR "Invalid storage"; return 1; }
    echo "$storage"
}

prompt_rootfs_storage() {
    local storages
    mapfile -t storages < <(get_rootfs_storages)
    [[ ${#storages[@]} -eq 0 ]] && log ERROR "No rootfs storage found" && return 1
    
    echo
    print_info "Available rootfs storages:"
    printf '%s\n' "${storages[@]}" | nl -s ') '
    local default_storage="${storages[0]}"
    echo -n "Select rootfs storage [default: $default_storage]: "
    read -r storage_input
    local storage="${storage_input:-$default_storage}"
    
    [[ "$storage_input" =~ ^[0-9]+$ ]] && storage="${storages[$((storage_input-1))]}"
    printf '%s\n' "${storages[@]}" | grep -qx "$storage" || { log ERROR "Invalid storage"; return 1; }
    echo "$storage"
}

###################################################################################
# CONFIGURATION GATHERING
###################################################################################

gather_configuration() {
    log STEP "Gathering configuration"
    
    if [[ "$IS_INTERACTIVE" = true ]]; then
        CT_ID=$(prompt_ct_id) || exit 2
        CT_HOSTNAME=$(prompt_hostname) || exit 2
        CT_USERNAME=$(prompt_username) || exit 2
        CT_PASSWORD=$(prompt_password) || exit 2
        CT_MEMORY=$(prompt_memory) || exit 2
        CT_CORES=$(prompt_cores) || exit 2
        CT_BRIDGE=$(prompt_bridge) || exit 2
        TEMPLATE_STORAGE=$(prompt_template_storage) || exit 2
        ROOTFS_STORAGE=$(prompt_rootfs_storage) || exit 2
    else
        CT_ID="${CT_ID:-$(get_next_ct_id)}"
        CT_HOSTNAME="${CT_HOSTNAME:-$DEFAULT_HOSTNAME}"
        CT_MEMORY="${CT_MEMORY:-$DEFAULT_MEMORY}"
        CT_CORES="${CT_CORES:-$DEFAULT_CORES}"
        CT_BRIDGE="${CT_BRIDGE:-$DEFAULT_BRIDGE}"
        TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-$(get_template_storages | head -n1)}"
        ROOTFS_STORAGE="${ROOTFS_STORAGE:-$(get_rootfs_storages | head -n1)}"
        
        [[ -z "$CT_USERNAME" ]] && die "CT_USERNAME required in non-interactive mode"
        [[ -z "$CT_PASSWORD" ]] && die "CT_PASSWORD required in non-interactive mode"
        
        check_ct_exists "$CT_ID" || exit 2
        validate_hostname "$CT_HOSTNAME" || exit 2
        validate_username "$CT_USERNAME" || exit 2
        validate_password "$CT_PASSWORD" || exit 2
        validate_memory "$CT_MEMORY" || exit 2
        validate_cores "$CT_CORES" || exit 2
    fi
    
    log SUCCESS "Configuration gathered"
}

show_configuration_summary() {
    echo
    print_header "Configuration Summary"
    print_kv "Container ID" "$CT_ID"
    print_kv "Hostname" "$CT_HOSTNAME"
    print_kv "Username" "$CT_USERNAME"
    print_kv "Memory" "${CT_MEMORY}MB"
    print_kv "Cores" "$CT_CORES"
    print_kv "Swap" "${DEFAULT_SWAP}MB"
    print_kv "Disk" "${DEFAULT_DISK}GB"
    print_kv "Network" "$CT_BRIDGE"
    print_kv "Template Storage" "$TEMPLATE_STORAGE"
    print_kv "Rootfs Storage" "$ROOTFS_STORAGE"
    echo
    
    if [[ "$IS_INTERACTIVE" = true ]]; then
        echo -n "Proceed? [Y/n]: "
        read -r confirm
        [[ "$confirm" =~ ^[Nn] ]] && log INFO "Cancelled" && exit 0
    fi
}

###################################################################################
# TEMPLATE DOWNLOAD
###################################################################################

download_debian_template() {
    local storage="$1"
    
    log STEP "Downloading Debian LXC template"
    
    print_subheader "Updating template list..."
    if ! pveam update 2>&1 | tee -a "$LOG_FILE"; then
        die "Failed to update template list"
    fi
    
    print_subheader "Finding latest Debian template..."
    local template_name=$(pveam available --section system | awk '/debian/ {print $2}' | sort -V | tail -n 1)
    
    if [[ -z "$template_name" ]]; then
        die "No Debian templates available"
    fi
    
    log INFO "Latest template: $template_name"
    
    # Check if already downloaded
    if pvesm list "$storage" 2>/dev/null | grep -q "$template_name"; then
        log SUCCESS "Template already downloaded: $template_name"
        echo "$template_name"
        return 0
    fi
    
    print_subheader "Downloading $template_name to $storage..."
    if ! pveam download "$storage" "$template_name" 2>&1 | tee -a "$LOG_FILE"; then
        die "Failed to download template"
    fi
    
    log SUCCESS "Template downloaded: $template_name"
    echo "$template_name"
}

locate_template() {
    local storage="$1"
    local template_name="$2"
    
    log STEP "Locating template"
    
    # Try pvesm path first
    local template_path
    template_path=$(pvesm path "${storage}:vztmpl/${template_name}" 2>/dev/null || true)
    
    # Fallback to standard location
    if [[ -z "$template_path" ]]; then
        template_path=$(find /var/lib/vz/template/cache -maxdepth 1 -name "$template_name" 2>/dev/null | head -n 1)
    fi
    
    if [[ -z "$template_path" ]]; then
        die "Failed to locate template: $template_name"
    fi
    
    log SUCCESS "Template located: $template_path"
    echo "$template_path"
}

###################################################################################
# CONTAINER CREATION
###################################################################################

create_lxc_container() {
    local ct_id="$1" hostname="$2" template_path="$3" rootfs_storage="$4"
    local memory="$5" cores="$6" bridge="$7" password="$8"
    
    log STEP "Creating LXC container"
    
    print_subheader "Creating container $ct_id..."
    
    if ! pct create "$ct_id" "$template_path" \
        --arch amd64 \
        --ostype debian \
        --hostname "$hostname" \
        --unprivileged 1 \
        --features nesting=1 \
        --password "$password" \
        --ignore-unpack-errors \
        --ssh-public-keys /root/.ssh/authorized_keys \
        --storage "$rootfs_storage" \
        --rootfs "${rootfs_storage}:${DEFAULT_DISK}" \
        --cores "$cores" \
        --memory "$memory" \
        --swap "$DEFAULT_SWAP" \
        --net0 "name=eth0,bridge=${bridge},firewall=1,ip=dhcp" \
        --start 1 2>&1 | tee -a "$LOG_FILE"; then
        die "Failed to create container"
    fi
    
    CREATED_CT_ID="$ct_id"
    log SUCCESS "Container created"
    
    # Wait for container to start
    sleep 5
}

configure_container() {
    local ct_id="$1" username="$2" password="$3"
    
    log STEP "Configuring container"
    
    print_subheader "Configuring locales..."
    pct exec "$ct_id" -- bash -c "
        export DEBIAN_FRONTEND=noninteractive && \
        export LANG=C.UTF-8 LC_ALL=C.UTF-8 && \
        apt-get update -y && \
        apt-get upgrade -y && \
        apt-get install -y locales && \
        sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
        locale-gen en_US.UTF-8 && \
        update-locale LANG=en_US.UTF-8
    " 2>&1 | tee -a "$LOG_FILE" || die "Locale configuration failed"
    
    pct exec "$ct_id" -- bash -c "echo 'LANG=en_US.UTF-8' >> /etc/environment" 2>&1 | tee -a "$LOG_FILE"
    pct exec "$ct_id" -- bash -c "echo 'LC_ALL=en_US.UTF-8' >> /etc/environment" 2>&1 | tee -a "$LOG_FILE"
    
    print_subheader "Creating user: $username..."
    pct exec "$ct_id" -- bash -c "
        apt-get install -y sudo cloud-init && \
        adduser --gecos ',,,,' --disabled-password $username && \
        usermod -aG sudo $username && \
        echo '$username:$password' | chpasswd && \
        passwd -l root
    " 2>&1 | tee -a "$LOG_FILE" || die "User configuration failed"
    
    print_subheader "Configuring cloud-init..."
    pct exec "$ct_id" -- bash -lc '
        set -e
        for u in cloud-init-local.service cloud-init-main.service cloud-init-network.service cloud-config.service cloud-final.service cloud-init.target; do
            systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl enable "$u" >/dev/null 2>&1 || true
        done
    ' 2>&1 | tee -a "$LOG_FILE"
    
    pct exec "$ct_id" -- bash -c "mkdir -p /var/lib/cloud/seed/nocloud" 2>&1 | tee -a "$LOG_FILE"
    pct exec "$ct_id" -- bash -c 'cat > /var/lib/cloud/seed/nocloud/user-data <<EOF
#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: [ "rsa", "ecdsa", "ed25519" ]
EOF' 2>&1 | tee -a "$LOG_FILE"
    pct exec "$ct_id" -- bash -c "touch /var/lib/cloud/seed/nocloud/meta-data" 2>&1 | tee -a "$LOG_FILE"
    
    log SUCCESS "Container configured"
}

prepare_for_template() {
    local ct_id="$1"
    
    log STEP "Preparing container for template conversion"
    
    pct exec "$ct_id" -- bash -c "
        apt-get clean && \
        rm -f /etc/ssh/ssh_host_* && \
        rm -f /etc/machine-id && \
        touch /etc/machine-id && \
        truncate -s 0 /var/log/*log
    " 2>&1 | tee -a "$LOG_FILE" || log WARN "Some cleanup operations failed"
    
    # Add description
    cat <<'EOF' >> /etc/pve/lxc/${ct_id}.conf
description: <img src="https://github.com/vdarkobar/cloud/blob/main/misc/debian-logo.png?raw=true" alt="Debian"/><br>
EOF
    
    log SUCCESS "Container prepared"
}

convert_to_template() {
    local ct_id="$1"
    local hostname="$2"
    
    log STEP "Converting to template"
    
    print_subheader "Stopping container..."
    pct stop "$ct_id" 2>&1 | tee -a "$LOG_FILE" || die "Failed to stop container"
    
    print_subheader "Converting to template..."
    pct template "$ct_id" 2>&1 | tee -a "$LOG_FILE" || die "Failed to convert to template"
    
    log SUCCESS "Converted to template"
}

###################################################################################
# MAIN
###################################################################################

main() {
    show_header
    detect_interactive_mode
    check_privileges
    check_environment
    check_dependencies
    
    gather_configuration
    show_configuration_summary
    
    local template_name
    template_name=$(download_debian_template "$TEMPLATE_STORAGE")
    
    local template_path
    template_path=$(locate_template "$TEMPLATE_STORAGE" "$template_name")
    
    create_lxc_container "$CT_ID" "$CT_HOSTNAME" "$template_path" "$ROOTFS_STORAGE" \
        "$CT_MEMORY" "$CT_CORES" "$CT_BRIDGE" "$CT_PASSWORD"
    
    configure_container "$CT_ID" "$CT_USERNAME" "$CT_PASSWORD"
    prepare_for_template "$CT_ID"
    convert_to_template "$CT_ID" "$CT_HOSTNAME"
    
    echo
    draw_separator
    log SUCCESS "LXC Template Created"
    draw_separator
    echo
    print_kv "Container ID" "$CT_ID"
    print_kv "Hostname" "$CT_HOSTNAME"
    print_kv "Username" "$CT_USERNAME"
    print_kv "Template Storage" "$TEMPLATE_STORAGE"
    print_kv "Rootfs Storage" "$ROOTFS_STORAGE"
    echo
    print_info "Clone with: pct clone $CT_ID <new-id> --hostname <hostname>"
    print_info "SSH keys will regenerate on first boot via cloud-init"
    print_info "Log file: $LOG_FILE"
    echo
}

main "$@"
