#!/bin/bash

###################################################################################
# Proxmox VM Template Creator - Debian Cloud Image
###################################################################################
#
# DESCRIPTION:
#   Creates a Proxmox VM template from Debian cloud images with security
#   hardening, automated package installation, and proper user configuration.
#
# LOCATION: lab/pve/debvm.sh
# REPOSITORY: https://github.com/vdarkobar/lab
#
# USAGE:
#   Interactive mode:
#     ./debvm.sh
#
#   Non-interactive mode:
#     VM_USERNAME=admin VM_PASSWORD='pass' ./debvm.sh
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
readonly LOG_FILE="${LOG_DIR}/debvm-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"

# Default configuration
readonly DEFAULT_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2"
readonly DEFAULT_HOSTNAME="debvm"
readonly DEFAULT_MEMORY=4096
readonly DEFAULT_CORES=4
readonly DEFAULT_BRIDGE="vmbr0"
readonly MIN_MEMORY=512
readonly MIN_DISK_SPACE_GB=8

# Proxmox directories
readonly TEMPLATE_DIR="/var/lib/vz/template/iso"
readonly SNIPPET_DIR="/var/lib/vz/snippets"
readonly QEMU_CONF_DIR="/etc/pve/qemu-server"

# Reserved hostnames
readonly RESERVED_NAMES=(
    "localhost" "domain" "local" "host" "broadcasthost" 
    "localdomain" "loopback" "wpad" "gateway" "dns" 
    "mail" "ftp" "web" "router" "proxy"
)

# Global variables
CLEANUP_FILES=()
CREATED_VM_ID=""
IS_INTERACTIVE=true

###################################################################################
# UTILITY FUNCTIONS
###################################################################################

show_header() {
    draw_box "Proxmox VM Template Creator v${SCRIPT_VERSION}"
    log INFO "Creates security-hardened Debian VM templates"
    echo
}

detect_interactive_mode() {
    if [[ -n "${VM_USERNAME:-}" ]] && [[ -n "${VM_PASSWORD:-}" ]]; then
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
        log WARN "Running inside LXC container - some operations may not work"
    fi
    
    if ! command -v pvesm >/dev/null 2>&1; then
        die "Proxmox VE environment not detected"
    fi
}

check_dependencies() {
    log STEP "Checking dependencies"
    
    local missing_deps=()
    local required_commands=(
        "wget" "qm" "pvesm" "pvesh" "sha512sum"
        "virt-customize" "awk" "grep" "sed"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Install libguestfs-tools if needed
    if ! dpkg -l 2>/dev/null | grep -q "^ii.*libguestfs-tools"; then
        log INFO "Installing libguestfs-tools..."
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y libguestfs-tools >/dev/null 2>&1 || die "Failed to install libguestfs-tools"
        log SUCCESS "libguestfs-tools installed"
    fi
    
    [[ ${#missing_deps[@]} -gt 0 ]] && die "Missing commands: ${missing_deps[*]}"
    
    log SUCCESS "All dependencies satisfied"
}

cleanup() {
    local exit_code=$?
    
    if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
        log STEP "Cleaning up temporary files"
        for file in "${CLEANUP_FILES[@]}"; do
            [[ -f "$file" ]] && rm -f "$file" && log INFO "Removed: $(basename "$file")"
        done
    fi
    
    if [[ $exit_code -ne 0 ]] && [[ -n "$CREATED_VM_ID" ]]; then
        log WARN "Script failed after creating VM $CREATED_VM_ID"
        log INFO "Remove with: qm destroy $CREATED_VM_ID"
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
    [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]] && log ERROR "Invalid username: $username" && return 1
    return 0
}

validate_memory() {
    local memory="$1"
    local max_memory=$(free -m | awk '/^Mem:/{print $2}')
    [[ ! "$memory" =~ ^[0-9]+$ ]] && log ERROR "Memory must be a number" && return 1
    [[ "$memory" -lt "$MIN_MEMORY" ]] && log ERROR "Memory must be at least ${MIN_MEMORY}MB" && return 1
    [[ "$memory" -gt "$max_memory" ]] && log ERROR "Memory exceeds ${max_memory}MB" && return 1
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


#validate_storage_space() {
#    local storage="$1"
#    log STEP "Validating storage space"
#
#    local available_kib
#    available_kib="$(pvesm status -storage "$storage" 2>/dev/null | awk -v s="$storage" 'NR>1 && $1==s {print $6; exit}')"
#
#    if [[ "$available_kib" =~ ^[0-9]+$ ]]; then
#        local available_gib=$(( available_kib / 1024 / 1024 ))
#
#        if (( available_gib < MIN_DISK_SPACE_GB )); then
#            log ERROR "Insufficient space on $storage: ${available_gib}GB available, ${MIN_DISK_SPACE_GB}GB required"
#            return 1
#        fi
#
#        log SUCCESS "Storage space: ${available_gib}GB available"
#        return 0
#    fi
#
#    log WARN "Could not determine storage space for $storage (will proceed anyway)"
#    return 0
#}


#validate_storage_space() {
#    local storage="$1"
#    log STEP "Validating storage space"
#    
#    # Try to get storage status from pvesm (column 4 is 'avail' in bytes)
#    local available_bytes=$(pvesm status -storage "$storage" 2>/dev/null | awk 'NR==2 {print $4}')
#    
#    if [[ -n "$available_bytes" ]] && [[ "$available_bytes" =~ ^[0-9]+$ ]]; then
#        local available_gb=$((available_bytes / 1024 / 1024 / 1024))
#        
#        if [[ "$available_gb" -lt "$MIN_DISK_SPACE_GB" ]]; then
#            log ERROR "Insufficient space on $storage: ${available_gb}GB available, ${MIN_DISK_SPACE_GB}GB required"
#            return 1
#        fi
#        log SUCCESS "Storage space: ${available_gb}GB available"
#        return 0
#    else
#        log WARN "Could not determine storage space for $storage (will proceed anyway)"
#       return 0
#    fi
#}

check_vm_exists() {
    local vm_id="$1"
    qm status "$vm_id" >/dev/null 2>&1 && log ERROR "VM $vm_id already exists" && return 1
    return 0
}

###################################################################################
# INPUT FUNCTIONS
###################################################################################

get_next_vm_id() { pvesh get /cluster/nextid 2>/dev/null || echo "100"; }
get_network_bridges() { ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr' || echo "vmbr0"; }
get_available_storages() { pvesm status -content images 2>/dev/null | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print $1}' || echo "local-lvm"; }

prompt_vm_id() {
    local default_id=$(get_next_vm_id)
    echo >&2
    print_info "Next available VM ID: $default_id" >&2
    read -p "Enter VM ID [default: $default_id]: " -r vm_id
    vm_id="${vm_id:-$default_id}"
    [[ ! "$vm_id" =~ ^[0-9]+$ ]] && log ERROR "VM ID must be a number" && return 1
    check_vm_exists "$vm_id" || return 1
    echo "$vm_id"
}

prompt_memory() {
    local max_memory=$(free -m | awk '/^Mem:/{print $2}')
    echo >&2
    print_info "Memory range: ${MIN_MEMORY}MB to ${max_memory}MB" >&2
    read -p "Enter memory in MB [default: $DEFAULT_MEMORY]: " -r memory
    memory="${memory:-$DEFAULT_MEMORY}"
    validate_memory "$memory" || return 1
    echo "$memory"
}

prompt_cores() {
    local max_cores=$(nproc)
    echo >&2
    print_info "Cores range: 1 to $max_cores" >&2
    read -p "Enter cores [default: $DEFAULT_CORES]: " -r cores
    cores="${cores:-$DEFAULT_CORES}"
    validate_cores "$cores" || return 1
    echo "$cores"
}

prompt_bridge() {
    local bridges
    mapfile -t bridges < <(get_network_bridges)
    [[ ${#bridges[@]} -eq 0 ]] && log ERROR "No bridges found" && return 1
    
    echo >&2
    print_info "Available bridges:" >&2
    printf '%s\n' "${bridges[@]}" | nl -s ') ' >&2
    read -p "Enter bridge [default: $DEFAULT_BRIDGE]: " -r bridge_input
    local bridge="${bridge_input:-$DEFAULT_BRIDGE}"
    
    [[ "$bridge_input" =~ ^[0-9]+$ ]] && bridge="${bridges[$((bridge_input-1))]}"
    printf '%s\n' "${bridges[@]}" | grep -qx "$bridge" || { log ERROR "Invalid bridge"; return 1; }
    echo "$bridge"
}

prompt_storage() {
    local storages
    mapfile -t storages < <(get_available_storages)
    [[ ${#storages[@]} -eq 0 ]] && log ERROR "No storage found" && return 1
    
    echo >&2
    print_info "Available storages:" >&2
    printf '%s\n' "${storages[@]}" | nl -s ') ' >&2
    local default_storage="${storages[0]}"
    read -p "Select storage [default: $default_storage]: " -r storage_input
    local storage="${storage_input:-$default_storage}"
    
    [[ "$storage_input" =~ ^[0-9]+$ ]] && storage="${storages[$((storage_input-1))]}"
    printf '%s\n' "${storages[@]}" | grep -qx "$storage" || { log ERROR "Invalid storage"; return 1; }
    echo "$storage"
}

prompt_hostname() {
    while true; do
        echo >&2
        read -p "Enter hostname [default: $DEFAULT_HOSTNAME]: " -r hostname
        hostname="${hostname:-$DEFAULT_HOSTNAME}"
        validate_hostname "$hostname" && echo "$hostname" && return 0
    done
}

prompt_username() {
    while true; do
        echo >&2
        read -p "Enter username: " -r username
        [[ -z "$username" ]] && log ERROR "Username cannot be empty" && continue
        validate_username "$username" && echo "$username" && return 0
    done
}

prompt_password() {
    while true; do
        echo >&2
        read -p "Enter password: " -rs password
        echo >&2
        [[ -z "$password" ]] && log ERROR "Password cannot be empty" && continue
        read -p "Confirm password: " -rs password_confirm
        echo >&2
        [[ "$password" = "$password_confirm" ]] && echo "$password" && return 0
        log ERROR "Passwords do not match"
    done
}

prompt_image_url() {
    echo >&2
    print_info "Cloud Image URL" >&2
    print_subheader "Default: Debian 13 Generic Cloud Image" >&2
    print_subheader "${C_DIM}${DEFAULT_IMAGE_URL}${C_RESET}" >&2
    echo >&2
    read -p "Enter custom image URL (or press Enter for default): " -r image_url
    echo "${image_url:-$DEFAULT_IMAGE_URL}"
}

###################################################################################
# CONFIGURATION GATHERING
###################################################################################

gather_configuration() {
    log STEP "Gathering configuration"
    
    if [[ "$IS_INTERACTIVE" = true ]]; then
        VM_ID=$(prompt_vm_id) || exit 2
        VM_MEMORY=$(prompt_memory) || exit 2
        VM_CORES=$(prompt_cores) || exit 2
        VM_BRIDGE=$(prompt_bridge) || exit 2
        VM_STORAGE=$(prompt_storage) || exit 2
        VM_HOSTNAME=$(prompt_hostname) || exit 2
        VM_USERNAME=$(prompt_username) || exit 2
        VM_PASSWORD=$(prompt_password) || exit 2
        IMAGE_URL=$(prompt_image_url) || exit 2
    else
        VM_ID="${VM_ID:-$(get_next_vm_id)}"
        VM_MEMORY="${VM_MEMORY:-$DEFAULT_MEMORY}"
        VM_CORES="${VM_CORES:-$DEFAULT_CORES}"
        VM_BRIDGE="${VM_BRIDGE:-$DEFAULT_BRIDGE}"
        VM_STORAGE="${VM_STORAGE:-$(get_available_storages | head -n1)}"
        VM_HOSTNAME="${VM_HOSTNAME:-$DEFAULT_HOSTNAME}"
        IMAGE_URL="${IMAGE_URL:-$DEFAULT_IMAGE_URL}"
        
        [[ -z "$VM_USERNAME" ]] && die "VM_USERNAME required in non-interactive mode"
        [[ -z "$VM_PASSWORD" ]] && die "VM_PASSWORD required in non-interactive mode"
        
        check_vm_exists "$VM_ID" || exit 2
        validate_memory "$VM_MEMORY" || exit 2
        validate_cores "$VM_CORES" || exit 2
        validate_hostname "$VM_HOSTNAME" || exit 2
        validate_username "$VM_USERNAME" || exit 2
    fi
    
    validate_storage_space "$VM_STORAGE" || exit 5
    log SUCCESS "Configuration gathered"
}

show_configuration_summary() {
    echo
    print_header "Configuration Summary"
    print_kv "VM ID" "$VM_ID"
    print_kv "Hostname" "$VM_HOSTNAME"
    print_kv "Memory" "${VM_MEMORY}MB"
    print_kv "Cores" "$VM_CORES"
    print_kv "Network" "$VM_BRIDGE"
    print_kv "Storage" "$VM_STORAGE"
    print_kv "Username" "$VM_USERNAME"
    print_kv "Image" "$IMAGE_URL"
    echo
    
    if [[ "$IS_INTERACTIVE" = true ]]; then
        read -p "Proceed? [Y/n]: " -r confirm
        [[ "$confirm" =~ ^[Nn] ]] && log INFO "Cancelled" && exit 0
    fi
}

###################################################################################
# IMAGE DOWNLOAD AND VERIFICATION
###################################################################################

download_and_verify_image() {
    local image_url="$1"
    local image_name=$(basename "$image_url")
    local checksums_url="${image_url%/*}/SHA512SUMS"
    
    log STEP "Downloading cloud image"
    
    mkdir -p "$TEMPLATE_DIR"
    cd "$TEMPLATE_DIR"
    
    log INFO "Downloading checksums"
    wget -q "$checksums_url" -O SHA512SUMS 2>/dev/null || die "Failed to download checksums"
    CLEANUP_FILES+=("$TEMPLATE_DIR/SHA512SUMS")
    
    log INFO "Downloading image: $image_name"
    if ! wget -O "$image_name" "$image_url" 2>&1 | grep -o '[0-9]*%' | \
        while read -r percent; do
            [[ "$IS_INTERACTIVE" = true ]] && echo -ne "\r    Progress: $percent"
        done; then
        die "Failed to download image"
    fi
    [[ "$IS_INTERACTIVE" = true ]] && echo
    
    log SUCCESS "Image downloaded: $image_name"
    
    [[ "${KEEP_DOWNLOADS:-false}" != "true" ]] && CLEANUP_FILES+=("$TEMPLATE_DIR/$image_name")
    
    if [[ "${SKIP_CHECKSUM:-false}" != "true" ]]; then
        log STEP "Verifying integrity"
        local checksum_line=$(grep -E "([[:space:]]|\\*)${image_name}$" SHA512SUMS | head -n 1)
        [[ -z "$checksum_line" ]] && die "No checksum found for $image_name"
        echo "$checksum_line" | sha512sum -c --status 2>/dev/null || die "Checksum verification failed"
        log SUCCESS "Image verified"
    else
        log WARN "Checksum verification skipped (NOT RECOMMENDED)"
    fi
    
    echo "$image_name"
}

###################################################################################
# IMAGE CUSTOMIZATION
###################################################################################

customize_image() {
    local image_path="$1"
    local username="$2"
    local password="$3"
    
    log STEP "Customizing image"
    
    print_subheader "Locking root account"
    virt-customize -a "$image_path" --run-command "passwd -l root" 2>/dev/null || die "Failed to lock root"
    
    print_subheader "Creating user: $username"
    virt-customize -a "$image_path" --run-command "useradd -m -s /bin/bash $username" 2>/dev/null || die "Failed to create user"
    
    print_subheader "Adding to sudo group"
    virt-customize -a "$image_path" --run-command "usermod -aG sudo $username" 2>/dev/null || die "Failed to add to sudo"
    
    print_subheader "Setting password"
    virt-customize -a "$image_path" --password "$username:password:$password" 2>/dev/null || die "Failed to set password"
    
    print_subheader "Removing SSH host keys"
    virt-customize -a "$image_path" --run-command "rm -f /etc/ssh/ssh_host_*" 2>/dev/null || true
    
    print_subheader "Cleaning cloud-init"
    virt-customize -a "$image_path" --run-command "cloud-init clean --logs --seed || true" 2>/dev/null || true
    
    print_subheader "Clearing machine ID"
    virt-customize -a "$image_path" --run-command "truncate -s 0 /etc/machine-id" 2>/dev/null || true
    
    log SUCCESS "Image customized"
}

###################################################################################
# VM CREATION
###################################################################################

create_cloudinit_userdata() {
    local vm_id="$1"
    local userdata_file="$SNIPPET_DIR/userdata-${vm_id}.yaml"
    
    mkdir -p "$SNIPPET_DIR"
    
    cat > "$userdata_file" <<'EOF'
#cloud-config
package_update: true
packages:
  - qemu-guest-agent
  - openssh-server
  - cloud-init
  - cloud-guest-utils
  - sudo
  - curl
  - wget
  - ca-certificates
  - chrony
  - cron
runcmd:
  - systemctl enable --now qemu-guest-agent || true
  - systemctl enable --now ssh || true
EOF
    
    echo "$userdata_file"
}

create_proxmox_vm() {
    local vm_id="$1" hostname="$2" memory="$3" cores="$4" bridge="$5" storage="$6" image_path="$7" username="$8" password="$9"
    
    log STEP "Creating VM"
    
    print_subheader "Creating VM $vm_id"
    qm create "$vm_id" --name "$hostname" --memory "$memory" --cores "$cores" \
        --net0 "virtio,bridge=${bridge},firewall=1" 2>/dev/null || die "Failed to create VM"
    
    CREATED_VM_ID="$vm_id"
    
    print_subheader "Importing disk"
    local import_output=$(qm importdisk "$vm_id" "$image_path" "$storage" 2>&1)
    if [[ $? -ne 0 ]]; then
        qm destroy "$vm_id" 2>/dev/null
        die "Failed to import disk: $import_output"
    fi
    
    # Extract the actual disk name from importdisk output
    # Output usually contains: "Successfully imported disk as 'unused0:storage:vm-107-disk-0'"
    local disk_name=$(echo "$import_output" | grep -oP "unused\d+:\K${storage}:[^'\"]+")
    
    # Fallback to standard naming if extraction fails
    if [[ -z "$disk_name" ]]; then
        disk_name="${storage}:vm-${vm_id}-disk-0"
    fi
    
    print_subheader "Configuring VM"
    qm set "$vm_id" --scsihw virtio-scsi-single --scsi0 "${disk_name},cache=writeback,discard=on,ssd=1" >/dev/null 2>&1
    qm set "$vm_id" --boot c --bootdisk scsi0 >/dev/null 2>&1
    qm set "$vm_id" --scsi2 "${storage}:cloudinit" >/dev/null 2>&1
    qm set "$vm_id" --agent enabled=1 --serial0 socket --vga serial0 >/dev/null 2>&1
    qm set "$vm_id" --cpu cputype=host --ostype l26 --ciupgrade 1 >/dev/null 2>&1
    qm set "$vm_id" --balloon 2048 >/dev/null 2>&1
    qm set "$vm_id" --ciuser "$username" --cipassword "$password" --ipconfig0 ip=dhcp --hostname "$hostname" >/dev/null 2>&1
    
    local userdata_file=$(create_cloudinit_userdata "$vm_id")
    qm set "$vm_id" --cicustom "user=local:snippets/$(basename "$userdata_file")" >/dev/null 2>&1
    
    echo 'description: <img src="https://github.com/vdarkobar/cloud/blob/main/misc/debian-logo.png?raw=true" alt="Debian"/><br>' >> "${QEMU_CONF_DIR}/${vm_id}.conf"
    qm set "$vm_id" --tags "vm,template,debian13" >/dev/null 2>&1
    
    log SUCCESS "VM created"
}

convert_to_template() {
    local vm_id="$1"
    log STEP "Converting to template"
    qm template "$vm_id" 2>/dev/null || die "Failed to convert to template"
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
    
    local image_name=$(download_and_verify_image "$IMAGE_URL")
    local image_path="$TEMPLATE_DIR/$image_name"
    
    customize_image "$image_path" "$VM_USERNAME" "$VM_PASSWORD"
    create_proxmox_vm "$VM_ID" "$VM_HOSTNAME" "$VM_MEMORY" "$VM_CORES" "$VM_BRIDGE" "$VM_STORAGE" "$image_path" "$VM_USERNAME" "$VM_PASSWORD"
    convert_to_template "$VM_ID"
    
    echo
    draw_separator
    log SUCCESS "Template Created"
    draw_separator
    echo
    print_kv "Template ID" "$VM_ID"
    print_kv "Hostname" "$VM_HOSTNAME"
    print_kv "Username" "$VM_USERNAME"
    print_kv "Storage" "$VM_STORAGE"
    echo
    print_info "Clone with: qm clone $VM_ID <new-id> --name <hostname>"
    print_info "Log file: $LOG_FILE"
    echo
}

main "$@"
