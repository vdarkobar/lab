#!/bin/bash
###################################################################################
# Proxmox VM Template Creator - Debian Cloud Image
###################################################################################

readonly SCRIPT_VERSION="2.0.3"

# Handle --help flag early
case "${1:-}" in
    --help|-h)
        echo "Proxmox VM Template Creator v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → Select \"Create Debian VM Template\""
        echo
        echo "Environment variables (for non-interactive mode):"
        echo "  VM_ID              VM ID (e.g., \"9000\")"
        echo "  VM_HOSTNAME        Hostname (default: debvm)"
        echo "  VM_USERNAME        Non-root username"
        echo "  VM_PASSWORD        User password"
        echo "  VM_STORAGE         Storage for VM disk (e.g., \"local-lvm\")"
        echo "  VM_MEMORY          Memory in MB (default: 4096)"
        echo "  VM_CORES           CPU cores (default: 4)"
        echo "  VM_BRIDGE          Network bridge (default: vmbr0)"
        echo "  IMAGE_URL          Custom cloud image URL"
        echo "  SKIP_CHECKSUM      Set to \"true\" to skip verification"
        echo "  KEEP_DOWNLOADS     Set to \"true\" to keep downloaded image"
        echo
        echo "Example (fully automated):"
        echo "  VM_ID=9000 \\"
        echo "  VM_HOSTNAME=debian-tpl \\"
        echo "  VM_USERNAME=admin \\"
        echo "  VM_PASSWORD='SecurePass1!' \\"
        echo "  VM_STORAGE=local-lvm \\"
        echo "  $0"
        echo
        echo "Files created:"
        echo "  /var/lib/vz/snippets/userdata-<id>.yaml  Cloud-init config"
        echo "  /var/log/lab/debvm-*.log                 Installation log"
        exit 0
        ;;
esac

###################################################################################
# Fixes applied:
# - Correct storage free-space parsing (Available KiB is column 6)
# - Robust download (no pipefail false-negatives)
# - Command-substitution safe: download function logs to STDERR, returns filename on STDOUT
# - FIX: qm set has NO --hostname option -> hostname is set via cloud-init user-data
# - Improved diagnostics: ERR trap prints failing line/command; qm errors are not silenced
###################################################################################

set -Eeuo pipefail
trap 'echo "FATAL: line $LINENO: $BASH_COMMAND" >&2' ERR

###################################################################################
# CONFIGURATION
###################################################################################

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source formatting library
if [[ -f "${SCRIPT_DIR}/../lib/formatting.sh" ]]; then
  source "${SCRIPT_DIR}/../lib/formatting.sh"
else
  echo "ERROR: formatting.sh not found at ${SCRIPT_DIR}/../lib/formatting.sh" >&2
  exit 1
fi

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/debvm-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

# Defaults
readonly DEFAULT_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2"
readonly DEFAULT_HOSTNAME="debvm"
readonly DEFAULT_MEMORY=4096
readonly DEFAULT_CORES=4
readonly DEFAULT_BRIDGE="vmbr0"
readonly MIN_MEMORY=512
readonly MIN_DISK_SPACE_GB=8

# Paths
readonly TEMPLATE_DIR="/var/lib/vz/template/iso"
readonly SNIPPET_DIR="/var/lib/vz/snippets"

# Reserved hostnames
readonly RESERVED_NAMES=(
  "localhost" "domain" "local" "host" "broadcasthost"
  "localdomain" "loopback" "wpad" "gateway" "dns"
  "mail" "ftp" "web" "router" "proxy"
)

# Globals
CLEANUP_FILES=()
CREATED_VM_ID=""
IS_INTERACTIVE=true

# libguestfs is often best with direct backend on Proxmox
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"

###################################################################################
# UTILITY
###################################################################################

show_header() {
  draw_box "Proxmox VM Template Creator v${SCRIPT_VERSION}"
  log INFO "Creates security-hardened Debian VM templates"
  log INFO "Logging to: ${LOG_FILE}"
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
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "This script must be run as root or with sudo"
}

check_environment() {
  command -v pvesm >/dev/null 2>&1 || die "Proxmox VE environment not detected (pvesm missing)"
  command -v qm >/dev/null 2>&1 || die "Proxmox qm missing"
  command -v pvesh >/dev/null 2>&1 || die "Proxmox pvesh missing"
}

check_dependencies() {
  log STEP "Checking dependencies"

  # libguestfs-tools provides virt-customize
  if ! dpkg -l 2>/dev/null | awk '{print $1,$2}' | grep -q "^ii libguestfs-tools"; then
    log INFO "Installing libguestfs-tools..."
    apt-get update -qq
    apt-get install -y libguestfs-tools
    log SUCCESS "libguestfs-tools installed"
  fi

  local missing=()
  local req=(wget qm pvesm pvesh sha512sum virt-customize awk grep sed tee)
  for c in "${req[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "Missing commands: ${missing[*]}"

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
    log INFO "Remove with: qm destroy $CREATED_VM_ID --purge 1"
  fi

  if [[ $exit_code -ne 0 ]]; then
    log ERROR "Installation failed"
    log INFO "Log file: $LOG_FILE"
  fi

  exit $exit_code
}

trap cleanup EXIT INT TERM

###################################################################################
# VALIDATION
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
  [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] || { log ERROR "Invalid hostname: $hostname"; return 1; }
  return 0
}

validate_username() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]] || { log ERROR "Invalid username: $username"; return 1; }
  return 0
}

validate_memory() {
  local memory="$1"
  local max_memory
  max_memory="$(free -m | awk '/^Mem:/{print $2}')"
  [[ "$memory" =~ ^[0-9]+$ ]] || { log ERROR "Memory must be a number"; return 1; }
  (( memory >= MIN_MEMORY )) || { log ERROR "Memory must be at least ${MIN_MEMORY}MB"; return 1; }
  (( memory <= max_memory )) || { log ERROR "Memory exceeds ${max_memory}MB"; return 1; }
  return 0
}

validate_cores() {
  local cores="$1"
  local max_cores
  max_cores="$(nproc)"
  [[ "$cores" =~ ^[0-9]+$ ]] || { log ERROR "Cores must be a number"; return 1; }
  (( cores >= 1 )) || { log ERROR "Must have at least 1 core"; return 1; }
  (( cores <= max_cores )) || { log ERROR "Cores exceed $max_cores"; return 1; }
  return 0
}

validate_storage_space() {
  local storage="$1"
  log STEP "Validating storage space"

  # pvesm status columns:
  # Name Type Status Total(KiB) Used(KiB) Available(KiB) %
  local available_kib
  available_kib="$(pvesm status -storage "$storage" 2>/dev/null | awk -v s="$storage" 'NR>1 && $1==s {print $6; exit}')"

  if [[ "$available_kib" =~ ^[0-9]+$ ]]; then
    local available_gib=$(( available_kib / 1024 / 1024 ))
    if (( available_gib < MIN_DISK_SPACE_GB )); then
      log ERROR "Insufficient space on $storage: ${available_gib}GB available, ${MIN_DISK_SPACE_GB}GB required"
      return 1
    fi
    log SUCCESS "Storage space: ${available_gib}GB available"
    return 0
  fi

  log WARN "Could not determine storage space for $storage (will proceed anyway)"
  return 0
}

check_vm_exists() {
  local vm_id="$1"
  if qm status "$vm_id" >/dev/null 2>&1; then
    log ERROR "VM $vm_id already exists"
    return 1
  fi
  return 0
}

###################################################################################
# INPUT
###################################################################################

get_next_vm_id() { pvesh get /cluster/nextid 2>/dev/null || echo "100"; }
get_network_bridges() { ip -o link show | awk -F': ' '{print $2}' | grep '^vmbr' || echo "vmbr0"; }
get_available_storages() { pvesm status -content images 2>/dev/null | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print $1}' || echo "local-lvm"; }

prompt_vm_id() {
  local default_id
  default_id="$(get_next_vm_id)"
  echo >&2
  print_info "Next available VM ID: $default_id" >&2
  read -p "Enter VM ID [default: $default_id]: " -r vm_id
  vm_id="${vm_id:-$default_id}"
  [[ "$vm_id" =~ ^[0-9]+$ ]] || { log ERROR "VM ID must be a number"; return 1; }
  check_vm_exists "$vm_id" || return 1
  echo "$vm_id"
}

prompt_memory() {
  local max_memory
  max_memory="$(free -m | awk '/^Mem:/{print $2}')"
  echo >&2
  print_info "Memory range: ${MIN_MEMORY}MB to ${max_memory}MB" >&2
  read -p "Enter memory in MB [default: $DEFAULT_MEMORY]: " -r memory
  memory="${memory:-$DEFAULT_MEMORY}"
  validate_memory "$memory" || return 1
  echo "$memory"
}

prompt_cores() {
  local max_cores
  max_cores="$(nproc)"
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
  [[ ${#bridges[@]} -gt 0 ]] || { log ERROR "No bridges found"; return 1; }

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
  [[ ${#storages[@]} -gt 0 ]] || { log ERROR "No storage found"; return 1; }

  echo >&2
  print_info "Available storages (content: images):" >&2
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
    [[ -n "$username" ]] || { log ERROR "Username cannot be empty"; continue; }
    validate_username "$username" && echo "$username" && return 0
  done
}

prompt_password() {
  while true; do
    echo >&2
    read -p "Enter password: " -rs password
    echo >&2
    [[ -n "$password" ]] || { log ERROR "Password cannot be empty"; continue; }
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
# CONFIG GATHER
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

    [[ -n "${VM_USERNAME:-}" ]] || die "VM_USERNAME required in non-interactive mode"
    [[ -n "${VM_PASSWORD:-}" ]] || die "VM_PASSWORD required in non-interactive mode"

    check_vm_exists "$VM_ID" || exit 2
    validate_memory "$VM_MEMORY" || exit 2
    validate_cores "$VM_CORES" || exit 2
    validate_hostname "$VM_HOSTNAME" || exit 2
    validate_username "$VM_USERNAME" || exit 2
  fi

  # Defensive re-validation (catches variable corruption early)
  validate_username "$VM_USERNAME" || die "Invalid username after gathering: $VM_USERNAME"
  validate_hostname "$VM_HOSTNAME" || die "Invalid hostname after gathering: $VM_HOSTNAME"

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
    if [[ "${confirm:-Y}" =~ ^[Nn]$ ]]; then
      log INFO "Cancelled"
      exit 0
    fi
  fi
  return 0
}

###################################################################################
# DOWNLOAD + VERIFY
###################################################################################

download_and_verify_image() {
  local image_url="$1"
  local image_name
  image_name="$(basename "$image_url")"
  local checksums_url="${image_url%/*}/SHA512SUMS"

  # IMPORTANT: log to STDERR so command substitution remains clean
  log STEP "Downloading cloud image" >&2

  mkdir -p "$TEMPLATE_DIR" >&2
  cd "$TEMPLATE_DIR" >&2

  log INFO "Downloading checksums: $checksums_url" >&2
  wget -q "$checksums_url" -O SHA512SUMS || die "Failed to download checksums"
  CLEANUP_FILES+=("$TEMPLATE_DIR/SHA512SUMS")

  #log INFO "Downloading image: $image_name" >&2
  #if [[ "$IS_INTERACTIVE" = true ]]; then
  #  wget --show-progress -O "$image_name" "$image_url" || die "Failed to download image"
  #else
  #  wget -O "$image_name" "$image_url" || die "Failed to download image"
  #fi

log INFO "Downloading image: $image_name" >&2

if [[ "$IS_INTERACTIVE" = true ]]; then
  # Single updating progress bar line (no scroll spam)
  wget --progress=bar:force:noscroll -O "$image_name" "$image_url" \
    || die "Failed to download image"
else
  # Quiet for non-interactive runs (cron/CI/logs)
  wget -q -O "$image_name" "$image_url" \
    || die "Failed to download image"
fi

  log SUCCESS "Image downloaded: $image_name" >&2
  [[ "${KEEP_DOWNLOADS:-false}" != "true" ]] && CLEANUP_FILES+=("$TEMPLATE_DIR/$image_name")

  if [[ "${SKIP_CHECKSUM:-false}" != "true" ]]; then
    log STEP "Verifying integrity" >&2
    local checksum_line
    checksum_line="$(grep -E "([[:space:]]|\\*)${image_name}$" SHA512SUMS | head -n 1 || true)"
    [[ -n "$checksum_line" ]] || die "No checksum found for $image_name"
    echo "$checksum_line" | sha512sum -c --status || die "Checksum verification failed"
    log SUCCESS "Image verified" >&2
  else
    log WARN "Checksum verification skipped (NOT RECOMMENDED)" >&2
  fi

  # ONLY stdout output for safe capture
  printf '%s\n' "$image_name"
}

###################################################################################
# IMAGE CUSTOMIZATION
###################################################################################

customize_image() {
  local image_path="$1"
  local username="$2"
  local password="$3"

  log STEP "Customizing image (virt-customize)"

  virt-customize -a "$image_path" \
    --run-command "passwd -l root || true" \
    --run-command "id -u '$username' >/dev/null 2>&1 || useradd -m -s /bin/bash '$username'" \
    --run-command "usermod -aG sudo '$username'" \
    --password "$username:password:$password" \
    --run-command "rm -f /etc/ssh/ssh_host_* || true" \
    --run-command "cloud-init clean --logs --seed || true" \
    --run-command "truncate -s 0 /etc/machine-id || true" \
    || die "virt-customize failed (LIBGUESTFS_BACKEND=$LIBGUESTFS_BACKEND)"

  log SUCCESS "Image customized"
}

###################################################################################
# VM CREATION
###################################################################################

create_cloudinit_userdata() {
  local vm_id="$1"
  local hostname="$2"
  local userdata_file="$SNIPPET_DIR/userdata-${vm_id}.yaml"

  mkdir -p "$SNIPPET_DIR"

  cat > "$userdata_file" <<EOF
#cloud-config
hostname: ${hostname}
fqdn: ${hostname}
package_update: true
packages:
  - qemu-guest-agent
  - openssh-server
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
    --net0 "virtio,bridge=${bridge},firewall=1" \
    || die "Failed to create VM"

  CREATED_VM_ID="$vm_id"

  print_subheader "Importing disk into storage: $storage"

  local tmp_import import_output disk_name
  tmp_import="$(mktemp)"
  CLEANUP_FILES+=("$tmp_import")

  # Where to show progress: prefer real TTY so it stays visible even with global tee logging
  local PROG_OUT="/dev/stderr"
  [[ -w /dev/tty ]] && PROG_OUT="/dev/tty"

  if [[ "$IS_INTERACTIVE" = true ]]; then
    # Stream import output to file; render only % updates to console (single updating line)
    qm importdisk "$vm_id" "$image_path" "$storage" 2>&1 \
      | tee "$tmp_import" \
      | awk -v out="$PROG_OUT" '
          /^transferred / {
            pct=$NF; gsub(/[()]/,"",pct);
            printf("\r    Import progress: %s", pct) > out;
            fflush(out);
            next
          }
          END { print "" > out }
        ' >/dev/null
  else
    # Non-interactive: capture output (no progress spam)
    qm importdisk "$vm_id" "$image_path" "$storage" 2>&1 | tee "$tmp_import" >/dev/null
  fi

  import_output="$(cat "$tmp_import")"

  # Keep the final summary line(s) visible in the console/log
  echo "$import_output" | grep -E '^(importing disk|unused[0-9]+:|Successfully|successfully|error:|failed|TASK ERROR:)' || true

  # Best-effort parse of the imported volume name
  # Handles outputs like:
  # unused0: successfully imported disk 'vm:vm-110-disk-0'
  disk_name="$(echo "$import_output" | sed -n "s/.*unused0: successfully imported disk '\\''\(${storage}:[^'\\\"]\+\)'\\''.*/\1/p" | head -n1 || true)"
  [[ -n "$disk_name" ]] || disk_name="${storage}:vm-${vm_id}-disk-0"

  print_subheader "Configuring VM"
  qm set "$vm_id" --scsihw virtio-scsi-single --scsi0 "${disk_name},cache=writeback,discard=on,ssd=1"
  qm set "$vm_id" --boot c --bootdisk scsi0
  qm set "$vm_id" --scsi2 "${storage}:cloudinit"
  qm set "$vm_id" --agent enabled=1 --serial0 socket --vga serial0
  qm set "$vm_id" --cpu cputype=host --ostype l26 --ciupgrade 1
  qm set "$vm_id" --balloon 2048

  # NOTE: qm set does NOT support --hostname; hostname comes from cloud-init user-data.
  qm set "$vm_id" --ciuser "$username" --cipassword "$password" --ipconfig0 ip=dhcp

  local userdata_file
  userdata_file="$(create_cloudinit_userdata "$vm_id" "$hostname")"
  qm set "$vm_id" --cicustom "user=local:snippets/$(basename "$userdata_file")" \
    || die "Failed to set cicustom (ensure local storage supports snippets)"

  qm set "$vm_id" --tags "vm,template,debian13"

  log SUCCESS "VM created"
}

convert_to_template() {
  local vm_id="$1"
  log STEP "Converting to template"
  qm template "$vm_id" || die "Failed to convert to template"
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

  log INFO "Continuing after confirmation..."

  local image_name
  image_name="$(download_and_verify_image "$IMAGE_URL")"
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

  exit 0
}

main "$@"