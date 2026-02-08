---
name: lab-app-script
description: Guide for creating deployment scripts for the vdarkobar/lab repository on Debian 13 (Trixie) servers in Proxmox VE environments
---

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
- Server base scripts live in: `server/<n>.sh`
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

print_section() {
    local msg="$*"
    echo
    echo "${C_BOLD}${C_WHITE}═══ ${msg} ═══${C_RESET}"
    echo
}
```

### Visual Elements (Identical Across Scripts)

```bash
#############################################################################
# Visual Elements                                                           #
#############################################################################

draw_box() {
    local title="$1"
    shift
    local lines=("$@")
    
    # Calculate max width
    local max_width=0
    for line in "${lines[@]}"; do
        local stripped_line
        stripped_line=$(echo "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
        [[ ${#stripped_line} -gt $max_width ]] && max_width=${#stripped_line}
    done
    
    # Ensure minimum width for title
    [[ ${#title} -gt $max_width ]] && max_width=${#title}
    
    local box_width=$((max_width + 4))
    local border
    border=$(printf '═%.0s' $(seq 1 $box_width))
    
    # Top border
    echo "${C_CYAN}╔${border}╗${C_RESET}"
    
    # Title (centered)
    if [[ -n "$title" ]]; then
        local title_padding=$(( (box_width - ${#title}) / 2 ))
        local title_line
        title_line=$(printf "%-${box_width}s" "$(printf "%${title_padding}s")${title}")
        echo "${C_CYAN}║${C_RESET} ${C_BOLD}${C_WHITE}${title_line}${C_RESET} ${C_CYAN}║${C_RESET}"
        echo "${C_CYAN}╠${border}╣${C_RESET}"
    fi
    
    # Content lines
    for line in "${lines[@]}"; do
        local stripped_line
        stripped_line=$(echo "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
        local padding=$((box_width - ${#stripped_line}))
        local padded_line="${line}$(printf ' %.0s' $(seq 1 $padding))"
        echo "${C_CYAN}║${C_RESET} ${padded_line} ${C_CYAN}║${C_RESET}"
    done
    
    # Bottom border
    echo "${C_CYAN}╚${border}╝${C_RESET}"
}

draw_separator() {
    local char="${1:-─}"
    local width="${2:-80}"
    printf "${C_CYAN}%${width}s${C_RESET}\n" | tr ' ' "$char"
}
```

### Logging Functions (Identical Across Scripts)

```bash
#############################################################################
# Logging Functions                                                         #
#############################################################################

# Strip ANSI codes for clean log files
strip_ansi() {
    echo "$1" | sed -r 's/\x1B\[[0-9;]*[mK]//g'
}

# Unified logging function
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local stripped_msg
    stripped_msg=$(strip_ansi "$msg")
    
    # Append to log file (if LOG_FILE is set)
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${stripped_msg}" >> "${LOG_FILE}"
    fi
}

# Fatal error handler
die() {
    local msg="$*"
    print_error "$msg"
    log ERROR "$msg"
    exit 1
}

# Setup logging directory and file
setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" || {
            print_error "Failed to create log directory: $LOG_DIR"
            exit 1
        }
        sudo chmod 755 "$LOG_DIR"
    fi
    
    # Create log file (as current user)
    if ! touch "$LOG_FILE" 2>/dev/null; then
        if ! sudo touch "$LOG_FILE"; then
            print_error "Failed to create log file: $LOG_FILE"
            exit 1
        fi
        sudo chown "$(whoami):$(whoami)" "$LOG_FILE"
    fi
    
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    log INFO "=== ${SCRIPT_NAME}.sh v${SCRIPT_VERSION} started ==="
    log INFO "Executed by: $(whoami)"
    log INFO "Host: $(hostname)"
    log INFO "Date: $(date)"
}
```

### Helper Functions (Identical Across Scripts)

```bash
#############################################################################
# Helper Functions                                                          #
#############################################################################

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

is_silent() {
    [[ "${SILENT:-false}" == "true" ]]
}

# Get local IP (primary interface)
get_local_ip() {
    local ip
    
    # Try ip route first (most reliable)
    ip=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+')
    
    # Fallback to hostname -I (first IP)
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    # Final fallback
    if [[ -z "$ip" ]]; then
        ip="<IP>"
    fi
    
    echo "$ip"
}
```

#############################################################################
# Spinner (Optional - For Long-Running Operations)                         #
#############################################################################

# Spinner characters (with ASCII fallback for non-UTF-8 terminals)
# Declare in a separate block AFTER standard Unicode symbols
if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
else
    readonly SPINNER_CHARS='|/-\'
fi

# Run a command with an animated spinner, elapsed timer, and log capture.
# All command output is redirected to LOG_FILE. Console shows a spinner
# that resolves to ✓/✗ on completion with elapsed time.
#
# Usage:
#   run_with_spinner "Message" command arg1 arg2...
#
# Notes:
#   - Command runs in a background subshell (trap ERR does not fire for it)
#   - Safe with set -e: uses 'wait || exit_code=$?' to prevent errexit from
#     killing the function before cleanup (temp file removal, log capture)
#   - Exit code is preserved and returned to caller
#   - Falls back to running without spinner if mktemp fails
#   - No ANSI color codes during spin loop (avoids tput sgr0 glyph artifacts)

run_with_spinner() {
    local msg="$1"
    shift
    local pid tmp_out exit_code=0
    local spin_idx=0 start_ts now_ts elapsed

    # Skip spinner in non-interactive mode
    if ! [[ -t 1 ]] || is_silent; then
        print_step "$msg"
        log STEP "$msg"
        if "$@"; then
            print_success "Done"
            log SUCCESS "$msg - completed"
            return 0
        else
            print_error "Failed"
            log ERROR "$msg - failed"
            return 1
        fi
    fi

    tmp_out="$(mktemp)" || { log WARN "mktemp failed, running without spinner"; "$@"; return $?; }
    start_ts="$(date +%s)"

    log STEP "$msg" 2>/dev/null || true

    # Run command in background, capture all output
    "$@" >"$tmp_out" 2>&1 &
    pid=$!

    # Show spinner while command runs
    # IMPORTANT: No color codes in the spin loop — tput sgr0 emits \033(B
    # (G0 charset reset) which renders as a white square next to braille
    # characters on many terminals. Colors are only used on the final line.
    printf "  %s " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        printf "\r  %s %s (%ds)" "$msg" "${SPINNER_CHARS:spin_idx++%${#SPINNER_CHARS}:1}" "$elapsed"
        sleep 0.1
    done

    # Capture exit code (|| prevents set -e from killing before cleanup)
    wait "$pid" || exit_code=$?

    # Append command output to log file
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" ]]; then
        cat "$tmp_out" >> "$LOG_FILE" 2>/dev/null || true
    fi
    rm -f "$tmp_out"

    # Show result with elapsed time (colors only on final line)
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [[ $exit_code -eq 0 ]]; then
        printf "\r  %s %s (%ds)\n" "$msg" "${C_GREEN}${SYMBOL_SUCCESS}${C_RESET}" "$elapsed"
    else
        printf "\r  %s %s (%ds)\n" "$msg" "${C_RED}${SYMBOL_ERROR}${C_RESET}" "$elapsed"
    fi

    return $exit_code
}

### Cleanup Pattern (Mandatory)

```bash
#############################################################################
# Cleanup Handler                                                           #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == "true" ]]; then
        print_step "Restarting unattended-upgrades service..."
        sudo systemctl start unattended-upgrades 2>/dev/null || true
        log INFO "Restarted unattended-upgrades service"
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        log INFO "=== Installation completed successfully ==="
    else
        log ERROR "=== Installation failed with exit code: $exit_code ==="
    fi
}

trap cleanup EXIT INT TERM
```

### Preflight Checks (Mandatory)

```bash
#############################################################################
# Preflight Checks                                                          #
#############################################################################

preflight_checks() {
    print_section "Pre-flight Checks"
    
    # Refuse Proxmox host execution
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC."
    fi
    
    # Check systemd
    if [[ ! -d /run/systemd/system ]]; then
        die "This script requires systemd"
    fi
    
    # Check OS version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian"
        fi
        print_info "Detected OS: $PRETTY_NAME"
        log INFO "OS: $PRETTY_NAME"
    fi
    
    # Stop unattended-upgrades if running
    if service_is_active unattended-upgrades; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        print_step "Stopping unattended-upgrades service..."
        sudo systemctl stop unattended-upgrades
        log INFO "Stopped unattended-upgrades service"
    fi
    
    print_success "Pre-flight checks passed"
    log SUCCESS "Pre-flight checks completed"
}
```

---

## Firewall Configuration Pattern

### CRITICAL RULES

1. **NEVER enable UFW** - Scripts only add rules to existing configuration
2. **NEVER modify default policies** - Scripts don't touch INPUT/OUTPUT/FORWARD defaults
3. **Add rules ONLY if UFW is active** - Respect existing firewall state
4. **Idempotent operations** - Check if rule exists before adding
5. **Graceful failures** - Handle missing UFW without hard errors

### Standard Firewall Function

```bash
configure_firewall() {
    print_section "Firewall Configuration"
    
    # Skip if requested
    if [[ "${SKIP_FIREWALL}" == "true" ]]; then
        print_warning "Skipping firewall configuration (SKIP_FIREWALL=true)"
        log WARN "Firewall configuration skipped by user request"
        return 0
    fi
    
    # Check if UFW exists and is installed
    if ! command_exists ufw; then
        print_warning "UFW not installed - skipping firewall configuration"
        log WARN "UFW not available, firewall configuration skipped"
        return 0
    fi
    
    # Verify we can access ufw (PATH issue workaround)
    local ufw_cmd
    if command -v ufw >/dev/null 2>&1; then
        ufw_cmd="ufw"
    elif [[ -x /usr/sbin/ufw ]]; then
        ufw_cmd="/usr/sbin/ufw"
    else
        print_warning "UFW command not accessible - skipping firewall configuration"
        log WARN "UFW binary not in PATH or /usr/sbin, firewall configuration skipped"
        return 0
    fi
    
    # Check UFW status
    local ufw_status
    if ! ufw_status=$(sudo $ufw_cmd status 2>/dev/null); then
        print_warning "Cannot determine UFW status - skipping firewall configuration"
        log WARN "UFW status check failed, firewall configuration skipped"
        return 0
    fi
    
    # Only proceed if UFW is active
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        print_info "UFW is installed but not active - skipping firewall configuration"
        log INFO "UFW not active, firewall configuration skipped"
        return 0
    fi
    
    # UFW is active - add rules
    print_step "Adding firewall rules..."
    
    # Check if rule already exists (idempotency)
    if sudo $ufw_cmd status numbered | grep -q "${APP_PORT}/tcp"; then
        print_info "Firewall rule for port ${APP_PORT}/tcp already exists"
        log INFO "UFW rule for ${APP_PORT}/tcp already configured"
    else
        # Try to add rule with comment first
        if sudo $ufw_cmd allow ${APP_PORT}/tcp comment "${SCRIPT_NAME}" 2>/dev/null; then
            print_success "Added firewall rule: allow ${APP_PORT}/tcp"
            log SUCCESS "UFW rule added: ${APP_PORT}/tcp"
        else
            # Fallback: try without comment (older UFW versions)
            if sudo $ufw_cmd allow ${APP_PORT}/tcp 2>/dev/null; then
                print_success "Added firewall rule: allow ${APP_PORT}/tcp (no comment support)"
                log SUCCESS "UFW rule added: ${APP_PORT}/tcp (no comment)"
            else
                print_warning "Failed to add firewall rule - you may need to add manually:"
                print_warning "  sudo ufw allow ${APP_PORT}/tcp"
                log WARN "UFW rule addition failed for ${APP_PORT}/tcp"
            fi
        fi
    fi
}
```

---

## Configuration File Management Pattern

### Configuration Write Contract

When managing configuration files:

1. **Atomic writes**: Write to temp file, then move
2. **Backup on change**: Keep `.bak` if content differs
3. **Validate before apply**: Use app-specific validation (testparm, nginx -t, etc.)
4. **Restart only on change**: Compare checksums to avoid unnecessary restarts

### Example: Samba Configuration

```bash
configure_samba() {
    local config_file="/etc/samba/smb.conf"
    local temp_file="${config_file}.tmp"
    local backup_file="${config_file}.bak"
    
    # Generate new config
    cat > "$temp_file" << 'EOF'
[global]
    workgroup = WORKGROUP
    server string = Lab Samba Server
    security = user
    map to guest = bad user
    
[share]
    path = /srv/samba/share
    browseable = yes
    read only = no
    guest ok = yes
EOF
    
    # Validate new config
    if ! testparm -s "$temp_file" >/dev/null 2>&1; then
        rm -f "$temp_file"
        die "Invalid Samba configuration generated"
    fi
    
    # Check if config changed
    local config_changed=false
    if [[ -f "$config_file" ]]; then
        if ! diff -q "$config_file" "$temp_file" >/dev/null 2>&1; then
            config_changed=true
            sudo cp "$config_file" "$backup_file"
            print_info "Backed up existing config to $backup_file"
        fi
    else
        config_changed=true
    fi
    
    # Apply new config
    sudo mv "$temp_file" "$config_file"
    sudo chmod 644 "$config_file"
    
    # Restart service only if config changed
    if [[ "$config_changed" == "true" ]]; then
        print_step "Restarting Samba service..."
        sudo systemctl restart smbd nmbd
        sleep 2
        
        if ! service_is_active smbd; then
            die "Samba service failed to start"
        fi
        
        print_success "Samba service restarted"
    else
        print_info "Configuration unchanged - no restart needed"
    fi
}
```

---

## Interactive Elements Pattern

### Introduction Screen

```bash
show_intro() {
    [[ -t 1 ]] && ! is_silent && clear
    
    local local_ip
    local_ip=$(get_local_ip)
    
    draw_box "AppName Installation" \
        "" \
        "${C_BOLD}System Information${C_RESET}" \
        "  ${SYMBOL_BULLET} Hostname: $(hostname)" \
        "  ${SYMBOL_BULLET} IP Address: ${local_ip}" \
        "  ${SYMBOL_BULLET} User: $(whoami)" \
        "" \
        "${C_BOLD}Installation Steps${C_RESET}" \
        "  ${SYMBOL_BULLET} Install required packages" \
        "  ${SYMBOL_BULLET} Configure application" \
        "  ${SYMBOL_BULLET} Setup firewall rules" \
        "  ${SYMBOL_BULLET} Start services" \
        "" \
        "${C_BOLD}Requirements${C_RESET}" \
        "  ${SYMBOL_BULLET} Debian 13 (Trixie) or 12 (Bookworm)" \
        "  ${SYMBOL_BULLET} Non-root user with sudo" \
        "  ${SYMBOL_BULLET} Internet connectivity" \
        ""
    
    echo
}

confirm_start() {
    if is_silent; then
        return 0
    fi
    
    local response
    read -r -p "${C_YELLOW}${C_BOLD}Continue with installation? [y/N]:${C_RESET} " response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            log INFO "User confirmed installation"
            return 0
            ;;
        *)
            print_info "Installation cancelled by user"
            log INFO "Installation cancelled by user"
            exit 0
            ;;
    esac
}
```

### Already Installed Screen

```bash
show_already_installed() {
    local local_ip
    local_ip=$(get_local_ip)
    
    draw_box "AppName Already Installed" \
        "" \
        "${C_BOLD}Access Information${C_RESET}" \
        "  ${SYMBOL_BULLET} URL: http://${local_ip}:${APP_PORT}" \
        "" \
        "${C_BOLD}Management Commands${C_RESET}" \
        "  ${SYMBOL_BULLET} Status:    $0 --status" \
        "  ${SYMBOL_BULLET} Logs:      $0 --logs [N]" \
        "  ${SYMBOL_BULLET} Configure: $0 --configure" \
        "  ${SYMBOL_BULLET} Uninstall: $0 --uninstall" \
        ""
    
    echo
    exit 0
}
```

---

## Package Management Patterns

### Selective Package Installation

Only install packages that aren't already present:

```bash
install_packages() {
    print_section "Package Installation"
    
    local packages_needed=()
    local packages_to_check=("curl" "wget" "git" "vim")
    
    # Check which packages need installation
    for pkg in "${packages_to_check[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            packages_needed+=("$pkg")
        fi
    done
    
    if [[ ${#packages_needed[@]} -eq 0 ]]; then
        print_info "All required packages already installed"
        log INFO "No packages need installation"
        return 0
    fi
    
    print_step "Installing packages: ${packages_needed[*]}"
    log INFO "Installing: ${packages_needed[*]}"
    
    sudo apt-get update -qq
    sudo apt-get install -y "${packages_needed[@]}"
    
    print_success "Packages installed"
    log SUCCESS "Package installation completed"
}
```

### GPG Key Management (Idempotent)

```bash
setup_repository() {
    local keyring="/usr/share/keyrings/app.gpg"
    local key_url="https://example.com/key.gpg"
    
    # Only download if key doesn't exist
    if [[ ! -f "$keyring" ]]; then
        print_step "Adding repository GPG key..."
        curl -fsSL "$key_url" | sudo gpg --dearmor -o "$keyring"
        print_success "GPG key added"
    else
        print_info "GPG key already present"
    fi
    
    # Add repository source (idempotent)
    local sources_file="/etc/apt/sources.list.d/app.list"
    if [[ ! -f "$sources_file" ]]; then
        echo "deb [signed-by=$keyring] https://example.com/repo stable main" \
            | sudo tee "$sources_file" >/dev/null
        sudo apt-get update -qq
        print_success "Repository added"
    else
        print_info "Repository already configured"
    fi
}
```

---

## Docker Application Patterns

### Docker Group Management

```bash
setup_docker_access() {
    # Add user to docker group (idempotent)
    if ! groups | grep -q docker; then
        print_step "Adding user to docker group..."
        sudo usermod -aG docker "$(whoami)"
        log INFO "User added to docker group"
        
        print_warning "You may need to log out and back in for group changes to take effect"
        print_info "For this session, docker commands will use sudo"
    fi
}

# Docker command wrapper with sudo fallback
docker_cmd() {
    if docker info >/dev/null 2>&1; then
        docker "$@"
    else
        sudo docker "$@"
    fi
}
```

### Docker Compose Service Management

```bash
start_docker_service() {
    local compose_dir="/opt/app"
    
    print_step "Starting Docker containers..."
    
    cd "$compose_dir" || die "Failed to access $compose_dir"
    
    if docker_cmd compose up -d; then
        print_success "Containers started"
        log SUCCESS "Docker containers started"
        
        # Wait for service to be ready
        sleep 5
        
        # Verify containers are running
        if docker_cmd compose ps | grep -q "Up"; then
            print_success "Service is running"
        else
            die "Containers failed to start properly"
        fi
    else
        die "Failed to start Docker containers"
    fi
}

# Status command for Docker apps
cmd_status() {
    local compose_dir="/opt/app"
    
    echo "${C_BOLD}Service Status:${C_RESET}"
    cd "$compose_dir" 2>/dev/null || die "App directory not found"
    docker_cmd compose ps
}

# Logs command for Docker apps
cmd_logs() {
    local lines="${1:-50}"
    local compose_dir="/opt/app"
    
    cd "$compose_dir" 2>/dev/null || die "App directory not found"
    docker_cmd compose logs --tail="$lines"
}
```

---

## Service Management Patterns

### Systemd Service Validation

```bash
start_service() {
    local service_name="$1"
    
    print_step "Starting $service_name..."
    sudo systemctl start "$service_name"
    
    # Wait for service to initialize
    sleep 2
    
    # Verify service is running
    if service_is_active "$service_name"; then
        print_success "$service_name is running"
        log SUCCESS "$service_name started successfully"
    else
        print_error "$service_name failed to start"
        log ERROR "$service_name failed to start"
        
        # Show service status for debugging
        sudo systemctl status "$service_name" --no-pager
        die "Service startup failed"
    fi
}
```

### Multi-Service Applications

```bash
cmd_status() {
    echo "${C_BOLD}Service Status:${C_RESET}"
    
    local services=("service1" "service2" "service3")
    
    for svc in "${services[@]}"; do
        if service_is_active "$svc"; then
            echo "  ${C_GREEN}${SYMBOL_SUCCESS}${C_RESET} $svc: ${C_GREEN}active${C_RESET}"
        else
            echo "  ${C_RED}${SYMBOL_ERROR}${C_RESET} $svc: ${C_RED}inactive${C_RESET}"
        fi
    done
    
    echo
    echo "${C_BOLD}Access Information:${C_RESET}"
    echo "  URL: http://$(get_local_ip):${APP_PORT}"
}
```

---

## Post-Install Commands Pattern

### Status Command

```bash
cmd_status() {
    # Service-based apps
    if service_is_active "$SERVICE_NAME"; then
        echo "${C_GREEN}${SYMBOL_SUCCESS}${C_RESET} Service is ${C_GREEN}running${C_RESET}"
    else
        echo "${C_RED}${SYMBOL_ERROR}${C_RESET} Service is ${C_RED}not running${C_RESET}"
    fi
    
    echo
    echo "${C_BOLD}Access Information:${C_RESET}"
    echo "  URL: http://$(get_local_ip):${APP_PORT}"
    echo
    echo "${C_BOLD}Configuration:${C_RESET}"
    echo "  Config: /etc/app/config.conf"
    echo "  Data: /var/lib/app"
    echo
    echo "${C_BOLD}Management:${C_RESET}"
    echo "  Logs:      $0 --logs [N]"
    echo "  Configure: $0 --configure"
    echo "  Uninstall: $0 --uninstall"
}
```

### Logs Command

```bash
cmd_logs() {
    local lines="${1:-50}"
    
    # For systemd services
    sudo journalctl -u "$SERVICE_NAME" -n "$lines" --no-pager
    
    # For Docker apps
    # cd "$INSTALL_DIR" && docker_cmd compose logs --tail="$lines"
    
    # For log files
    # sudo tail -n "$lines" /var/log/app/app.log
}
```

### Configure Command

```bash
cmd_configure() {
    print_section "Configuration"
    
    # Re-run interactive configuration
    configure_app
    
    # Restart service to apply changes
    print_step "Restarting service..."
    sudo systemctl restart "$SERVICE_NAME"
    
    if service_is_active "$SERVICE_NAME"; then
        print_success "Configuration updated and service restarted"
    else
        die "Service failed to restart after configuration"
    fi
}
```

### Uninstall Command

```bash
cmd_uninstall() {
    print_section "Uninstallation"
    
    # Confirm with user unless silent
    if ! is_silent; then
        local response
        read -r -p "${C_YELLOW}${C_BOLD}Remove AppName? This will delete all data. [y/N]:${C_RESET} " response
        
        case "$response" in
            [yY][eE][sS]|[yY]) ;;
            *) print_info "Uninstall cancelled"; exit 0 ;;
        esac
    fi
    
    # Stop services
    if service_is_active "$SERVICE_NAME"; then
        print_step "Stopping services..."
        sudo systemctl stop "$SERVICE_NAME"
        sudo systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove files
    print_step "Removing files..."
    sudo rm -rf /opt/app
    sudo rm -f /etc/systemd/system/app.service
    sudo systemctl daemon-reload
    
    # Remove packages (optional - ask user)
    if ! is_silent; then
        read -r -p "${C_YELLOW}Remove installed packages? [y/N]:${C_RESET} " response
        if [[ "$response" =~ ^[yY] ]]; then
            sudo apt-get remove -y package1 package2
        fi
    fi
    
    # Remove firewall rules
    if command_exists ufw && sudo ufw status | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow ${APP_PORT}/tcp 2>/dev/null || true
    fi
    
    print_success "AppName has been uninstalled"
    
    echo
    print_info "Installation logs preserved at: /var/log/lab/${SCRIPT_NAME}-*.log"
}
```

---

## Summary Screen Pattern

```bash
show_summary() {
    local local_ip
    local_ip=$(get_local_ip)
    
    echo
    draw_box "Installation Complete!" \
        "" \
        "${C_BOLD}Access Information${C_RESET}" \
        "  ${SYMBOL_BULLET} URL: http://${local_ip}:${APP_PORT}" \
        "  ${SYMBOL_BULLET} Default credentials: admin / changeme" \
        "" \
        "${C_BOLD}Installation Details${C_RESET}" \
        "  ${SYMBOL_BULLET} Config: /etc/app/config.conf" \
        "  ${SYMBOL_BULLET} Data: /var/lib/app" \
        "  ${SYMBOL_BULLET} Logs: /var/log/app/app.log" \
        "" \
        "${C_BOLD}Management Commands${C_RESET}" \
        "  ${SYMBOL_BULLET} Status:    $0 --status" \
        "  ${SYMBOL_BULLET} Logs:      $0 --logs [N]" \
        "  ${SYMBOL_BULLET} Configure: $0 --configure" \
        "  ${SYMBOL_BULLET} Uninstall: $0 --uninstall" \
        "" \
        "${C_BOLD}Next Steps${C_RESET}" \
        "  ${SYMBOL_BULLET} Access the web interface" \
        "  ${SYMBOL_BULLET} Change default password" \
        "  ${SYMBOL_BULLET} Review logs: $0 --logs" \
        ""
    
    echo
    print_info "Installation log: ${LOG_FILE}"
    echo
    
    log SUCCESS "Installation completed successfully"
}
```

---

## Secrets Management Pattern

### CRITICAL: When Scripts Handle Secrets

**ONLY set `umask 077` if your script generates secret files** (passwords, tokens, API keys, certificates with private keys).

**DO NOT set `umask 077` if your script:**
- Creates shared directories (web roots, data directories)
- Needs group or world access to any paths
- Uses `mkdir -p` to create parent directories that need traversal

The problem: `umask 077` makes `mkdir -p` create parent directories as `700`, breaking traversal even if you `chmod` the final directory afterward.

### Example: Script That Needs Secrets

```bash
#!/bin/bash
set -euo pipefail

# This script generates passwords and tokens
umask 077  # OK - we're handling secrets

# Create secrets directory
SECRETS_DIR="/opt/app/secrets"
sudo mkdir -p "$SECRETS_DIR"  # Will be 700
sudo chmod 700 "$SECRETS_DIR"

# Generate secret files
generate_password() {
    local file="$1"
    openssl rand -base64 32 | sudo tee "$file" >/dev/null
    sudo chmod 600 "$file"
}

generate_password "$SECRETS_DIR/db_password"
generate_password "$SECRETS_DIR/api_token"
```

### Example: Script That Should NOT Use umask 077

```bash
#!/bin/bash
set -euo pipefail

# This script creates web root - NO SECRETS
# DO NOT set umask 077 here!

# Create web root
WEB_ROOT="/var/www/app"
sudo mkdir -p "$WEB_ROOT/public"  # Needs proper permissions for web server
sudo chmod 755 "$WEB_ROOT"
sudo chmod 755 "$WEB_ROOT/public"
```

### Idempotent Secret Generation

```bash
generate_secrets() {
    local secrets_dir="/opt/app/secrets"
    
    # Create secrets directory if it doesn't exist
    if [[ ! -d "$secrets_dir" ]]; then
        sudo mkdir -p "$secrets_dir"
        sudo chmod 700 "$secrets_dir"
        print_success "Created secrets directory"
    fi
    
    # Generate password only if it doesn't exist
    local password_file="$secrets_dir/admin_password"
    if [[ ! -f "$password_file" ]]; then
        openssl rand -base64 32 | sudo tee "$password_file" >/dev/null
        sudo chmod 600 "$password_file"
        print_success "Generated admin password"
    else
        print_info "Admin password already exists"
    fi
    
    # Show password securely
    echo
    print_info "Admin password: $(sudo cat "$password_file")"
    echo
}
```

---

## Testing & Debugging Patterns

### Debug Logging

```bash
# Add debug flag to any script
DEBUG="${DEBUG:-false}"

debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo "${C_DIM}[DEBUG] $*${C_RESET}" >&2
        log DEBUG "$*"
    fi
}

# Usage in script:
debug "Checking if UFW is active..."
debug "Found packages: ${packages_needed[*]}"
```

### Dry-Run Mode

```bash
DRY_RUN="${DRY_RUN:-false}"

run_command() {
    local cmd="$*"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY-RUN] Would execute: $cmd"
        log INFO "[DRY-RUN] $cmd"
        return 0
    fi
    
    eval "$cmd"
}

# Usage:
# DRY_RUN=true ./script.sh
```

---

## Common Pitfalls & Solutions

### Issue: UFW command not found

**Problem**: Script runs as non-root user, but `ufw` is in `/usr/sbin` which isn't in non-root PATH.

**Solution**: Check both `command -v ufw` and `/usr/sbin/ufw`:

```bash
local ufw_cmd
if command -v ufw >/dev/null 2>&1; then
    ufw_cmd="ufw"
elif [[ -x /usr/sbin/ufw ]]; then
    ufw_cmd="/usr/sbin/ufw"
else
    print_warning "UFW not accessible"
    return 0
fi

sudo $ufw_cmd status
```

### Issue: Log directory not writable

**Problem**: Script tries to create log file before checking sudo.

**Solution**: Check sudo BEFORE creating log file:

```bash
# Check sudo first
if ! sudo -v 2>/dev/null; then
    echo "ERROR: No sudo privileges" >&2
    exit 1
fi

# THEN setup logging
setup_logging
```

### Issue: Config file permissions break service

**Problem**: Service can't read config file created with `umask 077`.

**Solution**: Either don't use `umask 077`, or explicitly fix permissions:

```bash
# Write config
sudo tee /etc/app/config.conf >/dev/null << EOF
key=value
EOF

# Fix permissions explicitly
sudo chmod 644 /etc/app/config.conf
sudo chown root:root /etc/app/config.conf
```

---

## Configuration Templates

### Unbound DNS Configuration

```bash
configure_unbound() {
    local config_file="/etc/unbound/unbound.conf.d/custom.conf"
    local temp_file="${config_file}.tmp"
    
    cat > "$temp_file" << 'EOF'
server:
    # Network
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    # Access control
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    
    # Performance
    num-threads: 2
    msg-cache-size: 128m
    rrset-cache-size: 256m
    cache-min-ttl: 300
    cache-max-ttl: 86400
    
    # Privacy
    hide-identity: yes
    hide-version: yes
    
    # Security
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    
    # Logging
    verbosity: 1
    log-queries: no
    log-replies: no

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 1.0.0.1
EOF
    
    sudo mv "$temp_file" "$config_file"
    sudo chmod 644 "$config_file"
    
    # Validate configuration
    if ! sudo unbound-checkconf >/dev/null 2>&1; then
        die "Invalid Unbound configuration"
    fi
    
    sudo systemctl restart unbound
}
```

### Samba Configuration

```bash
configure_samba() {
    local config_file="/etc/samba/smb.conf"
    local temp_file="${config_file}.tmp"
    
    cat > "$temp_file" << 'EOF'
[global]
    workgroup = WORKGROUP
    server string = Lab Samba Server
    netbios name = LABSERVER
    security = user
    map to guest = bad user
    dns proxy = no
    
    # Performance
    socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=131072 SO_SNDBUF=131072
    read raw = yes
    write raw = yes
    
    # Logging
    log file = /var/log/samba/log.%m
    max log size = 1000
    log level = 1

[Public]
    path = /srv/samba/public
    browseable = yes
    read only = no
    guest ok = yes
    create mask = 0664
    directory mask = 0775
    force user = nobody
    force group = nogroup
EOF
    
    # Validate configuration
    if ! testparm -s "$temp_file" >/dev/null 2>&1; then
        rm -f "$temp_file"
        die "Invalid Samba configuration"
    fi
    
    # Backup and apply
    if [[ -f "$config_file" ]]; then
        sudo cp "$config_file" "${config_file}.bak"
    fi
    
    sudo mv "$temp_file" "$config_file"
    sudo chmod 644 "$config_file"
    
    # Create share directory
    sudo mkdir -p /srv/samba/public
    sudo chmod 777 /srv/samba/public
    
    sudo systemctl restart smbd nmbd
}
```

### Nginx Configuration (for NPM-Docker)

```bash
configure_nginx() {
    local compose_dir="/opt/npm"
    local config_file="$compose_dir/data/nginx/custom.conf"
    
    mkdir -p "$compose_dir/data/nginx"
    
    cat > "$config_file" << 'EOF'
# Custom Nginx settings
client_max_body_size 100M;
proxy_connect_timeout 600s;
proxy_send_timeout 600s;
proxy_read_timeout 600s;
EOF
    
    chmod 644 "$config_file"
}
```

---

## Example: Complete cloudflared.sh Audit

Here's how to audit an existing script against this skill:

```bash
# Check script metadata
grep -E "^readonly SCRIPT_VERSION=" cloudflared.sh
grep -E "^readonly SCRIPT_NAME=" cloudflared.sh

# Check --help handler placement (should be before set -euo pipefail)
grep -n "case.*--help" cloudflared.sh
grep -n "set -euo pipefail" cloudflared.sh

# Check safety checks
grep -n "EUID -eq 0" cloudflared.sh
grep -n "/etc/pve/.version" cloudflared.sh
grep -n "command -v sudo" cloudflared.sh

# Check CLI commands
grep -n "cmd_status()" cloudflared.sh
grep -n "cmd_logs()" cloudflared.sh
grep -n "cmd_configure()" cloudflared.sh
grep -n "cmd_uninstall()" cloudflared.sh

# Check firewall handling
grep -n "configure_firewall()" cloudflared.sh
grep -A 20 "configure_firewall()" cloudflared.sh | grep -E "(ufw enable|default)"

# Check logging
grep -n "setup_logging()" cloudflared.sh
grep -n "log ERROR" cloudflared.sh
grep -n "log SUCCESS" cloudflared.sh
```

**Common audit failures:**

1. `die()` using `print_error` instead of `log ERROR`
2. Missing `cmd_configure()` implementation
3. Firewall function trying to enable UFW
4. Missing spinner for long operations (>5 sec)
5. `--help` handler after `set -euo pipefail`

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
- [ ] (Optional) `SPINNER_CHARS` declared in separate block after standard Unicode symbols, with ASCII fallback for non-UTF-8
- [ ] (Optional) `run_with_spinner()` — if used, must match skill verbatim; no ANSI codes in spin loop

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

**Interactive Flow:**
- [ ] `show_intro()` displays title, system info, steps, requirements
- [ ] `confirm_start()` gates installation behind yes/no prompt
- [ ] `show_already_installed()` shown when re-running on existing install
- [ ] Clear screen guarded with `[[ -t 1 ]] && ! is_silent && clear`
- [ ] All interactive prompts skipped when `is_silent` returns true

**Package Management:**
- [ ] Selective install: check `dpkg -s` before `apt-get install`
- [ ] GPG keys guarded with existence check before download
- [ ] `apt-get update` only called when packages are actually needed

**Docker Apps (if applicable):**
- [ ] User added to docker group (idempotent)
- [ ] `docker info` check before every `docker compose` call (sudo fallback)
- [ ] `cmd_status` uses `docker compose ps`
- [ ] `cmd_logs` uses `docker compose logs --tail=`

**Service Management:**
- [ ] Config validated before service restart (testparm, checkconf, -t, etc.)
- [ ] Service verified running after start (`sleep` + `service_is_active`)
- [ ] Multi-service apps check all dependent services in `cmd_status`

---

## Repository Integration

After creating a new script:

1. Place in `apps/` directory
2. Add to `hardening.sh` APP_REGISTRY array
3. Update `CHECKSUMS.txt`: `sha256sum apps/newapp.sh >> CHECKSUMS.txt`
4. Add to README.md documentation
