#!/bin/bash

#############################################################################
# Lab Bootstrap Script                                                      #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Creates directory structure (server/, apps/, pve/, misc/)            #
#   2. Downloads all components from GitHub (including itself)              #
#   3. Verifies checksums for security                                      #
#   4. Presents menu to run setup scripts                                   #
#                                                                           #
# INSTALLATION METHODS:                                                     #
#                                                                           #
# Quick Install (convenient):                                               #
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
#                                                                           #
# Secure Install (verified):                                                #
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh && \
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256 && \
#   sha256sum -c bootstrap.sh.sha256                                        #
#                                                                           #
#   chmod +x bootstrap.sh && \                                              #
#   ./bootstrap.sh                                                          #
#                                                                           #
# Full source code review:                                                  #
#   https://github.com/vdarkobar/lab/blob/main/bootstrap.sh                 #
#############################################################################

#############################################################################
# Script Metadata                                                           #
#############################################################################

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="bootstrap"

#############################################################################
# Configuration                                                             #
#############################################################################

set -euo pipefail

readonly REPO_URL="https://raw.githubusercontent.com/vdarkobar/lab/main"
readonly INSTALL_DIR="$HOME/lab"
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"

#############################################################################
# Safety Checks (Before Any State Changes)                                 #
#############################################################################

# Bootstrap is special: it CAN run on PVE host (to download pve scripts)
# or on VMs/LXC (to download server/app scripts), or on workstation.
# Therefore, we skip the PVE host check unlike other lab scripts.

# Check for root (warn but allow - bootstrap doesn't need sudo)
if [[ ${EUID} -eq 0 ]]; then
    echo "WARNING: Running as root" >&2
    echo "Bootstrap doesn't require sudo and can run as any user" >&2
    echo "Press Ctrl+C to abort, or Enter to continue..." >&2
    read -r
fi

#############################################################################
# Terminal Formatting (Standard)                                            #
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
    readonly C_MAGENTA=$(tput setaf 5)
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
    readonly C_MAGENTA=""
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
# Output Functions (Standard)                                               #
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

#############################################################################
# Visual Elements (Standard)                                                #
#############################################################################

draw_box() {
    local text="$1"
    local width=62
    local text_len=${#text}
    local padding=$(( (width - text_len - 2) / 2 ))
    local padding_right=$(( width - text_len - padding - 2 ))

    echo "${C_CYAN}"
    echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
    printf "║%*s%s%*s║\n" $((padding + 1)) "" "$text" $((padding_right + 1)) ""
    echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
    echo "${C_RESET}"
}

draw_separator() {
    local char="${1:-─}"
    local width="${2:-80}"
    printf "${C_CYAN}%${width}s${C_RESET}\n" | tr ' ' "$char"
}

print_kv() {
    local key="$1"
    local value="$2"
    printf "${C_CYAN}%-20s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$key:" "$value"
}

#############################################################################
# Logging Functions (Standard)                                              #
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
    
    # Append to log file (if LOG_FILE is set and writable)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE}" ]] 2>/dev/null; then
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
    # Try to create log directory (may fail if not running with sudo - that's OK)
    if [[ ! -d "$LOG_DIR" ]]; then
        if mkdir -p "$LOG_DIR" 2>/dev/null || sudo mkdir -p "$LOG_DIR" 2>/dev/null; then
            chmod 755 "$LOG_DIR" 2>/dev/null || sudo chmod 755 "$LOG_DIR" 2>/dev/null || true
        fi
    fi
    
    # Create log file (try as user first, then sudo)
    if [[ -d "$LOG_DIR" ]]; then
        if touch "$LOG_FILE" 2>/dev/null; then
            chmod 644 "$LOG_FILE" 2>/dev/null || true
        elif command -v sudo >/dev/null 2>&1 && sudo -n touch "$LOG_FILE" 2>/dev/null; then
            sudo chown "$(whoami):$(whoami)" "$LOG_FILE" 2>/dev/null || true
            chmod 644 "$LOG_FILE" 2>/dev/null || true
        else
            # Logging disabled - not critical for bootstrap
            return 0
        fi
        
        log INFO "=== ${SCRIPT_NAME}.sh v${SCRIPT_VERSION} started ==="
        log INFO "Executed by: $(whoami)"
        log INFO "Host: $(hostname)"
        log INFO "Date: $(date)"
    fi
}

#############################################################################
# Helper Functions (Standard)                                               #
#############################################################################

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_silent() {
    [[ "${SILENT:-false}" == "true" ]]
}

#############################################################################
# Error Trap (Standard)                                                     #
#############################################################################

error_trap() {
    local line_number=$1
    print_error "Script failed at line ${line_number}"
    log ERROR "Script failed at line ${line_number}: $BASH_COMMAND"
}

trap 'error_trap ${LINENO}' ERR

#############################################################################
# Cleanup Handler                                                           #
#############################################################################

cleanup() {
    local exit_code=$?
    trap - ERR  # Remove error trap to avoid recursion

    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Bootstrap failed"
        log ERROR "Bootstrap exited with code: $exit_code"
        
        if [[ -d "$INSTALL_DIR" ]]; then
            print_warning "Partial installation at: ${INSTALL_DIR/$HOME/~}"
            print_info "You may want to remove it and try again:"
            printf "  %b\n" "${C_CYAN}rm -rf $INSTALL_DIR${C_RESET}"
        fi
    fi
}

trap cleanup EXIT

#############################################################################
# CLI Help Text                                                             #
#############################################################################

show_help() {
    cat << EOF
Lab Bootstrap Script v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
  --help, -h              Show this help message
  --version, -v           Show version information
  --download-only         Download and verify files, then exit
  --vm-template           Download then run PVE VM template script
  --lxc-template          Download then run PVE LXC template script
  --harden                Download then run Debian hardening script
  --jump                  Download then run Jump Server setup script
  (no options)            Interactive menu (default)

INSTALLATION METHODS:

Quick Install (convenient):
  bash -c "\$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"

Secure Install (verified):
  wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh
  wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256
  sha256sum -c bootstrap.sh.sha256
  chmod +x bootstrap.sh && ./bootstrap.sh

WHAT IT DOES:
  - Creates directory structure: ~/lab/{server,apps,pve,misc}
  - Downloads all components from GitHub (including bootstrap itself)
  - Verifies SHA256 checksums for security
  - Presents menu to run setup scripts (or runs directly with --options)

MENU OPTIONS:
  1) Create Debian VM Template  - runs on PVE host
  2) Create Debian LXC Template - runs on PVE host
  3) Harden Debian System       - runs in VM/LXC
  4) Setup Jump Server          - runs in VM/LXC

REQUIREMENTS:
  - wget or curl for downloads
  - sha256sum for verification
  - Internet connectivity

REPOSITORY:
  https://github.com/vdarkobar/lab

EOF
}

#############################################################################
# Context Detection                                                         #
#############################################################################

detect_context() {
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        echo "pve-host"
    elif [[ -f /etc/debian_version ]]; then
        if command -v systemd-detect-virt &>/dev/null && \
           systemd-detect-virt -c >/dev/null 2>&1; then
            echo "lxc"
        else
            echo "vm"
        fi
    else
        echo "workstation"
    fi
}

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_section "Pre-flight Checks"

    # Check for download tools
    if command_exists wget; then
        print_success "wget is available"
        log INFO "wget found"
    elif command_exists curl; then
        print_success "curl is available"
        log INFO "curl found"
    else
        die "Either wget or curl is required for downloads"
    fi

    # Check for checksum verification
    if command_exists sha256sum; then
        print_success "sha256sum is available"
        log INFO "sha256sum found"
    else
        die "sha256sum is required for security verification"
    fi

    # Detect and display context
    local context
    context=$(detect_context)
    print_info "Detected environment: ${C_BOLD}${context}${C_RESET}"
    log INFO "Environment detected: $context"

    echo
}

#############################################################################
# Directory Creation                                                        #
#############################################################################

create_directories() {
    print_section "Creating Directory Structure"

    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Directory ${INSTALL_DIR/$HOME/~} already exists"
        log WARN "Install directory exists: $INSTALL_DIR"
        
        if ! is_silent; then
            echo
            printf "%b" "${C_CYAN}Remove and recreate?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
            read -r response
            if [[ "$response" =~ ^[Yy](es)?$ ]]; then
                rm -rf "$INSTALL_DIR"
                print_success "Removed existing directory"
                log INFO "Removed existing directory: $INSTALL_DIR"
            else
                die "Installation cancelled by user"
            fi
        else
            print_info "SILENT mode: keeping existing directory"
            log INFO "SILENT mode: keeping existing directory"
        fi
    fi

    local directories=(
        "$INSTALL_DIR/server"
        "$INSTALL_DIR/apps"
        "$INSTALL_DIR/pve"
        "$INSTALL_DIR/misc"
    )

    for dir in "${directories[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            print_success "Created: ${dir/$HOME/~}"
            log SUCCESS "Created directory: $dir"
        else
            die "Failed to create directory: $dir"
        fi
    done

    echo
}

#############################################################################
# File Download with Retry                                                  #
#############################################################################

download_file() {
    local url="$1"
    local output="$2"
    local retries=3
    local attempt

    for ((attempt=1; attempt<=retries; attempt++)); do
        # Try wget first, then curl
        if command_exists wget; then
            if wget -q --show-progress "$url" -O "$output" 2>/dev/null; then
                log INFO "Downloaded: $output (wget, attempt $attempt)"
                return 0
            fi
        elif command_exists curl; then
            if curl -fsSL "$url" -o "$output" 2>/dev/null; then
                log INFO "Downloaded: $output (curl, attempt $attempt)"
                return 0
            fi
        fi

        if [[ $attempt -lt $retries ]]; then
            print_warning "Download failed, retrying ($attempt/$retries)..."
            log WARN "Download retry $attempt/$retries for: $url"
            sleep 2
        fi
    done

    log ERROR "Download failed after $retries attempts: $url"
    return 1
}

#############################################################################
# Component Download                                                        #
#############################################################################

download_components() {
    print_section "Downloading Components"

    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"

    # Download master checksums file
    print_step "Downloading checksums manifest..."
    if ! download_file "$REPO_URL/CHECKSUMS.txt" "CHECKSUMS.txt"; then
        die "Failed to download CHECKSUMS.txt"
    fi
    print_success "Downloaded: CHECKSUMS.txt"
    log SUCCESS "Downloaded CHECKSUMS.txt"

    echo

    # Files to download: path|display_name
    local files=(
        "bootstrap.sh|Bootstrap Script (self)"
        "bootstrap.sh.sha256|Bootstrap Checksum"
        "server/hardening.sh|Hardening Script"
        "server/jump.sh|Jump Server Script"
        "pve/debvm.sh|Debian VM Template Script"
        "pve/deblxc.sh|Debian LXC Template Script"
        "apps/docker.sh|Docker Installer"
        "apps/npm.sh|Nginx Proxy Manager Installer (native)"
        "apps/npm-docker.sh|Nginx Proxy Manager Installer (Docker)"
        "apps/cloudflared.sh|Cloudflare Tunnel Installer"
        "apps/unbound.sh|Unbound DNS Installer"
        "apps/samba.sh|Samba File Server Installer"
        "apps/bookstack.sh|Bookstack Wiki Installer"
        "apps/bentopdf.sh|BentoPDF Editor Installer"
        "misc/skill.md|Lab Script Standardization Guide"
        "misc/README.md|Repository Documentation"
    )

    # Download each file
    for file_entry in "${files[@]}"; do
        IFS='|' read -r file_path display_name <<< "$file_entry"

        print_step "Downloading $display_name..."
        if download_file "$REPO_URL/$file_path" "$file_path"; then
            local size
            size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "unknown")
            print_success "Downloaded: $file_path (${size} bytes)"
        else
            print_warning "Optional file not available: $file_path (skipped)"
            log WARN "Skipped unavailable file: $file_path"
        fi
    done

    echo
}

#############################################################################
# Checksum Verification                                                     #
#############################################################################

verify_checksums() {
    print_section "Verifying Checksums"

    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"

    local verification_failed=false
    local verified_count=0
    local skipped_count=0
    local unverified_count=0

    # Build list of files that have checksums
    local -a checksum_files=()
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        local file_path
        file_path=$(echo "$line" | awk '{print $2}')
        checksum_files+=("$file_path")
    done < CHECKSUMS.txt

    # Verify files listed in CHECKSUMS.txt
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue

        # Parse checksum line: "hash  filename"
        local expected_hash
        expected_hash=$(echo "$line" | awk '{print $1}')
        local file_path
        file_path=$(echo "$line" | awk '{print $2}')

        # Skip if file doesn't exist (optional files)
        if [[ ! -f "$file_path" ]]; then
            ((skipped_count++)) || true
            log INFO "Checksum skip (file not downloaded): $file_path"
            continue
        fi

        print_step "Verifying $file_path..."

        local actual_hash
        actual_hash=$(sha256sum "$file_path" | awk '{print $1}')

        if [[ "$actual_hash" == "$expected_hash" ]]; then
            print_success "$file_path: OK"
            log SUCCESS "Checksum verified: $file_path"
            ((verified_count++)) || true
        else
            print_error "$file_path: FAILED"
            print_error "  Expected: ${expected_hash:0:16}..."
            print_error "  Got:      ${actual_hash:0:16}..."
            log ERROR "Checksum FAILED: $file_path (expected: $expected_hash, got: $actual_hash)"
            verification_failed=true
        fi
    done < CHECKSUMS.txt

    # Check for downloaded files not in CHECKSUMS.txt
    local downloaded_files=(
        "bootstrap.sh"
        "bootstrap.sh.sha256"
        "server/hardening.sh"
        "server/jump.sh"
        "pve/debvm.sh"
        "pve/deblxc.sh"
        "apps/docker.sh"
        "apps/npm.sh"
        "apps/npm-docker.sh"
        "apps/cloudflared.sh"
        "apps/unbound.sh"
        "apps/samba.sh"
        "apps/bookstack.sh"
        "apps/bentopdf.sh"
        "misc/SKILL.md"
        "misc/README.md"
    )

    for file_path in "${downloaded_files[@]}"; do
        # Skip if file wasn't downloaded
        [[ ! -f "$file_path" ]] && continue

        # Check if file is in checksum list
        local found=false
        for checksum_file in "${checksum_files[@]}"; do
            if [[ "$checksum_file" == "$file_path" ]]; then
                found=true
                break
            fi
        done

        if [[ "$found" == false ]]; then
            print_warning "$file_path: NO CHECKSUM (not in CHECKSUMS.txt)"
            log WARN "No checksum for: $file_path"
            ((unverified_count++)) || true
        fi
    done

    echo

    if [[ "$verification_failed" == true ]]; then
        die "Checksum verification FAILED! Installation aborted for security."
    fi

    print_success "All verified checksums passed"
    log SUCCESS "Checksum verification complete: $verified_count verified, $skipped_count skipped, $unverified_count unverified"
    
    print_kv "Files verified" "$verified_count"
    print_kv "Files skipped" "$skipped_count"
    if [[ $unverified_count -gt 0 ]]; then
        print_kv "Files unverified" "$unverified_count"
    fi

    echo
}

#############################################################################
# Script Execution (Simplified - Trust the Scripts)                        #
#############################################################################

run_script() {
    local category="$1"  # server, apps, pve
    local script="$2"    # script filename (e.g., hardening.sh)
    local script_path="$INSTALL_DIR/$category/$script"

    print_section "Launching $script"
    log INFO "Running $category/$script"

    # Check if script exists
    if [[ ! -f "$script_path" ]]; then
        print_error "Script not found: $script_path"
        log ERROR "Script not found: $script_path"
        echo
        print_info "This script may not be available yet."
        print_info "Check repository for updates:"
        printf "  %b\n" "${C_CYAN}https://github.com/vdarkobar/lab${C_RESET}"
        exit 1
    fi

    # Change to script directory
    cd "$INSTALL_DIR/$category" || die "Cannot change to $category directory"

    # Make executable
    chmod +x "$script" || die "Cannot make $script executable"

    echo
    print_step "Executing ./$script..."
    log STEP "Executing: $script_path"
    echo

    # Run the script (it will do its own validation)
    if ./"$script"; then
        echo
        print_success "$script completed successfully"
        log SUCCESS "$script completed"
    else
        local exit_code=$?
        echo
        print_error "$script failed (exit code: $exit_code)"
        log ERROR "$script failed with exit code: $exit_code"
        exit "$exit_code"
    fi
}

#############################################################################
# Context-Aware Menu                                                        #
#############################################################################

show_contextual_menu() {
    local context
    context=$(detect_context)

    print_section "What would you like to do?"

    case "$context" in
        pve-host)
            print_info "Environment: Proxmox VE Host"
            echo
            echo "Available actions:"
            printf "  ${C_BOLD}1)${C_RESET} Create Debian VM Template  ${C_DIM}(debvm.sh)${C_RESET}\n"
            printf "  ${C_BOLD}2)${C_RESET} Create Debian LXC Template ${C_DIM}(deblxc.sh)${C_RESET}\n"
            printf "  ${C_BOLD}3)${C_RESET} Exit\n"
            echo
            ;;
        vm|lxc)
            print_info "Environment: Debian ${context}"
            echo
            echo "Available actions:"
            printf "  ${C_BOLD}1)${C_RESET} Harden Debian System ${C_DIM}(hardening.sh)${C_RESET}\n"
            printf "  ${C_BOLD}2)${C_RESET} Setup Jump Server    ${C_DIM}(jump.sh)${C_RESET}\n"
            printf "  ${C_BOLD}3)${C_RESET} Exit\n"
            echo
            ;;
        *)
            print_info "Environment: Unknown (showing all options)"
            echo
            echo "Template creation (run on PVE host):"
            printf "  ${C_BOLD}1)${C_RESET} Create Debian VM Template  ${C_DIM}(debvm.sh)${C_RESET}\n"
            printf "  ${C_BOLD}2)${C_RESET} Create Debian LXC Template ${C_DIM}(deblxc.sh)${C_RESET}\n"
            echo
            echo "Server setup (run in Debian VM/LXC):"
            printf "  ${C_BOLD}3)${C_RESET} Harden Debian System ${C_DIM}(hardening.sh)${C_RESET}\n"
            printf "  ${C_BOLD}4)${C_RESET} Setup Jump Server    ${C_DIM}(jump.sh)${C_RESET}\n"
            printf "  ${C_BOLD}5)${C_RESET} Exit\n"
            echo
            ;;
    esac

    # Handle menu selection based on context
    while true; do
        case "$context" in
            pve-host)
                printf "%b" "${C_CYAN}Select option [1-3]:${C_RESET} "
                read -r choice
                case "$choice" in
                    1) run_script "pve" "debvm.sh"; break ;;
                    2) run_script "pve" "deblxc.sh"; break ;;
                    3) print_step "Exiting"; exit 0 ;;
                    *) print_error "Invalid choice. Please select 1, 2, or 3" ;;
                esac
                ;;
            vm|lxc)
                printf "%b" "${C_CYAN}Select option [1-3]:${C_RESET} "
                read -r choice
                case "$choice" in
                    1) run_script "server" "hardening.sh"; break ;;
                    2) run_script "server" "jump.sh"; break ;;
                    3) print_step "Exiting"; exit 0 ;;
                    *) print_error "Invalid choice. Please select 1, 2, or 3" ;;
                esac
                ;;
            *)
                printf "%b" "${C_CYAN}Select option [1-5]:${C_RESET} "
                read -r choice
                case "$choice" in
                    1) run_script "pve" "debvm.sh"; break ;;
                    2) run_script "pve" "deblxc.sh"; break ;;
                    3) run_script "server" "hardening.sh"; break ;;
                    4) run_script "server" "jump.sh"; break ;;
                    5) print_step "Exiting"; exit 0 ;;
                    *) print_error "Invalid choice. Please select 1, 2, 3, 4, or 5" ;;
                esac
                ;;
        esac
    done
}

#############################################################################
# Installation Summary                                                      #
#############################################################################

show_summary() {
    echo
    draw_separator
    echo

    print_section "Installation Summary"
    print_kv "Install Directory" "${INSTALL_DIR/$HOME/~}"
    print_kv "Version" "$SCRIPT_VERSION"
    print_kv "Log File" "${LOG_FILE/$HOME/~}"

    echo
    print_section "Directory Structure"
    echo "${C_DIM}${SYMBOL_BULLET} bootstrap.sh - This script (archived copy)${C_RESET}"
    echo "${C_DIM}${SYMBOL_BULLET} server/      - Server scripts (hardening, jump)${C_RESET}"
    echo "${C_DIM}${SYMBOL_BULLET} apps/        - Application installers${C_RESET}"
    echo "${C_DIM}${SYMBOL_BULLET} pve/         - Proxmox VE scripts${C_RESET}"
    echo "${C_DIM}${SYMBOL_BULLET} misc/        - Documentation (SKILL.md, README.md)${C_RESET}"

    echo
    print_info "Scripts are ready in: ${C_BOLD}${INSTALL_DIR/$HOME/~}${C_RESET}"
    echo
}

#############################################################################
# Main Function                                                             #
#############################################################################

main() {
    # Parse CLI arguments BEFORE setup (to handle --help early)
    local ACTION=""
    local DOWNLOAD_ONLY=false

    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "$SCRIPT_VERSION"
            exit 0
            ;;
        --download-only)
            DOWNLOAD_ONLY=true
            ;;
        --vm-template)
            ACTION="vm-template"
            ;;
        --lxc-template)
            ACTION="lxc-template"
            ;;
        --harden)
            ACTION="harden"
            ;;
        --jump)
            ACTION="jump"
            ;;
        "")
            # Interactive mode (default)
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Try '$0 --help' for usage information" >&2
            exit 1
            ;;
    esac

    # Setup logging (after CLI parsing)
    setup_logging

    # Clear screen if running interactively
    [[ -t 1 ]] && clear || true

    # Banner
    draw_box "Lab Bootstrap v${SCRIPT_VERSION}"
    printf "%*s${C_DIM}https://github.com/vdarkobar/lab${C_RESET}\n" 18 ""

    # Core bootstrap operations (always run these)
    preflight_checks
    create_directories
    download_components
    verify_checksums

    # Download-only mode
    if [[ "$DOWNLOAD_ONLY" == true ]]; then
        show_summary
        print_success "Download complete (--download-only mode)"
        log INFO "Download-only mode: exiting"
        exit 0
    fi

    # Execute action or show menu
    case "$ACTION" in
        vm-template)
            run_script "pve" "debvm.sh"
            ;;
        lxc-template)
            run_script "pve" "deblxc.sh"
            ;;
        harden)
            run_script "server" "hardening.sh"
            ;;
        jump)
            run_script "server" "jump.sh"
            ;;
        *)
            # Interactive menu
            show_summary
            show_contextual_menu
            ;;
    esac
}

# Run main with all arguments
main "$@"
