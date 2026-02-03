#!/bin/bash

#############################################################################
# Lab Bootstrap Script                                                      #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# This script:                                                              #
#   1. Creates directory structure (lib/, server/, apps/)                   #
#   2. Downloads all components from GitHub                                 #
#   3. Verifies checksums for security                                      #
#   4. Runs hardening.sh                                                    #
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

readonly SCRIPT_VERSION="1.1.0"

# Handle --help flag early (before any setup)
case "${1:-}" in
    --help|-h)
        echo "Lab Bootstrap Script v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation methods:"
        echo "  Quick:  bash -c \"\$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)\""
        echo "  Secure: Download, verify checksum, then run"
        echo
        echo "What it does:"
        echo "  - Creates directory structure: ~/lab/{lib,server,apps,pve}"
        echo "  - Downloads all components from GitHub"
        echo "  - Verifies SHA256 checksums for security"
        echo "  - Presents menu to run setup scripts"
        echo
        echo "Menu options:"
        echo "  1) Create Debian VM Template  - runs on PVE host"
        echo "  2) Create Debian LXC Template - runs on PVE host"
        echo "  3) Harden Debian System       - runs in VM/LXC"
        echo "  4) Setup Jump Server          - runs in VM/LXC"
        echo
        echo "Requirements:"
        echo "  - wget or curl for downloads"
        echo "  - sha256sum for verification"
        echo "  - Internet connectivity"
        echo
        echo "Repository: https://github.com/vdarkobar/lab"
        exit 0
        ;;
esac

#############################################################################
# Script Configuration                                                      #
#############################################################################

set -euo pipefail

readonly REPO_URL="https://raw.githubusercontent.com/vdarkobar/lab/main"
readonly INSTALL_DIR="$HOME/lab"

#############################################################################
# Terminal Formatting                                                       #
#############################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    # Colors
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    # Foreground colors
    readonly C_BLACK=$(tput setaf 0)
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_MAGENTA=$(tput setaf 5)
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
    readonly C_BLACK=""
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
    echo "${C_DIM}$(printf '─%.0s' $(seq 1 70))${C_RESET}"
}

#############################################################################
# Logging                                                                   #
#############################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    
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
    print_error "$@"
    exit 1
}

# Error trap for better debugging
trap 'print_error "Error on line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Create Directory Structure                                                #
#############################################################################

create_directories() {
    print_header "Creating Directory Structure"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Directory $INSTALL_DIR already exists"
        echo
        printf "%b" "${C_CYAN}Remove and recreate?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
        read -r response
        if [[ "$response" =~ ^[Yy](es)?$ ]]; then
            rm -rf "$INSTALL_DIR"
            print_success "Removed existing directory"
        else
            die "Installation cancelled"
        fi
    fi
    
    local directories=(
        "$INSTALL_DIR/lib"
        "$INSTALL_DIR/server"
        "$INSTALL_DIR/apps"
        "$INSTALL_DIR/pve"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        print_success "Created: ${dir/$HOME/~}"
    done
    
    echo
}

#############################################################################
# Download File with Retry                                                  #
#############################################################################

download_file() {
    local url="$1"
    local output="$2"
    local retries=3
    
    for ((i=1; i<=retries; i++)); do
        if wget -q --show-progress "$url" -O "$output" 2>/dev/null || \
           curl -fsSL "$url" -o "$output" 2>/dev/null; then
            return 0
        fi
        
        if [[ $i -lt $retries ]]; then
            print_warning "Download failed, retrying ($i/$retries)..."
            sleep 2
        fi
    done
    
    return 1
}

#############################################################################
# Download and Verify Components                                            #
#############################################################################

download_components() {
    print_header "Downloading Components"
    
    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"
    
    # Download master checksums file
    print_step "Downloading checksums manifest..."
    if ! download_file "$REPO_URL/CHECKSUMS.txt" "CHECKSUMS.txt"; then
        die "Failed to download CHECKSUMS.txt"
    fi
    print_success "Downloaded: CHECKSUMS.txt"
    
    echo
    
    # List of files to download: path|display_name
    local files=(
        "lib/formatting.sh|Formatting Library"
        "lib/helpers.sh|Helper Functions Library"
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
        "apps/bentopdf.sh|BentoPDF editor Installer"
    )
    
    # Download each file
    for file_entry in "${files[@]}"; do
        IFS='|' read -r file_path display_name <<< "$file_entry"
        
        print_step "Downloading $display_name..."
        if ! download_file "$REPO_URL/$file_path" "$file_path"; then
            print_warning "Optional file not available: $file_path (skipped)"
            continue
        fi
        
        local size
        size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "unknown")
        print_subheader "Downloaded: $file_path (${size} bytes)"
    done
    
    echo
}

#############################################################################
# Verify Checksums                                                          #
#############################################################################

verify_checksums() {
    print_header "Verifying Checksums"
    
    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"
    
    local verification_failed=false
    local verified_count=0
    local skipped_count=0
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        
        # Parse checksum line: "hash  filename"
        local expected_hash
        local file_path
        expected_hash=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')
        
        # Skip if file doesn't exist (optional files)
        if [[ ! -f "$file_path" ]]; then
            ((skipped_count++)) || true
            continue
        fi
        
        print_step "Verifying $file_path..."
        
        local actual_hash
        actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
        
        if [[ "$actual_hash" == "$expected_hash" ]]; then
            print_subheader "$file_path: OK"
            ((verified_count++)) || true
        else
            print_error "$file_path: FAILED"
            print_subheader "Expected: ${expected_hash:0:16}..."
            print_subheader "Got:      ${actual_hash:0:16}..."
            verification_failed=true
        fi
    done < CHECKSUMS.txt
    
    echo
    
    if [[ "$verification_failed" == true ]]; then
        die "Checksum verification failed! Installation aborted."
    fi
    
    print_success "All checksums verified"
    print_kv "Files verified" "$verified_count"
    print_kv "Files skipped" "$skipped_count"
    
    echo
}

#############################################################################
# Show Menu and Execute Choice                                              #
#############################################################################

show_menu() {
    print_header "What would you like to do?"
    
    echo
    printf "  ${C_BOLD}1)${C_RESET} Create Debian VM Template  ${C_DIM}(debvm.sh - runs on PVE host)${C_RESET}\n"
    printf "  ${C_BOLD}2)${C_RESET} Create Debian LXC Template ${C_DIM}(deblxc.sh - runs on PVE host)${C_RESET}\n"
    printf "  ${C_BOLD}3)${C_RESET} Harden Debian System       ${C_DIM}(hardening.sh - runs in VM/LXC)${C_RESET}\n"
    printf "  ${C_BOLD}4)${C_RESET} Setup Jump Server          ${C_DIM}(jump.sh - runs in VM/LXC)${C_RESET}\n"
    printf "  ${C_BOLD}5)${C_RESET} Exit\n"
    echo
    
    while true; do
        printf "%b" "${C_CYAN}Select option [1-5]:${C_RESET} "
        read -r choice
        
        case "$choice" in
            1)
                run_vm_template_creation
                break
                ;;
            2)
                run_lxc_template_creation
                break
                ;;
            3)
                run_hardening
                break
                ;;
            4)
                run_jump_server
                break
                ;;
            5)
                print_step "Exiting"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please select 1, 2, 3, 4, or 5"
                ;;
        esac
    done
}

#############################################################################
# Run VM Template Creation (on PVE host)                                    #
#############################################################################

run_vm_template_creation() {
    print_header "Creating Debian VM Template"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        print_error "This option must run on Proxmox VE host"
        print_kv "Detected" "Not PVE"
        echo
        print_warning "To create templates, run bootstrap.sh on PVE host"
        exit 1
    fi
    
    print_success "Proxmox VE detected"
    
    cd "$INSTALL_DIR/pve" || die "Cannot change to pve directory"
    
    chmod +x debvm.sh
    
    echo
    print_step "Launching debvm.sh..."
    echo
    
    if ./debvm.sh; then
        echo
        print_success "VM template creation completed!"
    else
        echo
        print_error "VM template creation failed"
        exit 1
    fi
}

#############################################################################
# Run LXC Template Creation (on PVE host)                                   #
#############################################################################

run_lxc_template_creation() {
    print_header "Creating Debian LXC Template"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        print_error "This option must run on Proxmox VE host"
        print_kv "Detected" "Not PVE"
        echo
        print_warning "To create templates, run bootstrap.sh on PVE host"
        exit 1
    fi
    
    print_success "Proxmox VE detected"
    
    cd "$INSTALL_DIR/pve" || die "Cannot change to pve directory"
    
    # Check if deblxc.sh exists
    if [[ ! -f "deblxc.sh" ]]; then
        print_error "deblxc.sh not found"
        print_warning "LXC template creation not yet available"
        echo
        print_step "Check repository for updates:"
        printf "  %b\n" "${C_CYAN}https://github.com/vdarkobar/lab${C_RESET}"
        exit 1
    fi
    
    chmod +x deblxc.sh
    
    echo
    print_step "Launching deblxc.sh..."
    echo
    
    if ./deblxc.sh; then
        echo
        print_success "LXC template creation completed!"
    else
        echo
        print_error "LXC template creation failed"
        exit 1
    fi
}

#############################################################################
# Run Hardening (on Debian 13 VM/LXC)                                       #
#############################################################################

run_hardening() {
    print_header "Server Hardening"
    
    # Check if running on Debian
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This option must run on Debian system"
        print_kv "Detected" "Not Debian"
        exit 1
    fi
    
    # Check Debian version
    local debian_version
    debian_version=$(cat /etc/debian_version)
    if [[ ! "$debian_version" =~ ^13 ]]; then
        print_warning "Expected Debian 13, found version: $debian_version"
        printf "%b" "${C_CYAN}Continue anyway?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
        read -r response
        if [[ "$response" != "yes" ]]; then
            die "Hardening cancelled"
        fi
    else
        print_success "Debian 13 detected"
    fi
    
    # Check for sudo (required - must run as non-root user with sudo)
    if ! command -v sudo >/dev/null 2>&1; then
        print_error "sudo is not installed"
        print_error "Hardening script requires sudo"
        echo
        print_info "Install sudo first (as root):"
        printf "  %b\n" "${C_CYAN}apt update && apt install sudo${C_RESET}"
        echo
        print_info "Then add your user to sudo group:"
        printf "  %b\n" "${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run hardening.sh as that non-root user"
        exit 1
    fi
    
    # Check if running as root (should not be)
    if [[ $EUID -eq 0 ]]; then
        print_error "Do not run hardening as root!"
        print_error "Hardening must run as non-root user with sudo privileges"
        echo
        print_info "Create a user first (as root):"
        printf "  %b\n" "${C_CYAN}adduser username${C_RESET}"
        printf "  %b\n" "${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run as that user:"
        printf "  %b\n" "${C_CYAN}su - username${C_RESET}"
        printf "  %b\n" "${C_CYAN}cd ~/lab/server && ./hardening.sh${C_RESET}"
        exit 1
    fi
    
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    print_success "sudo is available"
    
    # Run hardening
    cd "$INSTALL_DIR/server" || die "Cannot change to server directory"
    
    chmod +x hardening.sh
    
    echo
    print_step "Launching hardening.sh..."
    echo
    
    if ./hardening.sh; then
        echo
        print_success "Hardening completed!"
    else
        echo
        print_error "Hardening failed"
        exit 1
    fi
}

#############################################################################
# Run Jump Server Setup (on Debian 13 VM/LXC)                               #
#############################################################################

run_jump_server() {
    print_header "Jump Server Setup"
    
    # Check if running on Debian
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This option must run on Debian system"
        print_kv "Detected" "Not Debian"
        exit 1
    fi
    
    # Check Debian version
    local debian_version
    debian_version=$(cat /etc/debian_version)
    if [[ ! "$debian_version" =~ ^13 ]]; then
        print_warning "Expected Debian 13, found version: $debian_version"
        printf "%b" "${C_CYAN}Continue anyway?${C_RESET} ${C_DIM}(yes/no)${C_RESET} "
        read -r response
        if [[ "$response" != "yes" ]]; then
            die "Jump Server setup cancelled"
        fi
    else
        print_success "Debian 13 detected"
    fi
    
    # Check for sudo (required - must run as non-root user with sudo)
    if ! command -v sudo >/dev/null 2>&1; then
        print_error "sudo is not installed"
        print_error "Jump Server script requires sudo"
        echo
        print_info "Install sudo first (as root):"
        printf "  %b\n" "${C_CYAN}apt update && apt install sudo${C_RESET}"
        echo
        print_info "Then add your user to sudo group:"
        printf "  %b\n" "${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run jump.sh as that non-root user"
        exit 1
    fi
    
    # Check if running as root (should not be)
    if [[ $EUID -eq 0 ]]; then
        print_error "Do not run as root!"
        print_error "Jump Server must run as non-root user with sudo privileges"
        echo
        print_info "Create a user first (as root):"
        printf "  %b\n" "${C_CYAN}adduser username${C_RESET}"
        printf "  %b\n" "${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run as that user:"
        printf "  %b\n" "${C_CYAN}su - username${C_RESET}"
        printf "  %b\n" "${C_CYAN}cd ~/lab/server && ./jump.sh${C_RESET}"
        exit 1
    fi
    
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    print_success "sudo is available"
    
    # Run jump server setup
    cd "$INSTALL_DIR/server" || die "Cannot change to server directory"
    
    # Check if jump.sh exists
    if [[ ! -f "jump.sh" ]]; then
        print_error "jump.sh not found"
        print_warning "Jump Server script not yet available"
        echo
        print_step "Check repository for updates:"
        printf "  %b\n" "${C_CYAN}https://github.com/vdarkobar/lab${C_RESET}"
        exit 1
    fi
    
    chmod +x jump.sh
    
    echo
    print_step "Launching jump.sh..."
    echo
    
    if ./jump.sh; then
        echo
        print_success "Jump Server setup completed!"
    else
        echo
        print_error "Jump Server setup failed"
        exit 1
    fi
}

#############################################################################
# Cleanup on Error                                                          #
#############################################################################

cleanup() {
    local exit_code=$?
    # Remove error trap to avoid recursion
    trap - ERR
    
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Installation failed"
        if [[ -d "$INSTALL_DIR" ]]; then
            print_warning "Partial installation at: $INSTALL_DIR"
            print_info "You may want to remove it:"
            printf "  %b\n" "${C_CYAN}rm -rf $INSTALL_DIR${C_RESET}"
        fi
    fi
}

trap cleanup EXIT

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # Check for required tools
    if command -v wget >/dev/null 2>&1; then
        print_success "wget is available"
    elif command -v curl >/dev/null 2>&1; then
        print_success "curl is available"
    else
        die "Either wget or curl is required"
    fi
    
    if command -v sha256sum >/dev/null 2>&1; then
        print_success "sha256sum is available"
    else
        die "sha256sum is required"
    fi
    
    echo
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    echo
    draw_separator
    echo
    
    print_header "Installation Summary"
    print_kv "Install Directory" "${INSTALL_DIR/$HOME/~}"
    print_kv "Version" "$SCRIPT_VERSION"
    
    echo
    print_header "Directory Structure"
    print_subheader "lib/     - Shared libraries"
    print_subheader "server/  - Server scripts (hardening, jump)"
    print_subheader "apps/    - Application installers"
    print_subheader "pve/     - Proxmox VE scripts"
    
    echo
}

#############################################################################
# Main Function                                                             #
#############################################################################

main() {
    # Clear screen if running directly (not piped)
    [[ -t 1 ]] && clear || true
    
    draw_box "Lab Bootstrap v${SCRIPT_VERSION}"
    printf "%*s${C_DIM}https://github.com/vdarkobar/lab${C_RESET}\n" 18 ""
    
    # Run installation steps
    preflight_checks
    create_directories
    download_components
    verify_checksums
    show_summary
    
    # Show menu for what to do next
    show_menu
}

# Run main
main "$@"
