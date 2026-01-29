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
# Quick Install (convenient, medium security):                              #
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
#                                                                           #
# Secure Install (verified, high security - RECOMMENDED):                   #
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256
#   sha256sum -c bootstrap.sh.sha256                                        #
#   chmod +x bootstrap.sh                                                   #
#   ./bootstrap.sh                                                          #
#                                                                           #
# Full source code review:                                                  #
#   https://github.com/vdarkobar/lab/blob/main/bootstrap.sh                 #
#############################################################################

set -euo pipefail

#################################################################
# Configuration                                                 #
#################################################################

readonly REPO_URL="https://raw.githubusercontent.com/vdarkobar/lab/main"
readonly INSTALL_DIR="$HOME/lab"
readonly VERSION="1.1.0"

# Simple colors (no dependencies)
readonly C_GREEN='\033[0;32m'
readonly C_RED='\033[0;31m'
readonly C_YELLOW='\033[0;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_RESET='\033[0m'

#################################################################
# Helper Functions                                              #
#################################################################

print_header() {
    echo
    echo -e "${C_CYAN}━━━ $1 ━━━${C_RESET}"
}

print_success() {
    echo -e "${C_GREEN}✓${C_RESET} $1"
}

print_error() {
    echo -e "${C_RED}✗${C_RESET} $1" >&2
}

print_warning() {
    echo -e "${C_YELLOW}⚠${C_RESET} $1"
}

print_step() {
    echo -e "${C_BLUE}→${C_RESET} $1"
}

print_info() {
    echo -e "${C_BLUE}ℹ${C_RESET} $1"
}

die() {
    print_error "$1"
    exit 1
}

#################################################################
# Create Directory Structure                                    #
#################################################################

create_directories() {
    print_header "Creating Directory Structure"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Directory $INSTALL_DIR already exists"
        echo -n "Remove and recreate? (yes/no): "
        read -r response
        if [[ "$response" =~ ^[Yy](es)?$ ]]; then
            rm -rf "$INSTALL_DIR"
            print_success "Removed existing directory"
        else
            die "Installation cancelled"
        fi
    fi
    
    mkdir -p "$INSTALL_DIR"/{lib,server,apps,pve}
    print_success "Created: $INSTALL_DIR/lib"
    print_success "Created: $INSTALL_DIR/server"
    print_success "Created: $INSTALL_DIR/apps"
    print_success "Created: $INSTALL_DIR/pve"
}

#################################################################
# Download File with Retry                                       #
#################################################################

download_file() {
    local url="$1"
    local output="$2"
    local retries=3
    
    for ((i=1; i<=retries; i++)); do
        if wget -q --show-progress "$url" -O "$output" 2>/dev/null || curl -fsSL "$url" -o "$output" 2>/dev/null; then
            return 0
        fi
        
        if [[ $i -lt $retries ]]; then
            print_warning "Download failed, retrying ($i/$retries)..."
            sleep 2
        fi
    done
    
    return 1
}

#################################################################
# Download and Verify Components                                #
#################################################################

download_components() {
    print_header "Downloading Components"
    
    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"
    
    # Download master checksums file
    print_step "Downloading checksums manifest..."
    if ! download_file "$REPO_URL/CHECKSUMS.txt" "CHECKSUMS.txt"; then
        die "Failed to download CHECKSUMS.txt"
    fi
    print_success "Downloaded: CHECKSUMS.txt"
    
    # List of files to download: path|display_name
    local files=(
        "lib/formatting.sh|Formatting Library"
        "lib/helpers.sh|Helper Functions Library"
        "server/hardening.sh|Hardening Script"
        "server/jump.sh|Jump Server Script"
        "pve/debvm.sh|Debian VM Template Script"
        "pve/deblxc.sh|Debian LXC Template Script"
        "apps/docker.sh|Docker Installer"
        "apps/npm.sh|Nginx Proxy Manager Installer"
        "apps/unbound.sh|Unbound DNS Installer"
        "apps/samba.sh|Samba File Server Installer"
        "apps/bookstack.sh|Bookstack Wiki Installer"
    )
    
    # Download each file
    for file_entry in "${files[@]}"; do
        IFS='|' read -r file_path display_name <<< "$file_entry"
        
        print_step "Downloading $display_name..."
        if ! download_file "$REPO_URL/$file_path" "$file_path"; then
            print_warning "Optional file not available: $file_path (skipped)"
            continue
        fi
        
        local size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "unknown")
        print_success "Downloaded: $file_path (${size} bytes)"
    done
}

#################################################################
# Verify Checksums                                              #
#################################################################

verify_checksums() {
    print_header "Verifying Checksums"
    
    cd "$INSTALL_DIR" || die "Cannot change to $INSTALL_DIR"
    
    # Verify each downloaded file
    local verification_failed=false
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        
        # Parse checksum line: "hash  filename"
        local expected_hash=$(echo "$line" | awk '{print $1}')
        local file_path=$(echo "$line" | awk '{print $2}')
        
        # Skip if file doesn't exist (optional files)
        [[ ! -f "$file_path" ]] && continue
        
        print_step "Verifying $file_path..."
        
        local actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
        
        if [[ "$actual_hash" == "$expected_hash" ]]; then
            print_success "$file_path: OK"
        else
            print_error "$file_path: FAILED"
            print_error "  Expected: ${expected_hash:0:16}..."
            print_error "  Got:      ${actual_hash:0:16}..."
            verification_failed=true
        fi
    done < CHECKSUMS.txt
    
    if [[ "$verification_failed" == true ]]; then
        die "Checksum verification failed! Installation aborted."
    fi
    
    print_success "All checksums verified"
}

#################################################################
# Show Menu and Execute Choice                                  #
#################################################################

show_menu() {
    print_header "What would you like to do?"
    
    echo
    echo "1) Create Debian VM Template (debvm.sh - runs on PVE host)"
    echo "2) Create Debian LXC Template (deblxc.sh - runs on PVE host)"
    echo "3) Harden Debian System (hardening.sh - runs in VM/LXC)"
    echo "4) Setup Jump Server (jump.sh - runs in VM/LXC)"
    echo "5) Exit"
    echo
    
    while true; do
        echo -n "Select option [1-5]: "
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

#################################################################
# Run VM Template Creation (on PVE host)                        #
#################################################################

run_vm_template_creation() {
    print_header "Creating Debian VM Template"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        print_error "This option must run on Proxmox VE host"
        print_step "Detected environment: Not PVE"
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

#################################################################
# Run LXC Template Creation (on PVE host)                       #
#################################################################

run_lxc_template_creation() {
    print_header "Creating Debian LXC Template"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        print_error "This option must run on Proxmox VE host"
        print_step "Detected environment: Not PVE"
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
        echo "  https://github.com/vdarkobar/lab"
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

#################################################################
# Run Hardening (on Debian 13 VM/LXC)                           #
#################################################################

run_hardening() {
    print_header "Server Hardening"
    
    # Check if running on Debian
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This option must run on Debian system"
        print_info "Detected: Not Debian"
        exit 1
    fi
    
    # Check Debian version
    local debian_version=$(cat /etc/debian_version)
    if [[ ! "$debian_version" =~ ^13 ]]; then
        print_warning "Expected Debian 13, found version: $debian_version"
        echo -n "Continue anyway? (yes/no): "
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
        echo "  ${C_CYAN}apt update && apt install sudo${C_RESET}"
        echo
        print_info "Then add your user to sudo group:"
        echo "  ${C_CYAN}usermod -aG sudo username${C_RESET}"
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
        echo "  ${C_CYAN}adduser username${C_RESET}"
        echo "  ${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run as that user:"
        echo "  ${C_CYAN}su - username${C_RESET}"
        echo "  ${C_CYAN}cd ~/lab/server && ./hardening.sh${C_RESET}"
        exit 1
    fi
    
    print_success "Running as non-root user: $(whoami)"
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

#################################################################
# Run Jump Server Setup (on Debian 13 VM/LXC)                   #
#################################################################

run_jump_server() {
    print_header "Jump Server Setup"
    
    # Check if running on Debian
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This option must run on Debian system"
        print_info "Detected: Not Debian"
        exit 1
    fi
    
    # Check Debian version
    local debian_version=$(cat /etc/debian_version)
    if [[ ! "$debian_version" =~ ^13 ]]; then
        print_warning "Expected Debian 13, found version: $debian_version"
        echo -n "Continue anyway? (yes/no): "
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
        echo "  ${C_CYAN}apt update && apt install sudo${C_RESET}"
        echo
        print_info "Then add your user to sudo group:"
        echo "  ${C_CYAN}usermod -aG sudo username${C_RESET}"
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
        echo "  ${C_CYAN}adduser username${C_RESET}"
        echo "  ${C_CYAN}usermod -aG sudo username${C_RESET}"
        echo
        print_info "Then run as that user:"
        echo "  ${C_CYAN}su - username${C_RESET}"
        echo "  ${C_CYAN}cd ~/lab/server && ./jump.sh${C_RESET}"
        exit 1
    fi
    
    print_success "Running as non-root user: $(whoami)"
    print_success "sudo is available"
    
    # Run jump server setup
    cd "$INSTALL_DIR/server" || die "Cannot change to server directory"
    
    # Check if jump.sh exists
    if [[ ! -f "jump.sh" ]]; then
        print_error "jump.sh not found"
        print_warning "Jump Server script not yet available"
        echo
        print_step "Check repository for updates:"
        echo "  https://github.com/vdarkobar/lab"
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

#################################################################
# Cleanup on Error                                              #
#################################################################

cleanup() {
    if [[ $? -ne 0 ]]; then
        print_error "Installation failed"
        if [[ -d "$INSTALL_DIR" ]]; then
            print_warning "Partial installation at: $INSTALL_DIR"
            print_warning "You may want to remove it: rm -rf $INSTALL_DIR"
        fi
    fi
}

trap cleanup EXIT

#################################################################
# Main Function                                                 #
#################################################################

main() {
    echo
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║                  Lab Bootstrap v${VERSION}                     ║${C_RESET}"
    echo -e "${C_CYAN}║          https://github.com/vdarkobar/lab                 ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════╝${C_RESET}"
    
    # Check for required tools
    if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
        die "Either wget or curl is required"
    fi
    
    if ! command -v sha256sum >/dev/null 2>&1; then
        die "sha256sum is required"
    fi
    
    # Run installation steps
    create_directories
    download_components
    verify_checksums
    
    # Show menu for what to do next
    show_menu
    
    echo
    print_success "Installation directory: $INSTALL_DIR"
    echo
}

# Run main
main "$@"
