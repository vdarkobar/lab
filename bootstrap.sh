#!/bin/bash

#############################################################################
# Lab Bootstrap Script                                                      #
# Source: https://github.com/vdarkobar/lab                                 #
#                                                                            #
# This script:                                                              #
#   1. Creates directory structure (lib/, server/, apps/)                  #
#   2. Downloads all components from GitHub                                #
#   3. Verifies checksums for security                                     #
#   4. Runs hardening.sh                                                   #
#                                                                            #
# INSTALLATION METHODS:                                                     #
#                                                                            #
# Quick Install (convenient, medium security):                             #
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
#                                                                            #
# Secure Install (verified, high security - RECOMMENDED):                  #
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh
#   wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256
#   sha256sum -c bootstrap.sh.sha256                                       #
#   chmod +x bootstrap.sh                                                  #
#   ./bootstrap.sh                                                         #
#                                                                            #
# Full source code review:                                                  #
#   https://github.com/vdarkobar/lab/blob/main/bootstrap.sh               #
#############################################################################

set -euo pipefail

#################################################################
# Configuration                                                  #
#################################################################

readonly REPO_URL="https://raw.githubusercontent.com/vdarkobar/lab/main"
readonly INSTALL_DIR="$HOME/lab"
readonly VERSION="1.0.0"

# Simple colors (no dependencies)
readonly C_GREEN='\033[0;32m'
readonly C_RED='\033[0;31m'
readonly C_YELLOW='\033[0;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_RESET='\033[0m'

#################################################################
# Helper Functions                                               #
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

die() {
    print_error "$1"
    exit 1
}

#################################################################
# Create Directory Structure                                     #
#################################################################

create_directories() {
    print_header "Creating Directory Structure"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Directory $INSTALL_DIR already exists"
        echo -n "Remove and recreate? (yes/no): "
        read -r response
        if [[ "$response" == "yes" ]]; then
            rm -rf "$INSTALL_DIR"
            print_success "Removed existing directory"
        else
            die "Installation cancelled"
        fi
    fi
    
    mkdir -p "$INSTALL_DIR"/{lib,server,apps}
    print_success "Created: $INSTALL_DIR/lib"
    print_success "Created: $INSTALL_DIR/server"
    print_success "Created: $INSTALL_DIR/apps"
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
# Download and Verify Components                                 #
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
        "server/hardening.sh|Hardening Script"
        "pve/template.sh|VM Template Script"
    )
    
    # Download each file
    for file_entry in "${files[@]}"; do
        IFS='|' read -r file_path display_name <<< "$file_entry"
        
        print_step "Downloading $display_name..."
        if ! download_file "$REPO_URL/$file_path" "$file_path"; then
            die "Failed to download $file_path"
        fi
        
        local size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "unknown")
        print_success "Downloaded: $file_path (${size} bytes)"
    done
}

#################################################################
# Verify Checksums                                               #
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
    echo "1) Create Debian VM Template (runs on PVE host)"
    echo "2) Prepare Hardening Files (for Debian 13 VM/LXC)"
    echo "3) Exit"
    echo
    
    while true; do
        echo -n "Select option [1-3]: "
        read -r choice
        
        case "$choice" in
            1)
                run_template_creation
                break
                ;;
            2)
                prepare_hardening
                break
                ;;
            3)
                print_info "Exiting"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please select 1, 2, or 3"
                ;;
        esac
    done
}

#################################################################
# Run Template Creation (on PVE host)                          #
#################################################################

run_template_creation() {
    print_header "Creating Debian VM Template"
    
    # Check if running on Proxmox VE
    if [[ ! -f /etc/pve/.version ]]; then
        print_error "This option must run on Proxmox VE host"
        print_info "Detected environment: Not PVE"
        echo
        print_warning "To create templates, run bootstrap.sh on PVE host"
        exit 1
    fi
    
    print_success "Proxmox VE detected"
    
    cd "$INSTALL_DIR/pve" || die "Cannot change to pve directory"
    
    chmod +x template.sh
    
    echo
    print_step "Launching template.sh..."
    echo
    
    if ./template.sh; then
        echo
        print_success "Template creation completed!"
    else
        echo
        print_error "Template creation failed"
        exit 1
    fi
}

#################################################################
# Run Hardening (on Debian 13 VM/LXC)                          #
#################################################################

prepare_hardening() {
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
# Cleanup on Error                                               #
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
# Main Function                                                  #
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
