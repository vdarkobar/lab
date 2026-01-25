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
# Run Hardening Script                                           #
#################################################################

run_hardening() {
    print_header "Starting Server Hardening"
    
    cd "$INSTALL_DIR/server" || die "Cannot change to server directory"
    
    chmod +x hardening.sh
    
    echo
    print_step "Launching hardening.sh..."
    echo
    
    if ./hardening.sh; then
        echo
        print_success "Setup completed successfully!"
    else
        echo
        print_error "Hardening script failed"
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
    run_hardening
    
    echo
    print_success "Installation directory: $INSTALL_DIR"
    echo
}

# Run main
main "$@"
