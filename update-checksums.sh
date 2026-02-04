#!/bin/bash

#############################################################################
# Checksum Generator for Lab Repository                                     #
# Generates SHA256 checksums for all .sh files in CHECKSUMS.txt format     #
#############################################################################

readonly SCRIPT_VERSION="2.0.0"

# Handle --help flag early (before any setup)
case "${1:-}" in
    --help|-h)
        echo "Checksum Generator v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help|--dry-run|--verify]"
        echo
        echo "Options:"
        echo "  --help, -h       Show this help message"
        echo "  --dry-run, -n    Preview changes without updating files"
        echo
        echo "Requirements:"
        echo "  - Must be run from lab repository root directory"
        echo "  - sha256sum must be available"
        echo
        echo "What it does:"
        echo "  - Scans lib/, server/, pve/, apps/ directories"
        echo "  - Generates SHA256 checksums for all .sh files"
        echo "  - Creates/updates CHECKSUMS.txt"
        echo "  - Creates/updates bootstrap.sh.sha256"
        echo
        echo "Directory structure expected:"
        echo "  lib/        Library scripts"
        echo "  server/     Server deployment scripts"
        echo "  pve/        Proxmox VE scripts"
        echo "  apps/       Application installation scripts"
        echo "  bootstrap.sh  Entry point script"
        echo
        echo "Files created/updated:"
        echo "  CHECKSUMS.txt         All script checksums"
        echo "  bootstrap.sh.sha256   Bootstrap-only checksum"
        echo
        echo "Examples:"
        echo "  # Update checksums"
        echo "  ./update-checksums.sh"
        echo
        echo "  # Preview without changes"
        echo "  ./update-checksums.sh --dry-run"
        echo
        echo "  # Verify current checksums"
        echo "  ./update-checksums.sh --verify"
        echo
        echo "Post-update workflow:"
        echo "  git diff CHECKSUMS.txt"
        echo "  git add CHECKSUMS.txt bootstrap.sh.sha256"
        echo "  git commit -m 'Update checksums'"
        echo "  git push"
        echo
        echo "Additional options:"
        echo "  --verify, -c     Verify existing checksums against files"
        echo "  --version, -v    Show version information"
        exit 0
        ;;
esac

#############################################################################
#                                                                           #
# DESCRIPTION:                                                              #
#   Generates and maintains SHA256 checksums for all shell scripts in the  #
#   lab repository. Supports verification and dry-run modes for CI/CD.     #
#                                                                           #
# LOCATION: lab/update-checksums.sh                                         #
# REPOSITORY: https://github.com/vdarkobar/lab                              #
#                                                                           #
# EXECUTION REQUIREMENTS:                                                   #
#   - Run from repository root directory                                    #
#   - No special privileges required                                        #
#                                                                           #
# USAGE:                                                                    #
#   ./update-checksums.sh              # Update CHECKSUMS.txt               #
#   ./update-checksums.sh --dry-run    # Preview changes                    #
#   ./update-checksums.sh --verify     # Verify existing checksums          #
#                                                                           #
# VERSION: 2.0.0                                                            #
# LICENSE: MIT                                                              #
#                                                                           #
#############################################################################

# Note: No set -e - we want to process all files even if one fails
set -uo pipefail

#############################################################################
# Terminal Formatting (embedded - no external dependency)                   #
#############################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    # Colors
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    # Foreground colors
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
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
    printf "${C_CYAN}%-18s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$key:" "$value"
}

#############################################################################
# Visual Elements                                                           #
#############################################################################

draw_box() {
    local text="$1"
    local width=68
    local padding=$(( (width - ${#text} - 2) / 2 ))
    
    echo "${C_CYAN}"
    echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
    printf "║%*s%s%*s║\n" $padding "" "$text" $padding ""
    echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
    echo "${C_RESET}"
}

draw_separator() {
    echo "${C_DIM}$(printf '─%.0s' $(seq 1 70))${C_RESET}"
}

#############################################################################
# Error Handling                                                            #
#############################################################################

die() {
    print_error "$@"
    exit 1
}

#############################################################################
# Script Configuration                                                      #
#############################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Directories to scan (relative to script location)
readonly SCAN_DIRS=("lib" "server" "pve" "apps")

# Output files
readonly CHECKSUMS_FILE="CHECKSUMS.txt"
readonly BOOTSTRAP_CHECKSUM="bootstrap.sh.sha256"

#############################################################################
# Helper Functions                                                          #
#############################################################################

command_exists() {
    command -v "$1" &>/dev/null
}

# Get short checksum for display
short_checksum() {
    local checksum="$1"
    echo "${checksum:0:16}..."
}

# Count files in a directory matching pattern
count_files() {
    local dir="$1"
    local pattern="${2:-*.sh}"
    
    if [[ -d "$dir" ]]; then
        find "$dir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | wc -l
    else
        echo 0
    fi
}

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # Check sha256sum is available
    if ! command_exists sha256sum; then
        die "sha256sum not found. Please install coreutils."
    fi
    print_success "sha256sum available"
    
    # Check we're in a valid repository structure
    local found_dirs=0
    for dir in "${SCAN_DIRS[@]}"; do
        if [[ -d "$SCRIPT_DIR/$dir" ]]; then
            ((found_dirs++))
        fi
    done
    
    if [[ $found_dirs -eq 0 ]]; then
        die "No script directories found. Run from lab repository root."
    fi
    print_success "Repository structure validated ($found_dirs directories found)"
    
    # Show what we found
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(count_files "$SCRIPT_DIR/$dir" "*.sh")
        if [[ $count -gt 0 ]]; then
            print_subheader "$dir/: $count scripts"
        fi
    done
    
    if [[ -f "$SCRIPT_DIR/bootstrap.sh" ]]; then
        print_subheader "bootstrap.sh: present"
    fi
}

#############################################################################
# Generate Checksums                                                        #
#############################################################################

generate_checksums() {
    local output_file="$1"
    local script_count=0
    local failed_count=0
    
    # Write header
    cat > "$output_file" << EOF
# Lab Components Checksums
# Generated: $(date +%Y-%m-%d)
# Algorithm: SHA256
#
# Format: checksum  filepath
# 
# Verify with: sha256sum -c CHECKSUMS.txt

EOF
    
    # Process each directory
    for dir in "${SCAN_DIRS[@]}"; do
        local dir_path="$SCRIPT_DIR/$dir"
        
        if [[ ! -d "$dir_path" ]]; then
            continue
        fi
        
        # Get section name from directory
        local section_name
        case "$dir" in
            lib)    section_name="Libraries" ;;
            server) section_name="Server Scripts" ;;
            pve)    section_name="PVE Scripts" ;;
            apps)   section_name="Application Scripts" ;;
            *)      section_name="$dir" ;;
        esac
        
        print_header "Processing $dir/"
        echo "# $section_name" >> "$output_file"
        
        # Process scripts in directory
        shopt -s nullglob
        local dir_count=0
        for script in "$dir_path"/*.sh; do
            if [[ -f "$script" ]]; then
                local relative_path="${script#$SCRIPT_DIR/}"
                
                if sha256sum "$script" 2>/dev/null | sed "s|$SCRIPT_DIR/||" >> "$output_file"; then
                    local checksum
                    checksum=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
                    print_success "$relative_path"
                    echo "  ${C_DIM}$(short_checksum "$checksum")${C_RESET}"
                    ((script_count++))
                    ((dir_count++))
                else
                    print_warning "Failed: $relative_path"
                    ((failed_count++))
                fi
            fi
        done
        shopt -u nullglob
        
        if [[ $dir_count -eq 0 ]]; then
            print_info "No scripts found in $dir/"
        fi
        
        echo >> "$output_file"
    done
    
    # Return counts via global variables (bash doesn't support multiple returns)
    TOTAL_SCRIPTS=$script_count
    FAILED_SCRIPTS=$failed_count
}

#############################################################################
# Generate Bootstrap Checksum                                               #
#############################################################################

generate_bootstrap_checksum() {
    local bootstrap_path="$SCRIPT_DIR/bootstrap.sh"
    local checksum_file="$SCRIPT_DIR/$BOOTSTRAP_CHECKSUM"
    
    if [[ ! -f "$bootstrap_path" ]]; then
        print_warning "bootstrap.sh not found, skipping dedicated checksum"
        return 1
    fi
    
    print_header "Processing bootstrap.sh"
    
    if sha256sum "$bootstrap_path" 2>/dev/null | sed "s|$SCRIPT_DIR/||" > "$checksum_file"; then
        local checksum
        checksum=$(awk '{print $1}' "$checksum_file")
        print_success "bootstrap.sh"
        echo "  ${C_DIM}$(short_checksum "$checksum")${C_RESET}"
        print_success "$BOOTSTRAP_CHECKSUM created"
        return 0
    else
        print_error "Failed to generate bootstrap checksum"
        return 1
    fi
}

#############################################################################
# Verify Checksums                                                          #
#############################################################################

verify_checksums() {
    local checksums_path="$SCRIPT_DIR/$CHECKSUMS_FILE"
    
    if [[ ! -f "$checksums_path" ]]; then
        die "CHECKSUMS.txt not found. Run without --verify first."
    fi
    
    print_header "Verifying Checksums"
    
    local pass_count=0
    local fail_count=0
    local skip_count=0
    
    # Change to script directory for relative paths
    cd "$SCRIPT_DIR"
    
    # Read and verify each checksum
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "${line// }" ]] && continue
        
        local checksum filepath
        checksum=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | awk '{print $2}')
        
        if [[ ! -f "$filepath" ]]; then
            print_warning "Missing: $filepath"
            ((skip_count++))
            continue
        fi
        
        local current_checksum
        current_checksum=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
        
        if [[ "$checksum" == "$current_checksum" ]]; then
            print_success "$filepath"
            ((pass_count++))
        else
            print_error "MISMATCH: $filepath"
            echo "  ${C_DIM}Expected: $(short_checksum "$checksum")${C_RESET}"
            echo "  ${C_DIM}Got:      $(short_checksum "$current_checksum")${C_RESET}"
            ((fail_count++))
        fi
    done < "$checksums_path"
    
    # Summary
    echo
    draw_separator
    print_kv "Passed" "$pass_count"
    print_kv "Failed" "$fail_count"
    print_kv "Missing" "$skip_count"
    draw_separator
    
    if [[ $fail_count -gt 0 ]]; then
        echo
        print_error "Checksum verification FAILED"
        print_info "Run ./update-checksums.sh to regenerate checksums"
        return 1
    elif [[ $skip_count -gt 0 ]]; then
        echo
        print_warning "Verification passed with missing files"
        return 0
    else
        echo
        print_success "All checksums verified successfully"
        return 0
    fi
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    local mode="$1"
    local output_file="$2"
    
    echo
    draw_separator
    print_kv "Scripts processed" "$TOTAL_SCRIPTS"
    
    if [[ $FAILED_SCRIPTS -gt 0 ]]; then
        print_kv "Failed" "$FAILED_SCRIPTS"
    fi
    draw_separator
    
    if [[ "$mode" == "dry-run" ]]; then
        echo
        print_warning "Dry-run mode: No files were modified"
        echo
        print_info "Preview saved to: ${C_CYAN}$output_file${C_RESET}"
        echo
        print_info "To apply changes, run without --dry-run:"
        echo "  ${C_CYAN}./update-checksums.sh${C_RESET}"
    else
        echo
        print_success "CHECKSUMS.txt updated successfully"
        if [[ -f "$SCRIPT_DIR/$BOOTSTRAP_CHECKSUM" ]]; then
            print_success "$BOOTSTRAP_CHECKSUM updated successfully"
        fi
        echo
        print_info "Review changes:"
        echo "  ${C_CYAN}git diff $CHECKSUMS_FILE${C_RESET}"
        echo
        print_info "Commit workflow:"
        echo "${C_CYAN}git add $CHECKSUMS_FILE $BOOTSTRAP_CHECKSUM$ && \\${C_RESET}"
        echo "${C_CYAN}git commit -m 'Update checksums' && \\${C_RESET}"
        echo "${C_CYAN}git push${C_RESET}"
    fi
    draw_separator
}

#############################################################################
# Show Introduction                                                         #
#############################################################################

show_intro() {
    local mode="$1"
    
    clear
    draw_box "Checksum Generator v${SCRIPT_VERSION}"
    
    echo
    print_kv "Working directory" "$SCRIPT_DIR"
    print_kv "Mode" "$mode"
    print_kv "Output" "$CHECKSUMS_FILE"
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    local mode="update"
    local output_file="$SCRIPT_DIR/$CHECKSUMS_FILE"
    
    # Parse arguments
    case "${1:-}" in
        --dry-run|-n)
            mode="dry-run"
            output_file="$SCRIPT_DIR/CHECKSUMS.txt.preview"
            ;;
        --verify|-c)
            mode="verify"
            ;;
        --version|-v)
            echo "update-checksums.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
        "")
            # Default: update mode
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
    
    # Handle verify mode separately
    if [[ "$mode" == "verify" ]]; then
        show_intro "verify"
        verify_checksums
        exit $?
    fi
    
    # Show introduction
    show_intro "$mode"
    
    # Pre-flight checks
    preflight_checks
    
    # Generate checksums
    generate_checksums "$output_file"
    
    # Generate bootstrap checksum (only in update mode)
    if [[ "$mode" == "update" ]]; then
        generate_bootstrap_checksum || true
    fi
    
    # Show summary
    show_summary "$mode" "$output_file"
}

# Run main function
main "$@"
