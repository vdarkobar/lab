#!/bin/bash

#############################################################################
# Checksum Generator for CHECKSUMS.txt                                     #
# Generates checksums for all .sh files and outputs in CHECKSUMS.txt format #
#                                                                            #
# USAGE:                                                                    #
#   ./update-checksums.sh              # Update CHECKSUMS.txt directly     #
#   ./update-checksums.sh --dry-run    # Preview changes without updating  #
#                                                                            #
#############################################################################

# Note: No set -e - we want to process all files even if one fails

#################################################################
# Load Formatting Library                                       #
#################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/lib/formatting.sh"
else
    echo "ERROR: Cannot find formatting library at $SCRIPT_DIR/lib/formatting.sh" >&2
    exit 1
fi

print_header "Checksum Generator for CHECKSUMS.txt"

# Check for dry-run mode
DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]] || [[ "${1:-}" == "-n" ]]; then
    DRY_RUN=true
    OUTPUT_FILE="CHECKSUMS.txt.preview"
    print_warning "Dry-run mode: Changes will be saved to CHECKSUMS.txt.preview"
else
    OUTPUT_FILE="CHECKSUMS.txt"
fi

SCRIPT_COUNT=0

# Start the file with header
cat > "$OUTPUT_FILE" << 'EOF'
# Lab Components Checksums
# Generated: $(date +%Y-%m-%d)
# Algorithm: SHA256
#
# Format: checksum  filepath
# 
# Verify with: sha256sum -c CHECKSUMS.txt

EOF

# Process lib directory
if [ -d "lib" ]; then
    print_subheader "Processing lib/"
    echo "# Libraries" >> "$OUTPUT_FILE"
    
    shopt -s nullglob
    for script in lib/*.sh; do
        if [ -f "$script" ]; then
            if sha256sum "$script" >> "$OUTPUT_FILE" 2>/dev/null; then
                CHECKSUM=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
                print_success "$script"
                print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
                ((SCRIPT_COUNT++))
            else
                print_warning "Skipped $script (checksum failed)"
            fi
        fi
    done
    shopt -u nullglob
    echo >> "$OUTPUT_FILE"
fi

# Process server directory
if [ -d "server" ]; then
    echo
    print_subheader "Processing server/"
    echo "# Server Scripts" >> "$OUTPUT_FILE"
    
    shopt -s nullglob  # Handle case where no .sh files exist
    for script in server/*.sh; do
        if [ -f "$script" ]; then
            if sha256sum "$script" >> "$OUTPUT_FILE" 2>/dev/null; then
                CHECKSUM=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
                print_success "$script"
                print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
                ((SCRIPT_COUNT++))
            else
                print_warning "Skipped $script (checksum failed)"
            fi
        fi
    done
    shopt -u nullglob
    echo >> "$OUTPUT_FILE"
fi

# Process pve directory
if [ -d "pve" ]; then
    echo
    print_subheader "Processing pve/"
    echo "# PVE Scripts" >> "$OUTPUT_FILE"
    
    shopt -s nullglob
    for script in pve/*.sh; do
        if [ -f "$script" ]; then
            if sha256sum "$script" >> "$OUTPUT_FILE" 2>/dev/null; then
                CHECKSUM=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
                print_success "$script"
                print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
                ((SCRIPT_COUNT++))
            else
                print_warning "Skipped $script (checksum failed)"
            fi
        fi
    done
    shopt -u nullglob
    echo >> "$OUTPUT_FILE"
fi

# Process apps directory
if [ -d "apps" ]; then
    echo
    print_subheader "Processing apps/"
    echo "# Application Scripts" >> "$OUTPUT_FILE"
    
    shopt -s nullglob
    for script in apps/*.sh; do
        if [ -f "$script" ]; then
            if sha256sum "$script" >> "$OUTPUT_FILE" 2>/dev/null; then
                CHECKSUM=$(sha256sum "$script" 2>/dev/null | awk '{print $1}')
                print_success "$script"
                print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
                ((SCRIPT_COUNT++))
            else
                print_warning "Skipped $script (checksum failed)"
            fi
        fi
    done
    shopt -u nullglob
    echo >> "$OUTPUT_FILE"
fi

# Process bootstrap.sh in root
if [ -f "bootstrap.sh" ]; then
    echo
    print_subheader "Processing bootstrap.sh"
    if sha256sum bootstrap.sh > bootstrap.sh.sha256 2>/dev/null; then
        CHECKSUM=$(cat bootstrap.sh.sha256 2>/dev/null | awk '{print $1}')
        print_success "bootstrap.sh"
        print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
        print_success "bootstrap.sh.sha256 (created)"
    else
        print_warning "Failed to create bootstrap.sh.sha256"
    fi
fi

echo
draw_separator
print_success "Generated checksums for $SCRIPT_COUNT script(s)"

if [[ "$DRY_RUN" == true ]]; then
    echo
    print_warning "Dry-run mode: No files were modified"
    echo
    print_info "Preview saved to: CHECKSUMS.txt.preview"
    echo "  ${C_CYAN}cat CHECKSUMS.txt.preview${C_RESET}"
    echo
    print_info "To apply changes, run without --dry-run:"
    echo "  ${C_CYAN}./update-checksums.sh${C_RESET}"
else
    echo
    print_success "CHECKSUMS.txt updated successfully"
    print_success "bootstrap.sh.sha256 updated successfully"
    echo
    print_info "Review changes with:"
    echo "  ${C_CYAN}git diff CHECKSUMS.txt${C_RESET}"
    echo
    print_info "Then commit:"
    echo "${C_CYAN}git add CHECKSUMS.txt bootstrap.sh.sha256 && \\${C_RESET}"
    echo "${C_CYAN}git commit -m 'Update checksums' && \\${C_RESET}"
    echo "${C_CYAN}git push${C_RESET}"
fi
draw_separator
