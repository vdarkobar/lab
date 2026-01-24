#!/bin/bash

#############################################################################
# Checksum Generator for CHECKSUMS.txt                                     #
# Generates checksums for all .sh files and outputs in CHECKSUMS.txt format #
#############################################################################

set -e

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

OUTPUT_FILE="CHECKSUMS.txt.new"

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

SCRIPT_COUNT=0

# Process lib directory
if [ -d "lib" ]; then
    print_subheader "Processing lib/"
    echo "# Libraries" >> "$OUTPUT_FILE"
    
    for script in lib/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            print_success "$script"
            print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process server directory
if [ -d "server" ]; then
    echo
    print_subheader "Processing server/"
    echo "# Server Scripts" >> "$OUTPUT_FILE"
    
    for script in server/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            print_success "$script"
            print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process apps directory
if [ -d "apps" ]; then
    echo
    print_subheader "Processing apps/"
    echo "# Application Scripts" >> "$OUTPUT_FILE"
    
    for script in apps/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            print_success "$script"
            print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process bootstrap.sh in root
if [ -f "bootstrap.sh" ]; then
    echo
    print_subheader "Processing bootstrap.sh"
    sha256sum bootstrap.sh > bootstrap.sh.sha256
    CHECKSUM=$(cat bootstrap.sh.sha256 | awk '{print $1}')
    print_success "bootstrap.sh"
    print_subheader "  ${C_DIM}${CHECKSUM:0:16}...${C_RESET}"
    print_success "bootstrap.sh.sha256 (created)"
fi

echo
draw_separator
print_success "Generated checksums for $SCRIPT_COUNT script(s)"
echo
print_warning "Review the generated file:"
echo "  ${C_CYAN}cat $OUTPUT_FILE${C_RESET}"
echo
print_warning "If it looks good, replace CHECKSUMS.txt:"
echo "  ${C_CYAN}mv $OUTPUT_FILE CHECKSUMS.txt${C_RESET}"
echo
print_warning "Then commit:"
echo "  ${C_CYAN}git add CHECKSUMS.txt bootstrap.sh.sha256${C_RESET}"
echo "  ${C_CYAN}git commit -m 'Update checksums'${C_RESET}"
echo "  ${C_CYAN}git push${C_RESET}"
draw_separator
