#!/bin/bash

#############################################################################
# Checksum Generator for CHECKSUMS.txt                                     #
# Generates checksums for all .sh files and outputs in CHECKSUMS.txt format #
#############################################################################

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Checksum Generator for CHECKSUMS.txt${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

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
    echo -e "${GREEN}Processing lib/${NC}"
    echo "# Libraries" >> "$OUTPUT_FILE"
    
    for script in lib/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            echo "  ✓ $script"
            echo "    ${CHECKSUM:0:16}..."
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process server directory
if [ -d "server" ]; then
    echo
    echo -e "${GREEN}Processing server/${NC}"
    echo "# Server Scripts" >> "$OUTPUT_FILE"
    
    for script in server/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            echo "  ✓ $script"
            echo "    ${CHECKSUM:0:16}..."
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process apps directory
if [ -d "apps" ]; then
    echo
    echo -e "${GREEN}Processing apps/${NC}"
    echo "# Application Scripts" >> "$OUTPUT_FILE"
    
    for script in apps/*.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" >> "$OUTPUT_FILE"
            CHECKSUM=$(sha256sum "$script" | awk '{print $1}')
            echo "  ✓ $script"
            echo "    ${CHECKSUM:0:16}..."
            ((SCRIPT_COUNT++))
        fi
    done
    echo >> "$OUTPUT_FILE"
fi

# Process bootstrap.sh in root
if [ -f "bootstrap.sh" ]; then
    echo
    echo -e "${GREEN}Processing bootstrap.sh${NC}"
    sha256sum bootstrap.sh > bootstrap.sh.sha256
    CHECKSUM=$(cat bootstrap.sh.sha256 | awk '{print $1}')
    echo "  ✓ bootstrap.sh"
    echo "    ${CHECKSUM:0:16}..."
    echo "  ✓ bootstrap.sh.sha256 (created)"
fi

echo
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Generated checksums for $SCRIPT_COUNT script(s)${NC}"
echo
echo -e "${YELLOW}Review the generated file:${NC}"
echo "  cat $OUTPUT_FILE"
echo
echo -e "${YELLOW}If it looks good, replace CHECKSUMS.txt:${NC}"
echo "  mv $OUTPUT_FILE CHECKSUMS.txt"
echo
echo -e "${YELLOW}Then commit:${NC}"
echo "  git add CHECKSUMS.txt bootstrap.sh.sha256"
echo "  git commit -m 'Update checksums'"
echo "  git push"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
