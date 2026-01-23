#!/bin/bash

#############################################################################
# Simple Checksum Generator                                                 #
# Generates SHA256 checksums for all .sh files in the repository           #
#############################################################################

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Checksum Generator${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# Find all .sh files in the repository
SCRIPT_COUNT=0

# Process all/apps directory
if [ -d "all/apps" ]; then
    echo -e "${GREEN}Processing all/apps/${NC}"
    cd all/apps
    
    for script in *.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" > "${script}.sha256"
            CHECKSUM=$(cat "${script}.sha256" | awk '{print $1}')
            echo "  ✓ $script"
            echo "    ${CHECKSUM:0:16}..."
            ((SCRIPT_COUNT++))
        fi
    done
    
    cd ../..
fi

# Process hardening directory
if [ -d "hardening" ]; then
    echo
    echo -e "${GREEN}Processing hardening/${NC}"
    cd hardening
    
    for script in *.sh; do
        if [ -f "$script" ]; then
            sha256sum "$script" > "${script}.sha256"
            CHECKSUM=$(cat "${script}.sha256" | awk '{print $1}')
            echo "  ✓ $script"
            echo "    ${CHECKSUM:0:16}..."
            ((SCRIPT_COUNT++))
        fi
    done
    
    cd ..
fi

# Process any .sh files in root
for script in *.sh; do
    if [ -f "$script" ] && [ "$script" != "update-checksums.sh" ]; then
        sha256sum "$script" > "${script}.sha256"
        CHECKSUM=$(cat "${script}.sha256" | awk '{print $1}')
        echo "  ✓ $script (root)"
        echo "    ${CHECKSUM:0:16}..."
        ((SCRIPT_COUNT++))
    fi
done

echo
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Generated checksums for $SCRIPT_COUNT script(s)${NC}"
echo
echo "Next steps:"
echo "  git add *.sha256 all/apps/*.sha256 hardening/*.sha256"
echo "  git commit -m 'Update checksums'"
echo "  git push"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
