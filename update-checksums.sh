#!/bin/bash
set -euo pipefail

# Minimal checksum generator - no formatting, just commands
# Usage: ./update-checksums-minimal.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKSUMS_FILE="$SCRIPT_DIR/CHECKSUMS.txt"
BOOTSTRAP_CHECKSUM="$SCRIPT_DIR/bootstrap.sh.sha256"

# Check sha256sum exists
command -v sha256sum >/dev/null || { echo "sha256sum not found" >&2; exit 1; }

# Generate CHECKSUMS.txt
cat > "$CHECKSUMS_FILE" << EOF
# Lab Components Checksums
# Generated: $(date +%Y-%m-%d)
# Algorithm: SHA256
#
# Format: checksum  filepath
#
# Verify with: sha256sum -c CHECKSUMS.txt

EOF

# Process bootstrap.sh
if [[ -f "$SCRIPT_DIR/bootstrap.sh" ]]; then
    echo "# Bootstrap Script" >> "$CHECKSUMS_FILE"
    sha256sum "$SCRIPT_DIR/bootstrap.sh" | sed "s|$SCRIPT_DIR/||" >> "$CHECKSUMS_FILE"
    echo >> "$CHECKSUMS_FILE"
fi

# Process directories
for dir in server pve apps; do
    dir_path="$SCRIPT_DIR/$dir"
    [[ ! -d "$dir_path" ]] && continue
    
    case "$dir" in
        server) echo "# Server Scripts" >> "$CHECKSUMS_FILE" ;;
        pve)    echo "# PVE Scripts" >> "$CHECKSUMS_FILE" ;;
        apps)   echo "# Application Scripts" >> "$CHECKSUMS_FILE" ;;
    esac
    
    for script in "$dir_path"/*.sh; do
        [[ -f "$script" ]] && sha256sum "$script" | sed "s|$SCRIPT_DIR/||" >> "$CHECKSUMS_FILE"
    done
    
    echo >> "$CHECKSUMS_FILE"
done

# Generate bootstrap.sh.sha256
if [[ -f "$SCRIPT_DIR/bootstrap.sh" ]]; then
    sha256sum "$SCRIPT_DIR/bootstrap.sh" | sed "s|$SCRIPT_DIR/||" > "$BOOTSTRAP_CHECKSUM"
fi

echo "Done. Generated:"
echo "  $CHECKSUMS_FILE"
[[ -f "$BOOTSTRAP_CHECKSUM" ]] && echo "  $BOOTSTRAP_CHECKSUM"

echo
echo "To commit changes:"
echo "  git add CHECKSUMS.txt bootstrap.sh.sha256 && \\"
echo "  git commit -m 'Update checksums' && \\"
echo "  git push"
