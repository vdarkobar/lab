#!/bin/bash

#############################################################################
# Idempotent Helper Functions Library                                       #
# Atomic file operations, config management, and Debian repo helpers        #
#                                                                           #
# Usage: source "$(dirname "$0")/../lib/helpers.sh"                         #
#                                                                           #
# Return code convention:                                                   #
#   0 = success, action taken (file changed, line added, etc.)              #
#   1 = failure                                                             #
#   2 = success, no change needed (already correct)                         #
#                                                                           #
# Example caller pattern (set -e safe):                                     #
#   rc=0                                                                    #
#   write_file_if_changed /path 0644 <<'EOF' || rc=$?                       #
#   content                                                                 #
#   EOF                                                                     #
#   case $rc in                                                             #
#       0) echo "Changed"; systemctl restart foo ;;                         #
#       2) echo "Already correct" ;;                                        #
#       *) echo "Failed"; exit 1 ;;                                         #
#   esac                                                                    #
#############################################################################

#############################################################################
# File Operations                                                           #
#############################################################################

# write_file_if_changed <path> [mode]
#
# Reads content from stdin. Only writes if content differs from existing file.
# Creates parent directories if needed. Default mode: 0644
# Uses atomic write (temp file in same directory, then mv).
#
# Returns:
#   0 = file was changed
#   1 = failure
#   2 = no change needed
#
# Example:
#   write_file_if_changed /etc/sysctl.d/99-lab.conf 0644 <<'EOF'
#   net.ipv4.ip_forward = 0
#   EOF

write_file_if_changed() {
    local path="$1"
    local mode="${2:-0644}"
    local dir tmpfile

    dir="$(dirname "$path")"
    mkdir -p "$dir" || return 1

    # Temp file in same directory for atomic mv (same filesystem)
    tmpfile="$(mktemp "${dir}/.tmp.$(basename "$path").XXXXXX")" || return 1

    # Read stdin to temp file
    cat > "$tmpfile" || { rm -f "$tmpfile"; return 1; }

    # Compare with existing file
    if [[ -f "$path" ]] && cmp -s "$tmpfile" "$path"; then
        rm -f "$tmpfile"
        # Enforce mode even if content unchanged
        chmod "$mode" "$path" 2>/dev/null || true
        return 2  # No change needed
    fi

    # Atomic move (guaranteed same filesystem)
    mv "$tmpfile" "$path" || { rm -f "$tmpfile"; return 1; }
    chmod "$mode" "$path"
    chown root:root "$path" 2>/dev/null || true

    return 0  # Changed
}

#############################################################################
# Line/Key-Value Operations                                                 #
#############################################################################

# ensure_line <file> <line>
#
# Adds line if not present (exact match). Creates file if missing.
# Preserves existing content and order.
#
# Returns:
#   0 = line was added
#   1 = failure
#   2 = line already present
#
# Example:
#   ensure_line /etc/hosts "127.0.0.1 myhost"

ensure_line() {
    local file="$1"
    local line="$2"

    mkdir -p "$(dirname "$file")" || return 1
    [[ -f "$file" ]] || touch "$file" || return 1

    # Exact match with fixed string
    if grep -qxF -- "$line" "$file"; then
        return 2  # Already present
    fi

    echo "$line" >> "$file" || return 1
    return 0  # Added
}

# ensure_kv <file> <key> <value> [delimiter]
#
# Sets key to value. Replaces if key exists, appends if missing.
# Default delimiter: "=" (must be single character)
# Creates file if missing. Preserves comments and other lines.
# Uses awk for safe handling (no regex escaping issues).
#
# Returns:
#   0 = value was changed/added
#   1 = failure
#   2 = already set correctly
#
# Example:
#   ensure_kv /etc/foo.conf "PermitRootLogin" "no" " "

ensure_kv() {
    local file="$1"
    local key="$2"
    local value="$3"
    local delim="${4:-=}"
    local tmpfile current_value

    # Delimiter must be single character (awk -F treats multi-char as regex)
    if [[ ${#delim} -ne 1 ]]; then
        echo "ERROR: ensure_kv delimiter must be single character" >&2
        return 1
    fi

    mkdir -p "$(dirname "$file")" || return 1
    [[ -f "$file" ]] || touch "$file" || return 1

    # Check current value using awk (no regex escaping issues)
    # Trim leading whitespace from value for comparison
    current_value="$(awk -F "$delim" -v k="$key" '$1 == k {gsub(/^[ \t]+/, "", $2); print $2; exit}' "$file")"

    if [[ "$current_value" == "$value" ]]; then
        return 2  # Already correct
    fi

    # Create temp in same dir for atomicity
    tmpfile="$(mktemp "$(dirname "$file")/.tmp.$(basename "$file").XXXXXX")" || return 1

    # Replace or append using awk (handles keys with special chars safely)
    awk -F "$delim" -v k="$key" -v v="$value" -v d="$delim" '
        BEGIN { found=0 }
        $1 == k { print k d v; found=1; next }
        { print }
        END { if (!found) print k d v }
    ' "$file" > "$tmpfile" || { rm -f "$tmpfile"; return 1; }

    mv "$tmpfile" "$file" || { rm -f "$tmpfile"; return 1; }
    return 0  # Changed
}

#############################################################################
# Debian Repository Codename Helpers                                        #
#############################################################################

# get_supported_codename <repo_type>
#
# Returns a codename known to be supported by the specified repository.
# External repos (Docker, OpenResty, etc.) often lag new Debian releases.
# This function falls back to the last known-good codename with a warning.
#
# Override with environment variables:
#   DOCKER_DIST, NODESOURCE_DIST, OPENRESTY_DIST
#
# repo_type: docker | nodesource | openresty
#
# Returns: codename string (always succeeds, falls back to bookworm)
#
# Example:
#   CODENAME="$(get_supported_codename docker)"

get_supported_codename() {
    local repo_type="$1"
    local detected override_var override_val os_id

    # Detect current codename from os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        detected="${VERSION_CODENAME:-}"
        os_id="${ID:-}"
    fi

    # Fallback to lsb_release if os-release didn't have codename
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "unknown")"
    [[ -z "$os_id" ]] && os_id="unknown"

    # Warn if not Debian (repos may not be compatible)
    if [[ "$os_id" != "debian" ]]; then
        echo "WARNING: Not Debian (detected: $os_id), repo compatibility uncertain" >&2
    fi

    # Check for environment variable override
    case "$repo_type" in
        docker)     override_var="DOCKER_DIST" ;;
        nodesource) override_var="NODESOURCE_DIST" ;;
        openresty)  override_var="OPENRESTY_DIST" ;;
        *)          override_var="" ;;
    esac

    if [[ -n "$override_var" ]]; then
        override_val="${!override_var:-}"
        if [[ -n "$override_val" ]]; then
            echo "$override_val"
            return 0
        fi
    fi

    # Return detected if supported, otherwise fallback to last known-good
    case "$repo_type" in
        docker)
            case "$detected" in
                bookworm|bullseye)
                    echo "$detected"
                    ;;
                *)
                    echo "WARNING: '$detected' may not be in Docker repo, using bookworm" >&2
                    echo "WARNING: Override with DOCKER_DIST=<codename>" >&2
                    echo "bookworm"
                    ;;
            esac
            ;;
        nodesource)
            # NodeSource uses "nodistro" for current Debian versions
            echo "nodistro"
            ;;
        openresty)
            case "$detected" in
                bookworm|bullseye)
                    echo "$detected"
                    ;;
                *)
                    echo "WARNING: '$detected' may not be in OpenResty repo, using bookworm" >&2
                    echo "WARNING: Override with OPENRESTY_DIST=<codename>" >&2
                    echo "bookworm"
                    ;;
            esac
            ;;
        *)
            # Unknown repo type - return detected with warning
            echo "WARNING: Unknown repo type '$repo_type', returning detected codename '$detected'" >&2
            echo "$detected"
            ;;
    esac
}

#############################################################################
# SSH Configuration Helpers                                                 #
#############################################################################

# ensure_sshd_include
#
# Ensures /etc/ssh/sshd_config has Include directive for drop-in configs.
# Required for drop-in files in /etc/ssh/sshd_config.d/ to be read.
# Only modifies vendor config if Include is missing.
#
# Returns:
#   0 = Include was added
#   1 = failure
#   2 = Include already present

ensure_sshd_include() {
    local main_config="/etc/ssh/sshd_config"
    local include_line="Include /etc/ssh/sshd_config.d/*.conf"
    local tmpfile

    # Check if Include directive already exists
    if grep -qE '^[[:space:]]*Include.*/etc/ssh/sshd_config\.d/' "$main_config" 2>/dev/null; then
        return 2  # Already present
    fi

    echo "WARNING: Adding Include directive to $main_config" >&2

    # Portable prepend: create new file with Include + original content
    tmpfile="${main_config}.labtmp"
    { printf '%s\n' "$include_line"; cat "$main_config"; } > "$tmpfile" || return 1
    mv "$tmpfile" "$main_config" || { rm -f "$tmpfile"; return 1; }

    return 0
}

# reload_sshd
#
# Reloads SSH service (portable across Debian/others where service name varies).
# Verifies service is active after reload.
#
# Returns:
#   0 = reload successful, service running
#   1 = failure

reload_sshd() {
    local svc

    # Determine service name (ssh on Debian, sshd elsewhere)
    if systemctl list-unit-files ssh.service &>/dev/null; then
        svc="ssh"
    elif systemctl list-unit-files sshd.service &>/dev/null; then
        svc="sshd"
    else
        echo "ERROR: Cannot find ssh or sshd service" >&2
        return 1
    fi

    if ! systemctl reload "$svc"; then
        echo "ERROR: Failed to reload $svc" >&2
        return 1
    fi

    sleep 1

    if systemctl is-active --quiet "$svc"; then
        echo "SSH service reloaded and running"
        return 0
    else
        echo "ERROR: $svc not active after reload" >&2
        return 1
    fi
}

# apply_ssh_hardening
#
# Applies SSH hardening via drop-in config with validation and rollback.
# Creates /etc/ssh/sshd_config.d/99-lab-hardening.conf
# Validates full config chain before reload. Rolls back on failure.
#
# Returns:
#   0 = success (applied or already correct)
#   1 = failure (rolled back)

apply_ssh_hardening() {
    local config_file="/etc/ssh/sshd_config.d/99-lab-hardening.conf"
    local backup="/tmp/sshd_lab_backup_$$"
    local rc=0

    # Backup current state (if exists)
    [[ -f "$config_file" ]] && cp "$config_file" "$backup"

    # Ensure Include directive exists (non-fatal warning if fails)
    ensure_sshd_include || true

    # Write our hardening config
    write_file_if_changed "$config_file" 0644 <<'EOF' || rc=$?
# Managed by lab/hardening.sh - do not edit manually
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
EOF

    # If unchanged, done (success)
    [[ $rc -eq 2 ]] && { rm -f "$backup"; return 0; }

    # If write failed, abort
    [[ $rc -ne 0 ]] && { rm -f "$backup"; return 1; }

    # Validate full config chain
    if ! sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
        echo "ERROR: SSH config validation failed, rolling back" >&2
        if [[ -f "$backup" ]]; then
            mv "$backup" "$config_file"
        else
            rm -f "$config_file"
        fi
        # Reload after rollback to restore previous state
        reload_sshd || true
        return 1
    fi

    # Reload service
    if ! reload_sshd; then
        echo "ERROR: SSH reload failed, rolling back" >&2
        if [[ -f "$backup" ]]; then
            mv "$backup" "$config_file"
        else
            rm -f "$config_file"
        fi
        # Reload after rollback
        reload_sshd || true
        return 1
    fi

    rm -f "$backup"
    return 0
}

#############################################################################
# fail2ban Configuration Helper                                             #
#############################################################################

# apply_fail2ban_config
#
# Applies fail2ban jail config via drop-in.
# Creates /etc/fail2ban/jail.d/99-lab.conf
# Does not touch jail.local or other user files.
# Only restarts service if config changed AND service exists.
#
# Returns:
#   0 = success (applied or already correct)
#   1 = failure

apply_fail2ban_config() {
    local config_file="/etc/fail2ban/jail.d/99-lab.conf"
    local rc=0

    write_file_if_changed "$config_file" 0644 <<'EOF' || rc=$?
# Managed by lab/hardening.sh - do not edit manually
# User customizations belong in jail.local or other jail.d/ files

[sshd]
enabled = true
maxretry = 3
bantime = 1h
findtime = 10m
EOF

    case $rc in
        0)
            # Changed - restart if service exists
            if systemctl list-unit-files fail2ban.service &>/dev/null; then
                systemctl restart fail2ban
            fi
            return 0
            ;;
        2)
            # No change needed
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

#############################################################################
# sysctl Configuration Helper                                               #
#############################################################################

# apply_sysctl_hardening
#
# Applies sysctl hardening via drop-in.
# Creates /etc/sysctl.d/99-lab-hardening.conf
# Reloads sysctl if config changed.
#
# Returns:
#   0 = success (applied or already correct)
#   1 = failure

apply_sysctl_hardening() {
    local rc=0

    write_file_if_changed /etc/sysctl.d/99-lab-hardening.conf 0644 <<'EOF' || rc=$?
# Managed by lab/hardening.sh - do not edit manually
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
EOF

    case $rc in
        0)
            # Changed - reload sysctl
            sysctl --system >/dev/null
            return 0
            ;;
        2)
            # No change needed
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

#############################################################################
# Export Functions                                                          #
#############################################################################

export -f write_file_if_changed
export -f ensure_line
export -f ensure_kv
export -f get_supported_codename
export -f ensure_sshd_include
export -f reload_sshd
export -f apply_ssh_hardening
export -f apply_fail2ban_config
export -f apply_sysctl_hardening
