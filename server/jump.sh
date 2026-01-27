#!/bin/bash

#############################################################################
# Bastion Host / Jump Server Setup                                          #
# Hardens a Debian server for secure SSH access with 2FA                    #
#############################################################################

readonly SCRIPT_VERSION="2.1.0"

# Handle --help flag early (before sourcing libraries)
case "${1:-}" in
    --help|-h)
        echo "Bastion Host / Jump Server Setup v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Jump Server\""
        echo "  Or run directly: ./jump.sh"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Clean Debian 13 VM or LXC container"
        echo "  - Internet connection"
        echo
        echo "What it does:"
        echo "  - Installs security packages (fail2ban, ufw, etc.)"
        echo "  - Configures SSH with 2FA (Google Authenticator)"
        echo "  - Sets up UFW firewall (SSH on port 22)"
        echo "  - Hardens sysctl settings (LXC-safe)"
        echo "  - Generates Ed25519 SSH key pair"
        echo "  - Locks root account"
        echo
        echo "Environment variables:"
        echo "  SKIP_2FA=true       Skip Google Authenticator setup"
        echo "  SKIP_KEYGEN=true    Skip SSH key generation"
        echo "  SKIP_REBOOT=true    Skip reboot prompt"
        echo
        echo "Files created:"
        echo "  /var/log/lab/jump-*.log                   Installation log"
        echo "  ~/.ssh/id_ed25519                         SSH private key"
        echo "  ~/.ssh/id_ed25519.pub                     SSH public key"
        echo "  /etc/ssh/sshd_config.d/99-lab-bastion.conf    SSH hardening"
        echo "  /etc/sysctl.d/99-lab-bastion.conf             Sysctl hardening"
        echo "  /etc/fail2ban/jail.d/99-lab-bastion.conf      Fail2Ban config"
        echo
        echo "Post-install:"
        echo "  SSH: ssh user@host -p 22"
        echo "  Jump: ssh -J user@bastion:22 user@remote_host"
        exit 0
        ;;
esac

#############################################################################
# Configuration                                                             #
#############################################################################

set -euo pipefail

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source formatting library
if [[ -f "${SCRIPT_DIR}/../lib/formatting.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/formatting.sh"
elif [[ -f "${SCRIPT_DIR}/lib/formatting.sh" ]]; then
    source "${SCRIPT_DIR}/lib/formatting.sh"
else
    # Fallback: minimal formatting if library not found
    print_success() { echo "✓ $*"; }
    print_error() { echo "✗ $*" >&2; }
    print_warning() { echo "⚠ $*"; }
    print_info() { echo "ℹ $*"; }
    print_step() { echo "→ $*"; }
    print_header() { echo -e "\n━━━ $* ━━━"; }
    print_kv() { printf "%-20s %s\n" "$1:" "$2"; }
    draw_box() { echo -e "\n╔══════════════════════════════════════════════════════════════╗\n║  $*\n╚══════════════════════════════════════════════════════════════╝"; }
    draw_separator() { echo "──────────────────────────────────────────────────────────────"; }
    log() { local level="$1"; shift; echo "[$level] $*"; }
    die() { echo "ERROR: $*" >&2; exit 1; }
fi

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/jump-$(date +%Y%m%d-%H%M%S).log"

# Network info (populated by detect_network_info)
HOSTNAME=""
DOMAIN_LOCAL=""
LOCAL_IP=""

# Environment
export DEBIAN_FRONTEND=noninteractive

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # Must NOT run as root
    if [[ ${EUID} -eq 0 ]]; then
        echo
        print_error "This script must NOT be run as root!"
        echo
        print_info "Correct usage:"
        echo "  ./$(basename "$0")"
        echo
        print_info "The script will use sudo internally when needed."
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: $(whoami)"
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access, run as root:"
        echo "  usermod -aG sudo $(whoami)"
        echo "  # Then logout and login again"
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on PVE host"
    
    # Check Debian
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian. Detected: $ID"
        else
            print_success "Debian system detected: $VERSION"
        fi
    fi
    
    # Check internet connectivity
    print_step "Testing internet connectivity..."
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 5 --head https://www.google.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified"
        else
            die "No internet connectivity detected"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=5 --spider https://www.google.com 2>/dev/null; then
            print_success "Internet connectivity verified"
        else
            die "No internet connectivity detected"
        fi
    else
        print_warning "Cannot verify internet (curl/wget not available yet)"
    fi
    
    echo
}

#############################################################################
# Network Detection                                                         #
#############################################################################

detect_network_info() {
    print_header "Network Detection"
    
    # Get hostname
    HOSTNAME=$(hostname -s)
    print_success "Hostname: $HOSTNAME"
    
    # Extract domain from /etc/resolv.conf
    DOMAIN_LOCAL=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)
    if [[ -z "$DOMAIN_LOCAL" ]]; then
        DOMAIN_LOCAL=$(awk -F' ' '/^search/ {print $2; exit}' /etc/resolv.conf)
    fi
    
    if [[ -n "$DOMAIN_LOCAL" ]]; then
        print_success "Domain: $DOMAIN_LOCAL"
    else
        print_warning "Domain not found in /etc/resolv.conf"
        DOMAIN_LOCAL="local"
    fi
    
    # Get IP address
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$LOCAL_IP" ]]; then
        LOCAL_IP=$(ip addr show | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}' | grep -v '127.0.0.1' | head -n1)
    fi
    
    if [[ -n "$LOCAL_IP" ]]; then
        print_success "IP Address: $LOCAL_IP"
    else
        print_warning "Could not determine IP address"
    fi
    
    echo
}

#############################################################################
# Package Installation                                                      #
#############################################################################

install_packages() {
    print_header "Installing Packages"
    
    local packages=(
        ufw
        gnupg2
        fail2ban
        libpam-tmpdir
        qemu-guest-agent
        unattended-upgrades
        libpam-google-authenticator
    )
    
    local need_install=false
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            need_install=true
            break
        fi
    done
    
    if [[ "$need_install" == true ]]; then
        print_step "Updating package index..."
        sudo apt-get update -qq
        
        print_step "Installing packages..."
        sudo apt-get install -y "${packages[@]}"
        print_success "All packages installed"
    else
        print_success "All required packages already installed"
    fi
    
    echo
}

#############################################################################
# Configure /etc/hosts                                                      #
#############################################################################

configure_hosts() {
    print_header "Configuring /etc/hosts"
    
    local new_line="${LOCAL_IP} ${HOSTNAME} ${HOSTNAME}.${DOMAIN_LOCAL}"
    
    # Check if already configured
    if grep -qF "$new_line" /etc/hosts 2>/dev/null; then
        print_success "Hosts file already configured"
        return 0
    fi
    
    # Backup
    sudo cp /etc/hosts /etc/hosts.bak
    
    # Create new hosts file
    {
        echo "$new_line"
        grep -v "$HOSTNAME" /etc/hosts || true
    } | sudo tee /etc/hosts.tmp >/dev/null
    
    sudo mv /etc/hosts.tmp /etc/hosts
    print_success "Updated /etc/hosts"
    
    echo
}

#############################################################################
# Unattended Upgrades                                                       #
#############################################################################

configure_unattended_upgrades() {
    print_header "Configuring Unattended Upgrades"
    
    # Enable unattended-upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades
    
    local filepath="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    if [[ ! -f "$filepath" ]]; then
        print_warning "Config file not found: $filepath"
        return 0
    fi
    
    # Enable automatic cleanup and reboot
    sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' "$filepath"
    sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' "$filepath"
    sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' "$filepath"
    sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' "$filepath"
    sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' "$filepath"
    
    print_success "Unattended upgrades configured"
    echo
}

#############################################################################
# UFW Firewall                                                              #
#############################################################################

configure_ufw() {
    print_header "Configuring UFW Firewall"
    
    # Limit SSH
    print_step "Configuring SSH rate limiting..."
    sudo ufw limit 22/tcp comment "SSH" >/dev/null 2>&1 || true
    
    # Set defaults
    print_step "Setting default policies..."
    sudo ufw default deny incoming >/dev/null 2>&1
    sudo ufw default allow outgoing >/dev/null 2>&1
    
    # Enable UFW
    print_step "Enabling UFW..."
    sudo ufw --force enable >/dev/null 2>&1
    
    # Reload
    sudo ufw reload >/dev/null 2>&1
    
    print_success "UFW configured and enabled"
    echo
}

#############################################################################
# Fail2Ban                                                                  #
#############################################################################

configure_fail2ban() {
    print_header "Configuring Fail2Ban"
    
    if ! command -v fail2ban-server >/dev/null 2>&1; then
        print_warning "Fail2Ban not installed, skipping"
        return 0
    fi
    
    # Use drop-in config instead of editing jail.local
    # This survives package upgrades and is fully idempotent
    local dropin_dir="/etc/fail2ban/jail.d"
    local dropin_file="${dropin_dir}/99-lab-bastion.conf"
    
    print_step "Creating Fail2Ban drop-in configuration..."
    sudo mkdir -p "$dropin_dir"
    
    # Write drop-in config (overwrites if exists - idempotent)
    sudo tee "$dropin_file" > /dev/null << 'EOF'
# Managed by lab/jump.sh - do not edit manually
# Bastion host Fail2Ban settings

[DEFAULT]
# Use systemd backend (fixes Debian bug with auto backend)
backend = systemd

# Stricter limits: 3 attempts, 15 minute ban
bantime = 15m
maxretry = 3
findtime = 10m

[sshd]
enabled = true
EOF

    print_success "Fail2Ban drop-in config created: $dropin_file"
    
    # Enable and restart fail2ban
    sudo systemctl enable fail2ban >/dev/null 2>&1
    sudo systemctl restart fail2ban >/dev/null 2>&1
    
    print_success "Fail2Ban configured"
    echo
}

#############################################################################
# Secure Shared Memory                                                      #
#############################################################################

secure_shared_memory() {
    print_header "Securing Shared Memory"
    
    local line="none /run/shm tmpfs defaults,ro 0 0"
    
    if grep -qF "$line" /etc/fstab 2>/dev/null; then
        print_success "Shared memory already secured"
        return 0
    fi
    
    echo "$line" | sudo tee -a /etc/fstab >/dev/null
    print_success "Added tmpfs mount for /run/shm"
    
    echo
}

#############################################################################
# Sysctl Hardening (LXC-safe)                                               #
#############################################################################

configure_sysctl() {
    print_header "Configuring Sysctl (LXC-safe)"
    
    local dropin="/etc/sysctl.d/99-lab-bastion.conf"
    
    print_step "Creating sysctl drop-in configuration..."
    
    # Write drop-in config (overwrites if exists - idempotent)
    sudo tee "$dropin" >/dev/null <<'EOF'
# Managed by lab/jump.sh - do not edit manually
# Bastion hardening sysctl settings (LXC-safe)

# Reverse path filtering
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
EOF
    
    print_success "Sysctl drop-in config created: $dropin"
    
    # Apply (may fail in unprivileged LXC)
    print_step "Applying sysctl settings..."
    if sudo sysctl -p "$dropin" >/dev/null 2>&1; then
        print_success "Sysctl settings applied"
    else
        print_warning "Some sysctl keys denied (normal in unprivileged LXC)"
        # Suppress errors, || true prevents pipefail exit
        sudo sysctl -p "$dropin" 2>/dev/null || true
    fi
    
    echo
}

#############################################################################
# Lock Root Account                                                         #
#############################################################################

lock_root_account() {
    print_header "Locking Root Account"
    
    if sudo passwd -S root | grep -q ' L '; then
        print_success "Root account already locked"
    else
        sudo passwd -l root >/dev/null 2>&1
        print_success "Root account locked"
    fi
    
    echo
}

#############################################################################
# Configure PAM for 2FA                                                     #
#############################################################################

configure_pam_2fa() {
    print_header "Configuring PAM for 2FA"
    
    local pam_sshd="/etc/pam.d/sshd"
    local ga_line="auth required pam_google_authenticator.so nullok"
    
    # Comment out common-auth to prevent password prompt without 2FA
    if grep -q "^@include common-auth" "$pam_sshd"; then
        sudo sed -i 's|^@include common-auth|#@include common-auth|g' "$pam_sshd"
        print_success "Disabled password-only auth in PAM"
    fi
    
    # Add Google Authenticator PAM module
    if ! grep -qF "$ga_line" "$pam_sshd"; then
        echo "$ga_line" | sudo tee -a "$pam_sshd" >/dev/null
        print_success "Added Google Authenticator to PAM"
    else
        print_success "Google Authenticator already in PAM"
    fi
    
    echo
}

#############################################################################
# Configure SSH                                                             #
#############################################################################

configure_ssh() {
    print_header "Configuring SSH"
    
    local sshd_config="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="${dropin_dir}/99-lab-bastion.conf"
    local backup="/tmp/sshd_bastion_backup_$$"
    local user=$(whoami)
    
    # Ensure drop-in directory exists
    sudo mkdir -p "$dropin_dir"
    
    # Check if Include directive exists in main config
    print_step "Checking SSH Include directive..."
    if ! grep -qE '^[[:space:]]*Include.*/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
        print_warning "Adding Include directive to $sshd_config"
        # Portable prepend: create new file with Include + original content
        local include_line="Include /etc/ssh/sshd_config.d/*.conf"
        local tmpfile="${sshd_config}.labtmp"
        { printf '%s\n' "$include_line"; sudo cat "$sshd_config"; } | sudo tee "$tmpfile" > /dev/null
        sudo mv "$tmpfile" "$sshd_config"
    else
        print_success "Include directive already present"
    fi
    
    # Backup original config if not done
    if [[ ! -f "${sshd_config}.orig" ]]; then
        sudo cp "$sshd_config" "${sshd_config}.orig"
    fi
    
    # Backup current drop-in if exists
    [[ -f "$dropin_file" ]] && sudo cp "$dropin_file" "$backup"
    
    print_step "Creating SSH bastion drop-in configuration..."
    
    # Write drop-in config for bastion/jump server with 2FA
    sudo tee "$dropin_file" > /dev/null << EOF
# Managed by lab/jump.sh - do not edit manually
# Bastion/Jump Server SSH configuration with 2FA support

# Logging
LogLevel VERBOSE

# Authentication
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
IgnoreRhosts yes

# Password/key auth
PasswordAuthentication no
PermitEmptyPasswords no
GSSAPIAuthentication no

# 2FA / Challenge-Response authentication
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive

# Agent forwarding for jump functionality
AllowAgentForwarding yes

# Allowed ciphers and algorithms
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Restrict SSH access to current user
AllowUsers ${user}
EOF

    print_success "SSH bastion drop-in config created: $dropin_file"
    
    # Validate SSH configuration
    print_step "Validating SSH configuration..."
    if ! sudo sshd -t -f "$sshd_config" 2>/dev/null; then
        print_error "SSH configuration has errors, rolling back..."
        if [[ -f "$backup" ]]; then
            sudo mv "$backup" "$dropin_file"
        else
            sudo rm -f "$dropin_file"
        fi
        sudo systemctl restart sshd 2>/dev/null || true
        die "SSH configuration validation failed"
    fi
    print_success "SSH configuration is valid"
    
    # Restart SSH
    print_step "Restarting SSH service..."
    if sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
            print_success "SSH service restarted and running"
        else
            print_error "SSH service not active after restart, rolling back..."
            if [[ -f "$backup" ]]; then
                sudo mv "$backup" "$dropin_file"
            else
                sudo rm -f "$dropin_file"
            fi
            sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null || true
            die "SSH service failed after restart"
        fi
    else
        print_warning "SSH service restart may have failed"
    fi
    
    rm -f "$backup"
    echo
}

#############################################################################
# Generate SSH Key                                                          #
#############################################################################

generate_ssh_key() {
    print_header "Generating SSH Key"
    
    if [[ "${SKIP_KEYGEN:-false}" == "true" ]]; then
        print_warning "SSH key generation skipped (SKIP_KEYGEN=true)"
        return 0
    fi
    
    local keyfile="$HOME/.ssh/id_ed25519"
    
    if [[ -f "$keyfile" ]]; then
        print_warning "SSH key already exists: $keyfile"
        echo -n "Overwrite? (yes/no): "
        read -r response
        if [[ "${response,,}" != "yes" && "${response,,}" != "y" ]]; then
            print_info "Keeping existing key"
            return 0
        fi
    fi
    
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    
    print_step "Generating Ed25519 key (200 KDF rounds)..."
    ssh-keygen -t ed25519 -a 200 -N "" -f "$keyfile" -q
    
    print_success "SSH key generated: $keyfile"
    echo
}

#############################################################################
# Setup Google Authenticator                                                #
#############################################################################

setup_google_authenticator() {
    print_header "Setting Up Google Authenticator"
    
    if [[ "${SKIP_2FA:-false}" == "true" ]]; then
        print_warning "2FA setup skipped (SKIP_2FA=true)"
        return 0
    fi
    
    if ! command -v google-authenticator >/dev/null 2>&1; then
        print_warning "google-authenticator not installed, skipping"
        return 0
    fi
    
    echo
    print_info "Scan the QR code with Google Authenticator app"
    print_info "Save the emergency scratch codes!"
    echo
    
    # Options:
    # -d: disallow reuse of same token
    # -f: force create new secret
    # -t: time-based tokens
    # -r 3 -R 30: rate limit (3 attempts per 30 seconds)
    # -W: show warmup codes
    # Note: must use /dev/tty for QR code to render (bypasses tee logging)
    google-authenticator -d -f -t -r 3 -R 30 -W </dev/tty >/dev/tty
    
    print_success "Google Authenticator configured"
    echo
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    local user=$(whoami)
    local pubkey=""
    
    if [[ -f "$HOME/.ssh/id_ed25519.pub" ]]; then
        pubkey=$(cat "$HOME/.ssh/id_ed25519.pub")
    fi
    
    echo
    draw_box "Bastion Host Setup Complete"
    
    echo
    print_header "Connection Information"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "Hostname" "${HOSTNAME}.${DOMAIN_LOCAL}"
    print_kv "SSH User" "$user"
    print_kv "SSH Port" "22"
    
    echo
    print_header "SSH Commands"
    echo
    echo "  Direct connection:"
    echo "    ssh $user@$LOCAL_IP"
    echo
    echo "  Jump to remote host:"
    echo "    ssh -J $user@$LOCAL_IP:22 user@remote_host"
    echo
    
    if [[ -n "$pubkey" ]]; then
        print_header "SSH Public Key (for VM templates)"
        echo
        echo "  $pubkey"
        echo
    fi
    
    print_header "Important Files"
    print_kv "Log File" "$LOG_FILE"
    print_kv "SSH Config" "/etc/ssh/sshd_config"
    print_kv "Fail2Ban" "/etc/fail2ban/jail.local"
    
    draw_separator
    echo
}

#############################################################################
# Prompt Reboot                                                             #
#############################################################################

prompt_reboot() {
    if [[ "${SKIP_REBOOT:-false}" == "true" ]]; then
        print_info "Reboot skipped (SKIP_REBOOT=true)"
        print_warning "Remember to reboot later!"
        return 0
    fi
    
    echo
    while true; do
        echo -n "Restart now (recommended)? (yes/no): "
        read -r response
        
        case "${response,,}" in
            yes|y)
                print_step "Cleaning up and restarting..."
                sudo apt-get clean -qq
                sudo apt-get autoremove -qq -y
                sudo reboot now
                break
                ;;
            no|n)
                print_warning "Remember to restart later!"
                return 0
                ;;
            *)
                print_warning "Please enter 'yes' or 'no'"
                ;;
        esac
    done
}

#############################################################################
# Main                                                                      #
#############################################################################

main() {
    # Initialize logging
    sudo mkdir -p "$LOG_DIR"
    sudo touch "$LOG_FILE"
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    draw_box "Bastion Host / Jump Server Setup v${SCRIPT_VERSION}"
    echo
    print_info "Secure SSH access with 2FA (Google Authenticator)"
    print_info "Log file: $LOG_FILE"
    
    # Run setup
    preflight_checks
    detect_network_info
    
    # Show intro
    print_header "Configuration Summary"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    echo
    
    print_warning "Ensure you have a clean Debian install"
    print_warning "Check domain name before proceeding"
    echo
    
    # Confirm start
    while true; do
        echo -n "Start hardening? (yes/no): "
        read -r choice
        
        case "${choice,,}" in
            yes|y) break ;;
            no|n) die "Aborted by user" ;;
            *) print_warning "Please enter 'yes' or 'no'" ;;
        esac
    done
    
    # Execute hardening steps
    install_packages
    configure_hosts
    configure_unattended_upgrades
    configure_ufw
    configure_fail2ban
    secure_shared_memory
    configure_sysctl
    lock_root_account
    configure_pam_2fa
    configure_ssh
    generate_ssh_key
    setup_google_authenticator
    
    # Show results
    show_summary
    
    # Prompt for reboot
    prompt_reboot
}

main "$@"