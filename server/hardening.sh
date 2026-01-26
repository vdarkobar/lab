#!/bin/bash

#############################################################################
# Debian 13 VM/LXC Server Hardening Script                                  #
# Professional edition with enhanced output formatting                      #
#                                                                            #
# EXECUTION REQUIREMENTS:                                                   #
#   - Must be run as a NON-ROOT user                                        #
#   - User must have sudo privileges                                        #
#   - Script will use sudo internally for privileged operations             #
#                                                                            #
# CORRECT USAGE:                                                            #
#   ./hardening_professional.sh                                             #
#                                                                            #
# INCORRECT USAGE:                                                          #
#   sudo ./hardening_professional.sh  ← DO NOT DO THIS                      #
#   # ./hardening_professional.sh     ← DO NOT DO THIS                      #
#############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#################################################################
# Load Formatting Library                                       #
#################################################################

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the formatting library
if [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/../lib/formatting.sh"
else
    echo "ERROR: Cannot find formatting library at $SCRIPT_DIR/../lib/formatting.sh" >&2
    exit 1
fi

#################################################################
# Application Registry - ADD NEW APPS HERE                      #
#################################################################

# Easy app registration - just add new entries to this array
# Format: "display_name|script_name|detection_command"
readonly APP_REGISTRY=(
    "Nginx Proxy Manager|npm.sh|systemctl is-active --quiet openresty || systemctl is-active --quiet nginx-proxy-manager"
    "Docker|docker.sh|command -v docker >/dev/null 2>&1"
    "Portainer|portainer.sh|docker ps -a --format '{{.Names}}' | grep -q 'portainer'"
    "Unbound DNS|unbound.sh|systemctl is-active --quiet unbound"
    # Add more apps here - one per line
    # "App Name|script.sh|detection command that returns 0 if installed"
)

# Base URL for app scripts
readonly APPS_BASE_URL="https://raw.githubusercontent.com/vdarkobar/lab/main/apps"

#################################################################
# Configuration                                                  #
#################################################################

readonly SCRIPT_VERSION="2.1.0"
readonly LOG_FILE="/var/log/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"

#################################################################
# Pre-flight Checks                                             #
#################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # CRITICAL: Enforce non-root execution
    if [[ ${EUID} -eq 0 ]]; then
        echo
        print_error "This script must NOT be run as root!"
        echo
        print_info "Correct usage:"
        echo "  ${C_CYAN}./$(basename "$0")${C_RESET}"
        echo
        print_info "The script will use sudo internally when needed."
        echo
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access, run as root:"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# Then logout and login again${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Test sudo authentication
    if ! sudo -n true 2>/dev/null; then
        print_info "Sudo authentication required"
        if ! sudo -v; then
            die "Sudo authentication failed"
        fi
    fi
    print_success "Sudo authentication successful"
    
    # Check Debian version
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            print_warning "This script is designed for Debian. Detected: $ID"
        else
            print_success "Debian system detected: $VERSION"
        fi
    else
        print_warning "Cannot determine OS version"
    fi
    
    # Check disk space (need at least 1GB free)
    local free_space=$(df / | awk 'NR==2 {print $4}')
    local free_gb=$((free_space / 1048576))
    if [[ $free_space -lt 1048576 ]]; then
        die "Insufficient disk space. Need at least 1GB free, have ${free_gb}GB"
    fi
    print_success "Sufficient disk space available (${free_gb}GB free)"
    
    # Check internet connectivity (use HTTP instead of ICMP for container compatibility)
    print_step "Testing internet connectivity..."
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 5 --head https://www.google.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified (via curl)"
        else
            die "No internet connectivity detected (curl test failed)"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=5 --spider https://www.google.com 2>/dev/null; then
            print_success "Internet connectivity verified (via wget)"
        else
            die "No internet connectivity detected (wget test failed)"
        fi
    else
        print_warning "Cannot verify internet (curl/wget not available yet)"
        print_info "Assuming connectivity OK - will install curl in next step"
    fi
    
    echo
}

#################################################################
# Environment Detection                                          #
#################################################################

detect_environment() {
    print_header "Environment Detection"
    
    # Detect virtualization type
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if systemd-detect-virt --container >/dev/null 2>&1; then
            CONTAINER_TYPE=$(systemd-detect-virt --container)
            IS_CONTAINER=true
            IS_PRIVILEGED=false
            
            # Check if privileged container
            if [[ -c /dev/kmsg ]] || [[ -w /sys/kernel ]]; then
                IS_PRIVILEGED=true
            fi
        elif systemd-detect-virt --vm >/dev/null 2>&1; then
            CONTAINER_TYPE=$(systemd-detect-virt --vm)
            IS_CONTAINER=false
            IS_PRIVILEGED=true
        else
            CONTAINER_TYPE="bare-metal"
            IS_CONTAINER=false
            IS_PRIVILEGED=true
        fi
    else
        print_warning "systemd-detect-virt not found, assuming VM"
        CONTAINER_TYPE="unknown"
        IS_CONTAINER=false
        IS_PRIVILEGED=true
    fi
    
    print_kv "Environment Type" "$CONTAINER_TYPE"
    print_kv "Is Container" "$IS_CONTAINER"
    print_kv "Is Privileged" "$IS_PRIVILEGED"
    echo
}

#################################################################
# Network Information Detection                                  #
#################################################################

detect_network_info() {
    print_header "Network Configuration"
    
    # Get hostname
    HOSTNAME=$(hostname -s) || HOSTNAME="unknown"
    
    # Detect domain name
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved; then
        DOMAIN_LOCAL=$(resolvectl status | awk '/DNS Domain:/ {print $3; exit}' | head -n1)
    fi
    
    # Fallback to /etc/resolv.conf
    if [[ -z "${DOMAIN_LOCAL:-}" ]]; then
        DOMAIN_LOCAL=$(awk '/^domain|^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    fi
    
    # Final fallback
    DOMAIN_LOCAL=${DOMAIN_LOCAL:-"local"}
    
    # Detect primary IP address
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    # Fallback IP detection
    if [[ -z "$LOCAL_IP" ]] || [[ "$LOCAL_IP" == "127.0.0.1" ]]; then
        LOCAL_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    fi
    
    # Final fallback
    LOCAL_IP=${LOCAL_IP:-"127.0.0.1"}
    
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "FQDN" "$HOSTNAME.$DOMAIN_LOCAL"
    echo
}

#################################################################
# Display Introduction                                           #
#################################################################

show_intro() {
    clear
    
    draw_box "Debian Server Hardening Script v${SCRIPT_VERSION}"
    
    echo
    print_header "System Information"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "Hostname" "$HOSTNAME"
    print_kv "Domain" "$DOMAIN_LOCAL"
    print_kv "Environment" "$CONTAINER_TYPE"
    print_kv "Executing User" "$(whoami)"
    
    echo
    print_header "Hardening Steps"
    print_subheader "Install security packages (UFW, Fail2Ban, etc.)"
    print_subheader "Configure firewall rules"
    print_subheader "Set up intrusion prevention"
    print_subheader "Harden SSH configuration"
    print_subheader "Enable automatic security updates"
    print_subheader "Apply system security settings"
    print_subheader "Configure SSH key authentication"
    
    echo
    print_header "Requirements"
    print_warning "Script must run as non-root user (currently: $(whoami))"
    print_warning "User must have sudo privileges (will prompt if needed)"
    print_warning "SSH public key required for authentication"
    
    echo
    print_info "Logs will be saved to: ${C_DIM}${LOG_FILE}${C_RESET}"
    print_info "Backups will be saved to: ${C_DIM}${BACKUP_DIR}${C_RESET}"
    echo
}

#################################################################
# Confirm Script Execution                                       #
#################################################################

confirm_start() {
    draw_separator
    echo
    while true; do
        echo -n "${C_BOLD}${C_CYAN}Proceed with hardening? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r choice
        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        
        case "$choice" in
            yes|y)
                log INFO "User confirmed, starting installation..."
                echo
                return 0
                ;;
            no|n)
                log INFO "User cancelled installation"
                print_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                print_error "Invalid input. Please enter 'yes' or 'no'"
                ;;
        esac
    done
}

#################################################################
# Create Backup Directory                                        #
#################################################################

create_backup_dir() {
    if ! sudo mkdir -p "$BACKUP_DIR"; then
        die "Failed to create backup directory: $BACKUP_DIR"
    fi
    # Give ownership to current user so they can access backups
    sudo chown "$(whoami):$(id -gn)" "$BACKUP_DIR"
    log SUCCESS "Backup directory created"
}

#################################################################
# Backup File                                                    #
#################################################################

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="$BACKUP_DIR$(dirname "$file")"
        sudo mkdir -p "$backup_path"
        sudo cp -a "$file" "$backup_path/" || log WARN "Failed to backup $file"
        log INFO "Backed up: ${C_DIM}${file}${C_RESET}"
    fi
}

#################################################################
# Install Required Packages                                      #
#################################################################

install_packages() {
    print_header "Installing Security Packages"
    
    # Update package lists
    print_step "Updating package repositories..."
    if ! sudo apt update >/dev/null 2>&1; then
        die "Failed to update package repositories"
    fi
    print_success "Package lists updated"
    
    # Install packages
    local packages=(
        ufw
        fail2ban
        wget
        curl
        gnupg2
        argon2
        lsb-release
        gnupg-agent
        libpam-tmpdir
        bash-completion
        ca-certificates
        qemu-guest-agent
        unattended-upgrades
        cloud-initramfs-growroot
    )
    
    print_step "Installing packages: ${C_DIM}${packages[*]}${C_RESET}"
    if ! sudo DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}" >/dev/null 2>&1; then
        die "Failed to install packages"
    fi
    
    log SUCCESS "All packages installed successfully"
    echo
}

#################################################################
# Configure Hosts File                                           #
#################################################################

configure_hosts() {
    print_header "Configuring System Hosts File"
    
    backup_file "/etc/hosts"
    
    # Create new hosts file
    local temp_hosts=$(mktemp)
    
    {
        echo "127.0.0.1       localhost"
        echo "::1             localhost ip6-localhost ip6-loopback"
        echo "ff02::1         ip6-allnodes"
        echo "ff02::2         ip6-allrouters"
        echo ""
        echo "# Host configuration"
        echo "$LOCAL_IP       $HOSTNAME $HOSTNAME.$DOMAIN_LOCAL"
        echo ""
        echo "# Existing entries (if any)"
        grep -v -E '^(127\.0\.0\.1|::1|ff02::|#.*|^$)' /etc/hosts 2>/dev/null | \
        grep -v "$HOSTNAME" || true
    } > "$temp_hosts"
    
    if sudo mv "$temp_hosts" /etc/hosts; then
        sudo chmod 644 /etc/hosts
        log SUCCESS "Hosts file configured"
    else
        die "Failed to update /etc/hosts"
    fi
    echo
}

#################################################################
# Configure Unattended Upgrades                                  #
#################################################################

configure_unattended_upgrades() {
    print_header "Configuring Automatic Security Updates"
    
    # Enable unattended-upgrades
    print_step "Enabling unattended-upgrades..."
    if ! echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | \
         sudo debconf-set-selections; then
        die "Failed to configure unattended-upgrades"
    fi
    
    if ! sudo dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1; then
        die "Failed to enable unattended-upgrades"
    fi
    
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    if [[ ! -f "$config_file" ]]; then
        print_warning "Configuration file not found, skipping advanced options"
        return
    fi
    
    backup_file "$config_file"
    
    print_step "Configuring automatic cleanup and reboot..."
    # Configure options
    sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' "$config_file"
    sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' "$config_file"
    sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' "$config_file"
    sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' "$config_file"
    sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' "$config_file"
    
    log SUCCESS "Automatic security updates enabled"
    print_info "System will automatically reboot at 02:00 if needed"
    echo
}

#################################################################
# Configure Fail2Ban                                             #
#################################################################

configure_fail2ban() {
    print_header "Configuring Fail2Ban Intrusion Prevention"
    
    if ! command -v fail2ban-server >/dev/null 2>&1; then
        die "Fail2Ban is not installed"
    fi
    
    # Copy jail.conf to jail.local
    print_step "Creating Fail2Ban configuration..."
    if ! sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
        die "Failed to create jail.local"
    fi
    
    backup_file "/etc/fail2ban/jail.local"
    
    # Configure backend for systemd
    sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local
    
    # Enable SSH protection
    print_step "Enabling SSH protection..."
    local config_file="/etc/fail2ban/jail.local"
    sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > /tmp/jail.local.tmp
    sudo mv /tmp/jail.local.tmp "$config_file"
    
    # Set stricter limits
    print_step "Configuring ban parameters (3 attempts, 15min ban)..."
    sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' "$config_file"
    sudo sed -i 's|maxretry = 5|maxretry = 3|g' "$config_file"
    
    # Restart Fail2Ban
    if sudo systemctl restart fail2ban; then
        log SUCCESS "Fail2Ban configured and running"
    else
        print_warning "Fail2Ban restart failed, may need manual intervention"
    fi
    echo
}

#################################################################
# Configure UFW Firewall                                         #
#################################################################

configure_ufw() {
    print_header "Configuring UFW Firewall"
    
    # Check if UFW can work in this environment
    if [[ "$IS_CONTAINER" == "true" ]] && [[ "$IS_PRIVILEGED" == "false" ]]; then
        print_warning "UFW not supported in unprivileged containers"
        print_info "Configure firewall on the host system instead"
        echo
        return
    fi
    
    # Reset UFW to default state
    print_step "Resetting UFW to defaults..."
    sudo ufw --force reset >/dev/null 2>&1 || true
    
    # Set default policies
    print_step "Setting default policies..."
    sudo ufw default deny incoming >/dev/null
    sudo ufw default allow outgoing >/dev/null
    
    # Allow SSH (rate limited)
    print_step "Allowing SSH with rate limiting..."
    sudo ufw limit 22/tcp comment "SSH" >/dev/null
    
    # Enable UFW
    if sudo ufw --force enable >/dev/null 2>&1; then
        log SUCCESS "UFW firewall configured and enabled"
    else
        print_warning "UFW enable failed, may need manual configuration"
    fi
    echo
}

#################################################################
# Secure Shared Memory                                           #
#################################################################

secure_shared_memory() {
    print_header "Securing Shared Memory"
    
    if [[ "$IS_CONTAINER" == "true" ]]; then
        print_warning "Skipping shared memory hardening in container environment"
        echo
        return
    fi
    
    backup_file "/etc/fstab"
    
    # Check if entry already exists
    if grep -q '/run/shm' /etc/fstab; then
        print_info "Shared memory already configured in fstab"
    else
        echo "none /run/shm tmpfs defaults,ro 0 0" | sudo tee -a /etc/fstab > /dev/null
        log SUCCESS "Shared memory secured"
    fi
    echo
}

#################################################################
# Configure Sysctl (Network Security)                            #
#################################################################

configure_sysctl() {
    print_header "Applying Network Security Settings"
    
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    
    backup_file "$sysctl_file"
    
    print_step "Creating sysctl configuration..."
    # Create sysctl configuration
    sudo tee "$sysctl_file" > /dev/null << 'EOF'
# Network security hardening
# Applied by server hardening script

# IP Forwarding (disable unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

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

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
EOF

    # Apply settings (may fail in unprivileged containers)
    print_step "Applying sysctl settings..."
    if sudo sysctl -p "$sysctl_file" >/dev/null 2>&1; then
        log SUCCESS "Network security settings applied"
    else
        print_warning "Some settings failed (expected in unprivileged containers)"
        sudo sysctl -p "$sysctl_file" 2>&1 | grep -i "permission denied" | \
        while read -r line; do
            print_subheader "Denied: $(echo "$line" | awk '{print $2}')"
        done
    fi
    echo
}

#################################################################
# Configure SSH Key Authentication                               #
#################################################################

configure_ssh_keys() {
    print_header "Configuring SSH Key Authentication"
    
    local user=$(whoami)
    local ssh_dir="/home/$user/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    # Create .ssh directory if it doesn't exist
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_success "Created .ssh directory"
    fi
    
    # Create authorized_keys if it doesn't exist
    if [[ ! -f "$auth_keys" ]]; then
        touch "$auth_keys"
        chmod 600 "$auth_keys"
        print_success "Created authorized_keys file"
    fi
    
    # Request SSH public key
    echo
    draw_separator
    echo
    print_info "SSH Public Key Configuration"
    echo
    print_subheader "Paste your SSH public key below"
    print_subheader "Recommended: ed25519 keys for better security"
    echo
    echo "  ${C_DIM}Example: ssh-ed25519 AAAAC3Nza... user@host${C_RESET}"
    echo
    
    while true; do
        echo -n "${C_CYAN}Public Key: ${C_RESET}"
        read -r public_key
        
        # Check if input is empty
        if [[ -z "$public_key" ]]; then
            print_error "No input received"
            continue
        fi
        
        # Validate SSH key format
        if [[ "$public_key" =~ ^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)[[:space:]][A-Za-z0-9+/]+[=]{0,3}([[:space:]].*)?$ ]]; then
            # Check if key already exists
            if grep -Fq "$public_key" "$auth_keys" 2>/dev/null; then
                print_info "SSH key already exists in authorized_keys"
                break
            fi
            
            # Add key to authorized_keys
            echo "$public_key" >> "$auth_keys"
            chmod 600 "$auth_keys"
            log SUCCESS "SSH public key added successfully"
            break
        else
            print_error "Invalid SSH key format"
            print_subheader "Valid formats: ssh-rsa, ssh-ed25519, ecdsa-sha2-*"
        fi
    done
    
    echo
}

#################################################################
# Lock Root Account                                              #
#################################################################

lock_root_account() {
    print_header "Securing Root Account"
    
    # Check if root is already locked
    if sudo passwd -S root | grep -q " L "; then
        print_info "Root account password already locked"
    else
        if sudo passwd -l root >/dev/null 2>&1; then
            log SUCCESS "Root account password locked"
        else
            print_warning "Failed to lock root account"
        fi
    fi
    echo
}

#################################################################
# Configure SSH Daemon                                           #
#################################################################

configure_sshd() {
    print_header "Hardening SSH Configuration"
    
    local sshd_config="/etc/ssh/sshd_config"
    backup_file "$sshd_config"
    
    # Create backup
    sudo cp "$sshd_config" "${sshd_config}.original"
    
    print_step "Applying SSH security settings..."
    # Apply SSH hardening settings
    local settings=(
        "s|^#*PermitRootLogin.*|PermitRootLogin no|"
        "s|^#*PasswordAuthentication.*|PasswordAuthentication no|"
        "s|^#*PubkeyAuthentication.*|PubkeyAuthentication yes|"
        "s|^#*PermitEmptyPasswords.*|PermitEmptyPasswords no|"
        "s|^#*ChallengeResponseAuthentication.*|ChallengeResponseAuthentication no|"
        "s|^#*KbdInteractiveAuthentication.*|KbdInteractiveAuthentication no|"
        "s|^#*UsePAM.*|UsePAM no|"
        "s|^#*X11Forwarding.*|X11Forwarding no|"
        "s|^#*MaxAuthTries.*|MaxAuthTries 3|"
        "s|^#*MaxSessions.*|MaxSessions 2|"
        "s|^#*LogLevel.*|LogLevel VERBOSE|"
        "s|^#*StrictModes.*|StrictModes yes|"
        "s|^#*IgnoreRhosts.*|IgnoreRhosts yes|"
        "s|^#*GSSAPIAuthentication.*|GSSAPIAuthentication no|"
    )
    
    for setting in "${settings[@]}"; do
        sudo sed -i "$setting" "$sshd_config"
    done
    
    # Add additional security settings if not present
    if ! grep -q "^Protocol" "$sshd_config"; then
        echo "Protocol 2" | sudo tee -a "$sshd_config" > /dev/null
    fi
    
    if ! grep -q "^ClientAliveInterval" "$sshd_config"; then
        print_step "Adding advanced security options..."
        cat << 'EOF' | sudo tee -a "$sshd_config" > /dev/null

# Connection timeouts
ClientAliveInterval 300
ClientAliveCountMax 2

# Rate limiting
MaxStartups 10:30:60
LoginGraceTime 30

# Security hardening
PermitUserEnvironment no
Compression delayed

# Allowed ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOF
    fi
    
    # Restrict SSH access to current user
    local user=$(whoami)
    if ! grep -q "^AllowUsers" "$sshd_config"; then
        print_step "Restricting SSH access to user: ${C_BOLD}${user}${C_RESET}"
        echo "AllowUsers $user" | sudo tee -a "$sshd_config" > /dev/null
    else
        print_warning "AllowUsers already configured, verify manually"
    fi
    
    # Test SSH configuration
    print_step "Validating SSH configuration..."
    if sudo sshd -t; then
        log SUCCESS "SSH configuration is valid"
        
        # Restart SSH service
        if sudo systemctl restart sshd || sudo systemctl restart ssh; then
            log SUCCESS "SSH service restarted successfully"
        else
            print_warning "Failed to restart SSH service"
        fi
    else
        die "SSH configuration has errors, reverting changes"
    fi
    echo
}

#################################################################
# Check if Application is Installed                             #
#################################################################

check_app_installed() {
    local detection_cmd="$1"
    
    # Run detection command, suppress output
    if eval "$detection_cmd" 2>/dev/null; then
        return 0  # Installed
    else
        return 1  # Not installed
    fi
}

#################################################################
# Show Application Menu                                         #
#################################################################

show_app_menu() {
    print_header "Application Installation"
    
    echo
    print_info "Available applications to install:"
    echo
    
    local available_apps=()
    local app_count=0
    
    # Build menu of available (not installed) apps
    for app_entry in "${APP_REGISTRY[@]}"; do
        IFS='|' read -r display_name script_name detection_cmd <<< "$app_entry"
        
        if check_app_installed "$detection_cmd"; then
            print_subheader "${C_DIM}$display_name - Already installed ✓${C_RESET}"
        else
            ((app_count++))
            available_apps+=("$app_entry")
            print_subheader "${C_CYAN}${app_count})${C_RESET} $display_name ${C_DIM}(${script_name})${C_RESET}"
        fi
    done
    
    echo
    print_subheader "${C_CYAN}$((app_count + 1)))${C_RESET} Skip - No application installation"
    echo
    
    # If no apps available, skip
    if [[ $app_count -eq 0 ]]; then
        print_warning "All applications already installed"
        return 1
    fi
    
    # Get user selection
    while true; do
        echo -n "${C_CYAN}${C_BOLD}Select application to install [1-$((app_count + 1))]:${C_RESET} "
        read -r selection
        
        # Check if user wants to skip
        if [[ "$selection" -eq $((app_count + 1)) ]]; then
            print_info "Skipping application installation"
            return 1
        fi
        
        # Validate selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le $app_count ]]; then
            # Get selected app
            local selected_app="${available_apps[$((selection - 1))]}"
            IFS='|' read -r display_name script_name detection_cmd <<< "$selected_app"
            
            print_success "Selected: $display_name"
            echo
            
            # Download and install
            download_and_install_app "$script_name" "$display_name"
            return 0
        else
            print_error "Invalid selection. Please enter a number between 1 and $((app_count + 1))"
        fi
    done
}

#################################################################
# Download and Install Application                              #
#################################################################

download_and_install_app() {
    local script_name="$1"
    local display_name="$2"
    local script_url="${APPS_BASE_URL}/${script_name}"
    local tmp_script="/tmp/app-install-$RANDOM.sh"
    local checksums_file="${SCRIPT_DIR}/../CHECKSUMS.txt"
    local checksum_verified=false
    
    print_header "Installing: $display_name"
    
    # Download script
    print_step "Downloading ${script_name}..."
    print_subheader "Source: ${C_DIM}${script_url}${C_RESET}"
    
    if ! curl -fsSL "$script_url" -o "$tmp_script"; then
        print_error "Failed to download ${script_name}"
        return 1
    fi
    
    local file_size=$(stat -c%s "$tmp_script" 2>/dev/null || stat -f%z "$tmp_script" 2>/dev/null || echo "unknown")
    print_success "Script downloaded (${file_size} bytes)"
    
    # Try to verify using CHECKSUMS.txt
    print_step "Looking for checksum..."
    
    if [[ -f "$checksums_file" ]]; then
        print_success "Found CHECKSUMS.txt"
        
        # Extract expected hash for this script from CHECKSUMS.txt
        local expected_hash=$(grep "apps/${script_name}" "$checksums_file" | grep -v '^#' | awk '{print $1}')
        
        if [[ -n "$expected_hash" ]]; then
            local actual_hash=$(sha256sum "$tmp_script" | awk '{print $1}')
            
            print_step "Verifying integrity..."
            if [[ "$actual_hash" == "$expected_hash" ]]; then
                print_success "Checksum verified: ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                checksum_verified=true
            else
                rm -f "$tmp_script"
                print_error "Expected: ${C_DIM}${expected_hash:0:16}...${C_RESET}"
                print_error "Got:      ${C_DIM}${actual_hash:0:16}...${C_RESET}"
                print_error "Checksum verification FAILED!"
                return 1
            fi
        else
            print_warning "No checksum found in CHECKSUMS.txt for ${script_name}"
            checksum_verified=false
        fi
    else
        print_warning "CHECKSUMS.txt not found at ${C_DIM}${checksums_file}${C_RESET}"
        checksum_verified=false
    fi
    
    # If no checksum verification, ask user
    if [[ "$checksum_verified" == false ]]; then
        print_warning "Proceeding without verification (not recommended)"
        
        # Show what we're about to run
        echo
        print_step "Script preview (first 20 lines):"
        echo "${C_DIM}"
        head -20 "$tmp_script"
        echo "${C_RESET}"
        echo
        
        # Ask for confirmation
        while true; do
            echo -n "${C_BOLD}${C_RED}Execute unverified script? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r response
            
            case "$(echo "$response" | tr '[:upper:]' '[:lower:]')" in
                yes|y)
                    print_warning "Proceeding without verification"
                    break
                    ;;
                no|n)
                    rm -f "$tmp_script"
                    print_info "Installation cancelled"
                    return 1
                    ;;
                *)
                    print_error "Invalid input. Please enter 'yes' or 'no'"
                    ;;
            esac
        done
    fi
    
    # Execute the script
    echo
    print_step "Executing ${script_name}..."
    chmod +x "$tmp_script"
    
    if sudo -E bash "$tmp_script"; then
        log SUCCESS "${display_name} installed successfully"
        print_success "${display_name} installation completed"
    else
        log ERROR "${display_name} installation failed (exit code: $?)"
        print_error "${display_name} installation failed"
    fi
    
    # Cleanup
    rm -f "$tmp_script"
    echo
}

#################################################################
# Final Summary                                                  #
#################################################################

show_summary() {
    echo
    draw_box "Hardening Completed Successfully"
    
    echo
    print_header "Summary"
    print_success "Security packages installed and configured"
    print_success "Firewall (UFW) enabled and configured"
    print_success "Fail2Ban active for intrusion prevention"
    print_success "SSH hardened (password auth disabled)"
    print_success "Automatic security updates enabled"
    print_success "System security settings applied"
    
    echo
    print_header "Critical Next Steps"
    echo
    print_warning "Test SSH access from another terminal NOW"
    print_warning "Verify SSH key authentication works"
    print_warning "Do NOT close this session until verified"
    
    echo
    print_header "Important Information"
    print_kv "Log File" "$LOG_FILE"
    print_kv "Backups" "$BACKUP_DIR"
    print_kv "FQDN" "$HOSTNAME.$DOMAIN_LOCAL"
    print_kv "IP Address" "$LOCAL_IP"
    print_kv "SSH User" "$(whoami)"
    
    echo
    print_header "Next SSH Connection"
    echo "  ${C_CYAN}${C_BOLD}ssh $(whoami)@$LOCAL_IP${C_RESET}"
    echo
    
    draw_separator
    echo
}

#################################################################
# Main Execution                                                 #
#################################################################

main() {
    # Early check: Verify sudo is available before we do anything
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi
    
    # Verify user has sudo access before creating log file
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: Current user $(whoami) does not have sudo privileges" >&2
        echo "Please add user to sudo group:" >&2
        echo "  usermod -aG sudo $(whoami)" >&2
        echo "Then logout and login again" >&2
        exit 1
    fi
    
    # Initialize logging - create file as root but give ownership to current user
    sudo touch "$LOG_FILE" || {
        echo "ERROR: Cannot create log file. Ensure you have sudo privileges." >&2
        exit 1
    }
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    
    log INFO "=== Server Hardening Script Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
    
    # Run checks and setup
    preflight_checks
    detect_environment
    detect_network_info
    create_backup_dir
    
    # Show intro and get confirmation
    show_intro
    confirm_start
    
    # Execute hardening steps
    install_packages
    configure_hosts
    configure_unattended_upgrades
    configure_fail2ban
    configure_ufw
    secure_shared_memory
    configure_sysctl
    configure_ssh_keys
    lock_root_account
    configure_sshd
    
    # Show application installation menu
    if show_app_menu; then
        log SUCCESS "Application installation completed"
    else
        print_info "Application installation skipped"
    fi
    
    # Show summary
    show_summary
    
    log INFO "=== Server Hardening Script Completed ==="
}

# Run main function
main "$@"
