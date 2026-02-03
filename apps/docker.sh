#!/bin/bash

#############################################################################
# Docker + Docker Compose (v2) Installation Script                          #
# Installs Docker CE, CLI, containerd, and Compose plugin                   #
#############################################################################

readonly SCRIPT_VERSION="2.0.0"

# Handle --help flag early (before any setup)
case "${1:-}" in
    --help|-h)
        echo "Docker + Compose (v2) Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Docker\""
        echo "  OR run standalone after hardening"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Internet connectivity required"
        echo "  - Debian-based system (Debian/Ubuntu)"
        echo
        echo "What it does:"
        echo "  - Installs Docker CE, CLI, containerd"
        echo "  - Installs Docker Compose v2 plugin"
        echo "  - Installs Docker Buildx plugin"
        echo "  - Adds current user to docker group"
        echo "  - Configures Docker repository and GPG key"
        echo
        echo "Environment variables:"
        echo "  DOCKER_DIST=<codename>   Override Debian codename for Docker repo"
        echo "                           (useful when Docker doesn't support latest Debian)"
        echo
        echo "Files created:"
        echo "  /etc/apt/keyrings/docker.gpg         Docker GPG key"
        echo "  /etc/apt/sources.list.d/docker.list  Docker repository"
        echo
        echo "Post-install:"
        echo "  Log out and back in, or run: newgrp docker"
        exit 0
        ;;
esac

#############################################################################
# Script Configuration                                                      #
#############################################################################

set -euo pipefail

# Track services we stop (to restart later)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#############################################################################
# Terminal Formatting                                                       #
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
    printf "${C_CYAN}%-20s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "$key:" "$value"
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
# Logging                                                                   #
#############################################################################

die() {
    print_error "$@"
    exit 1
}

# Error trap for better debugging
trap 'print_error "Error on line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

preflight_checks() {
    print_header "Pre-flight Checks"
    
    # Must not run as root
    if [[ ${EUID} -eq 0 ]]; then
        print_error "This script must NOT be run as root!"
        print_info "Correct usage: ${C_CYAN}./$(basename "$0")${C_RESET}"
        die "Execution blocked: Running as root user"
    fi
    print_success "Running as non-root user: ${C_BOLD}$(whoami)${C_RESET}"
    
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "User $(whoami) does not have sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Check if running on PVE host
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC."
    fi
    print_success "Not running on Proxmox host"
    
    # Check internet connectivity
    print_step "Testing internet connectivity..."
    local internet_ok=false
    
    # Method 1: curl (if available)
    if command -v curl >/dev/null 2>&1; then
        if curl -s --max-time 5 --head https://download.docker.com >/dev/null 2>&1; then
            print_success "Internet connectivity verified (curl)"
            internet_ok=true
        fi
    fi
    
    # Method 2: wget (if available)
    if [[ "$internet_ok" == false ]] && command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=5 --spider https://download.docker.com 2>/dev/null; then
            print_success "Internet connectivity verified (wget)"
            internet_ok=true
        fi
    fi
    
    # Method 3: Bash /dev/tcp (built-in)
    if [[ "$internet_ok" == false ]]; then
        if (echo >/dev/tcp/download.docker.com/443) 2>/dev/null; then
            print_success "Internet connectivity verified (tcp)"
            internet_ok=true
        fi
    fi
    
    # If all methods fail, warn but continue
    if [[ "$internet_ok" == false ]]; then
        print_warning "Could not verify internet with available tools"
        print_info "Will verify connectivity when installing packages..."
    fi
    
    echo
}

#############################################################################
# Install Prerequisites                                                     #
#############################################################################

install_prerequisites() {
    print_header "Checking Prerequisites"
    
    local required_packages=(
        ca-certificates
        curl
        wget
        gnupg
        lsb-release
    )
    
    local missing_packages=()
    
    for pkg in "${required_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            print_success "Package installed: $pkg"
        else
            missing_packages+=("$pkg")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        print_step "Installing missing packages: ${missing_packages[*]}"
        sudo apt-get update >/dev/null 2>&1
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}" >/dev/null 2>&1
        print_success "Missing packages installed"
    fi
    
    echo
}

#############################################################################
# Docker Codename Detection                                                 #
#############################################################################

get_docker_codename() {
    # Check for manual override first
    local override_val="${DOCKER_DIST:-}"
    if [[ -n "$override_val" ]]; then
        echo "$override_val"
        return 0
    fi
    
    # Detect system codename from /etc/os-release
    local detected=""
    if [[ -f /etc/os-release ]]; then
        detected="$(grep '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    fi
    
    # Fallback to lsb_release if os-release didn't work
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "")"
    
    # Test if Docker repo exists for detected codename
    if [[ -n "$detected" ]]; then
        local test_url="https://download.docker.com/linux/debian/dists/${detected}/Release"
        if curl -sSf --head --max-time 5 "$test_url" >/dev/null 2>&1; then
            echo "$detected"
            return 0
        fi
        echo "INFO: Docker repo not found for '$detected', falling back to bookworm" >&2
    fi
    
    echo "bookworm"
}

#############################################################################
# Docker Installation (idempotent)                                          #
#############################################################################

install_docker() {
    print_header "Docker Installation"
    
    # Check if Docker is already installed and working
    if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        print_success "Docker is already installed and running"
        sudo docker --version
        sudo docker compose version
        echo
        return 0
    fi
    
    local need_apt_update=true
    
    # Stop unattended upgrades if running (track state to restart later)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
    # Docker GPG key
    print_step "Setting up Docker repository..."
    sudo mkdir -p /etc/apt/keyrings
    
    if [[ ! -s /etc/apt/keyrings/docker.gpg ]]; then
        print_subheader "Adding Docker GPG key..."
        curl -fsSL https://download.docker.com/linux/debian/gpg | \
            sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    else
        print_success "Docker GPG key already present"
    fi
    
    # Docker repository
    local docker_list="/etc/apt/sources.list.d/docker.list"
    local arch="$(dpkg --print-architecture)"
    local codename="$(get_docker_codename)"
    local desired_line="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${codename} stable"
    
    print_kv "Architecture" "$arch"
    print_kv "Codename" "$codename"
    
    if [[ -f "$docker_list" ]] && grep -Fqx "$desired_line" "$docker_list"; then
        print_success "Docker repository already configured"
        need_apt_update=false
    else
        print_subheader "Configuring Docker repository..."
        echo "$desired_line" | sudo tee "$docker_list" >/dev/null
    fi
    
    # Install Docker packages
    local docker_packages=(
        docker-ce
        docker-ce-cli
        containerd.io
        docker-buildx-plugin
        docker-compose-plugin
    )
    
    print_step "Installing Docker packages..."
    
    for pkg in "${docker_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            print_success "Already installed: $pkg"
        else
            if [[ "$need_apt_update" == true ]]; then
                sudo apt-get update >/dev/null 2>&1
                need_apt_update=false
            fi
            print_subheader "Installing: $pkg"
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1
        fi
    done
    
    # Enable and start Docker
    print_step "Enabling Docker service..."
    sudo systemctl enable --now docker >/dev/null 2>&1
    print_success "Docker service enabled and started"
    
    # Ensure docker group exists
    if getent group docker >/dev/null 2>&1; then
        print_success "Docker group exists"
    else
        print_step "Creating docker group..."
        sudo groupadd docker
    fi
    
    # Add user to docker group
    local user_name="$(id -un)"
    if id -nG "$user_name" | tr ' ' '\n' | grep -qx docker; then
        print_success "User already in docker group: $user_name"
    else
        print_step "Adding user to docker group..."
        sudo usermod -aG docker "$user_name"
        print_warning "Group membership active after logout/login or: newgrp docker"
    fi
    
    # Verify installation
    print_step "Verifying Docker installation..."
    if sudo docker --version && sudo docker compose version; then
        print_success "Docker and Docker Compose are working"
    else
        die "Docker installation verification failed"
    fi
    
    # Ensure package manager is in good state
    sudo dpkg --configure -a 2>/dev/null || true
    
    echo
}

#############################################################################
# Show Summary                                                              #
#############################################################################

show_summary() {
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "Docker Information"
    print_kv "Docker Version" "$(sudo docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')"
    print_kv "Compose Version" "$(sudo docker compose version 2>/dev/null | cut -d' ' -f4)"
    print_kv "User" "$(id -un)"
    print_kv "Docker Group" "$(id -nG | tr ' ' '\n' | grep -q docker && echo 'member' || echo 'pending logout')"
    
    echo
    print_header "Next Steps"
    print_info "To use Docker without sudo in your current session:"
    echo
    printf "  %b\n" "${C_DIM}# Option 1: Log out and back in${C_RESET}"
    printf "  %b\n" "${C_CYAN}logout${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Option 2: Activate group in current shell${C_RESET}"
    printf "  %b\n" "${C_CYAN}newgrp docker${C_RESET}"
    
    echo
    print_header "Useful Commands"
    printf "  %b\n" "${C_DIM}# Test Docker${C_RESET}"
    printf "  %b\n" "${C_CYAN}docker run hello-world${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Check Docker status${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl status docker${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View running containers${C_RESET}"
    printf "  %b\n" "${C_CYAN}docker ps${C_RESET}"
    
    echo
    print_header "File Locations"
    print_kv "GPG Key" "/etc/apt/keyrings/docker.gpg"
    print_kv "Repository" "/etc/apt/sources.list.d/docker.list"
    print_kv "Docker Root" "/var/lib/docker"
    
    echo
    draw_separator
    echo
}

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restarted unattended-upgrades service"
        fi
    fi
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Clear screen if running directly
    [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
    
    draw_box "Docker + Compose (v2) Installer v${SCRIPT_VERSION}"
    
    # Check if Docker is already fully installed and working
    if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        echo
        print_success "Docker is already installed and running"
        echo
        
        print_header "Current Installation"
        print_kv "Docker Version" "$(sudo docker --version | cut -d' ' -f3 | tr -d ',')"
        print_kv "Compose Version" "$(sudo docker compose version | cut -d' ' -f4)"
        
        echo
        print_header "Useful Commands"
        printf "  %b\n" "${C_DIM}# Test Docker${C_RESET}"
        printf "  %b\n" "${C_CYAN}docker run hello-world${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# Check Docker status${C_RESET}"
        printf "  %b\n" "${C_CYAN}sudo systemctl status docker${C_RESET}"
        echo
        printf "  %b\n" "${C_DIM}# View running containers${C_RESET}"
        printf "  %b\n" "${C_CYAN}docker ps${C_RESET}"
        
        echo
        print_info "Docker is ready to use. No action needed."
        echo
        exit 0
    fi
    
    # Run installation steps
    preflight_checks
    install_prerequisites
    install_docker
    show_summary
    
    # Restore any services we stopped
    cleanup
}

# Run main function
main "$@"
