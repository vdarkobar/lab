#!/bin/bash
readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="bookstack"

# Handle --help early (before defining functions)
case "${1:-}" in
    --help|-h)
        echo "BookStack Wiki Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help] [--status] [--logs [N]] [--configure] [--uninstall]"
        echo
        echo "Requirements:"
        echo "  - Must run as NON-ROOT user with sudo privileges"
        echo "  - Do NOT run with: sudo $0"
        echo "  - Debian 13 (Trixie) required"
        echo "  - Fresh server (no existing Apache/MySQL)"
        echo "  - Internet connectivity required"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"BookStack Wiki\""
        echo "  OR run standalone after hardening"
        echo
        echo "What it does:"
        echo "  - Installs Apache, PHP 8.4, MariaDB"
        echo "  - Clones BookStack from official repository"
        echo "  - Configures database and application"
        echo "  - Sets up Apache virtual host"
        echo "  - Configures UFW firewall rules"
        echo
        echo "Environment variables:"
        echo "  BOOKSTACK_DOMAIN          Domain or IP to host BookStack (required for silent)"
        echo "  BOOKSTACK_DIR             Install directory (default: /var/www/bookstack)"
        echo "  BOOKSTACK_SILENT=true     Non-interactive mode"
        echo "  BOOKSTACK_SKIP_UFW=true   Skip firewall configuration"
        echo "  BOOKSTACK_SKIP_REBOOT=true  Skip reboot prompt"
        echo
        echo "Post-install commands:"
        echo "  --status      Show BookStack status and access info"
        echo "  --logs [N]    Show last N lines of Apache logs (default: 50)"
        echo "  --configure   Reconfigure domain and restart services"
        echo "  --uninstall   Remove BookStack and clean up"
        echo
        echo "Network requirements:"
        echo "  Inbound 80/tcp    HTTP access (BookStack web interface)"
        echo
        echo "Files created:"
        echo "  /var/www/bookstack/              Application directory"
        echo "  /etc/apache2/sites-enabled/      Virtual host config"
        echo "  /var/log/lab/bookstack-*.log     Installation logs"
        echo
        echo "Default credentials (change immediately!):"
        echo "  Email:    admin@admin.com"
        echo "  Password: password"
        echo
        echo "Examples:"
        echo "  # Interactive installation"
        echo "  ./bookstack.sh"
        echo
        echo "  # Automated installation"
        echo "  BOOKSTACK_DOMAIN=\"wiki.example.com\" BOOKSTACK_SILENT=true ./bookstack.sh"
        exit 0
        ;;
esac

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Track services we stop (to restart on cleanup)
UNATTENDED_UPGRADES_WAS_ACTIVE=false

# BookStack configuration (env overrides)
BOOKSTACK_DOMAIN="${BOOKSTACK_DOMAIN:-}"
BOOKSTACK_DIR="${BOOKSTACK_DIR:-/var/www/bookstack}"
BOOKSTACK_SILENT="${BOOKSTACK_SILENT:-false}"; SILENT="$BOOKSTACK_SILENT"
BOOKSTACK_SKIP_UFW="${BOOKSTACK_SKIP_UFW:-false}"; SKIP_FIREWALL="$BOOKSTACK_SKIP_UFW"
BOOKSTACK_SKIP_REBOOT="${BOOKSTACK_SKIP_REBOOT:-false}"

# Database configuration (generated during install)
readonly DB_NAME="bookstack"
readonly DB_USER="bookstack"
DB_PASS=""  # Generated later

# Composer env
export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_NO_INTERACTION=1
export COMPOSER_DISABLE_XDEBUG_WARN=1

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"

#############################################################################
# Terminal Formatting (embedded - no external dependency)                   #
#############################################################################

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    COLORS_SUPPORTED=true
    
    readonly C_RESET=$(tput sgr0)
    readonly C_BOLD=$(tput bold)
    readonly C_DIM=$(tput dim)
    
    readonly C_RED=$(tput setaf 1)
    readonly C_GREEN=$(tput setaf 2)
    readonly C_YELLOW=$(tput setaf 3)
    readonly C_BLUE=$(tput setaf 4)
    readonly C_CYAN=$(tput setaf 6)
    readonly C_WHITE=$(tput setaf 7)
    
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
# Spinner Characters (optional - only needed if run_with_spinner is used)  #
#############################################################################

if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    readonly SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
else
    readonly SPINNER_CHARS='|/-\'
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

log() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Write plain text to log file (strip ANSI color codes)
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" || -w "$(dirname "${LOG_FILE:-/tmp}")" ]]; then
        echo "[$timestamp] [$level] $message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    # Display to console with formatting
    case "$level" in
        SUCCESS) print_success "$message" ;;
        ERROR)   print_error "$message" ;;
        WARN)    print_warning "$message" ;;
        INFO)    print_info "$message" ;;
        STEP)    print_step "$message" ;;
        *)       echo "$message" ;;
    esac
}

die() {
    local msg="$*"
    log ERROR "$msg"
    exit 1
}

setup_logging() {
    # Note: sudo existence check should be done BEFORE calling this function
    
    # Create log directory with sudo
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
    fi
    
    # Create log file and set ownership to current user
    sudo touch "$LOG_FILE" 2>/dev/null || true
    sudo chown "$(whoami):$(id -gn)" "$LOG_FILE" 2>/dev/null || true
    sudo chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    log INFO "=== ${SCRIPT_NAME} Started ==="
    log INFO "Version: $SCRIPT_VERSION"
    log INFO "User: $(whoami)"
    log INFO "Date: $(date)"
}

# Error trap for better debugging (set after print_error is defined)
trap 'print_error "Error at line $LINENO: $BASH_COMMAND"; log ERROR "Error at line $LINENO: $BASH_COMMAND"' ERR

#############################################################################
# Cleanup / Restore Services                                                #
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Restart unattended-upgrades if we stopped it
    if [[ "$UNATTENDED_UPGRADES_WAS_ACTIVE" == true ]]; then
        if sudo systemctl start unattended-upgrades 2>/dev/null; then
            print_info "Restarted unattended-upgrades service"
        fi
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

#############################################################################
# Helper Functions                                                          #
#############################################################################

is_silent() {
    [[ "${SILENT:-false}" == "true" ]]
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

# Uses ip route first, hostname -I as fallback
get_local_ip() {
    local ip_address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [[ -z "$ip_address" ]] && ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip_address=${ip_address:-"localhost"}
    echo "$ip_address"
}

generate_password() {
    local length="${1:-16}"
    local password=""
    while [[ ${#password} -lt $length ]]; do
        password+=$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' 2>/dev/null || true)
    done
    printf '%s' "${password:0:$length}"
}

#############################################################################
# Spinner for Long Operations (optional)                                    #
#############################################################################

# Run a command with an animated spinner, elapsed timer, and log capture.
# All command output is redirected to LOG_FILE. Console shows a spinner
# that resolves to ✓/✗ on completion with elapsed time.
#
# Usage:
#   if ! run_with_spinner "Installing packages" sudo apt-get install -y pkg; then
#       die "Failed to install packages"
#   fi
#
# Notes:
#   - Command runs in a background subshell (trap ERR does not fire for it)
#   - Safe with set -e: uses 'wait || exit_code=$?' to prevent errexit from
#     killing the function before cleanup (temp file removal, log capture)
#   - Exit code is preserved and returned to caller
#   - Falls back to running without spinner if mktemp fails

run_with_spinner() {
    local msg="$1"
    shift
    local pid tmp_out exit_code=0
    local spin_idx=0 start_ts now_ts elapsed

    tmp_out="$(mktemp)" || { log WARN "mktemp failed, running without spinner"; "$@"; return $?; }
    start_ts="$(date +%s)"

    log STEP "$msg" 2>/dev/null || true

    # Run command in background, capture all output
    "$@" >"$tmp_out" 2>&1 &
    pid=$!

    # Show spinner while command runs
    printf "  %s " "$msg"
    while kill -0 "$pid" 2>/dev/null; do
        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        printf "\r  %s %s (%ds)" "$msg" "${SPINNER_CHARS:spin_idx++%${#SPINNER_CHARS}:1}" "$elapsed"
        sleep 0.1
    done

    # Capture exit code (|| prevents set -e from killing before cleanup)
    wait "$pid" || exit_code=$?

    # Append command output to log file
    if [[ -n "${LOG_FILE:-}" ]] && [[ -w "${LOG_FILE:-}" ]]; then
        cat "$tmp_out" >> "$LOG_FILE" 2>/dev/null || true
    fi
    rm -f "$tmp_out"

    # Show result with elapsed time
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [[ $exit_code -eq 0 ]]; then
        printf "\r  %s %s (%ds)\n" "$msg" "${C_GREEN}${SYMBOL_SUCCESS}${C_RESET}" "$elapsed"
    else
        printf "\r  %s %s (%ds)\n" "$msg" "${C_RED}${SYMBOL_ERROR}${C_RESET}" "$elapsed"
    fi

    return $exit_code
}

#############################################################################
# APT Lock Handling                                                         #
#############################################################################

prepare_apt() {
    # Stop unattended-upgrades to avoid apt locks (best-effort)
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        UNATTENDED_UPGRADES_WAS_ACTIVE=true
        sudo systemctl stop unattended-upgrades 2>/dev/null || true
        print_info "Temporarily stopped unattended-upgrades"
    fi
    
    # Wait for dpkg lock (best-effort)
    local wait_count=0
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt/dpkg lock..."
        fi
        wait_count=$((wait_count + 1))
        sleep 2
        if [[ $wait_count -ge 60 ]]; then
            print_warning "Still waiting for apt lock (60s+) — continuing anyway"
            break
        fi
    done
}

#############################################################################
# Pre-flight Checks                                                         #
#############################################################################

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
    
    # sudo must exist on minimal images
    if ! command -v sudo >/dev/null 2>&1; then
        echo
        print_error "sudo is not installed. This script requires sudo."
        echo
        print_info "Fix (run as root):"
        echo "  apt-get update && apt-get install -y sudo"
        echo "  usermod -aG sudo $(whoami)"
        echo "  # then logout/login"
        echo
        die "Execution blocked: sudo not installed"
    fi
    
    # Verify sudo access (may prompt)
    if ! sudo -v 2>/dev/null; then
        echo
        print_error "User $(whoami) does not have sudo privileges"
        echo
        print_info "To grant sudo access (run as root):"
        echo "  ${C_CYAN}usermod -aG sudo $(whoami)${C_RESET}"
        echo "  ${C_CYAN}# then logout/login${C_RESET}"
        echo
        die "Execution blocked: No sudo privileges"
    fi
    print_success "Sudo privileges confirmed"
    
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command_exists pveversion; then
        die "This script must not run on the Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on Proxmox host"
    
    # Check for systemd (required)
    if ! command_exists systemctl; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    print_success "systemd available"
    
    # Check OS (warn if not Debian, note PHP 8.4 dependency)
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${ID:-}" != "debian" ]]; then
            print_warning "Designed for Debian. Detected: ${ID:-unknown}"
        elif [[ "${VERSION_ID:-}" != "13" ]]; then
            print_warning "Designed for Debian 13 (Trixie). Detected: ${VERSION_ID:-unknown}"
            print_warning "PHP 8.4 packages may not be available on other versions"
        else
            print_success "Debian 13 (Trixie) detected: ${PRETTY_NAME:-Debian 13}"
        fi
    else
        print_warning "Cannot determine OS version (/etc/os-release missing)"
    fi
    
    # Fresh server checks (official BookStack requirement)
    if [[ -d "/etc/apache2/sites-enabled" ]] && [[ "$(ls -A /etc/apache2/sites-enabled 2>/dev/null)" ]]; then
        local sites_count
        sites_count=$(ls /etc/apache2/sites-enabled 2>/dev/null | wc -l)
        if [[ $sites_count -gt 1 ]] || [[ ! -f /etc/apache2/sites-enabled/000-default.conf ]]; then
            die "Existing Apache configuration found. This script requires a fresh server."
        fi
    fi
    
    if [[ -d "/var/lib/mysql" ]] && [[ "$(ls -A /var/lib/mysql 2>/dev/null)" ]]; then
        die "Existing MySQL/MariaDB data found (/var/lib/mysql). Fresh server required."
    fi
    
    if [[ -d "$BOOKSTACK_DIR" ]]; then
        die "Install directory already exists ($BOOKSTACK_DIR). Use --uninstall first or choose different directory."
    fi
    print_success "Fresh server checks passed"
    
    # Check internet connectivity (multiple methods for minimal systems)
    print_step "Testing internet connectivity..."
    local internet_ok=false
    
    if command_exists curl; then
        if curl -s --max-time 5 --head https://deb.debian.org >/dev/null 2>&1; then
            print_success "Internet connectivity verified (curl)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]] && command_exists wget; then
        if wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
            print_success "Internet connectivity verified (wget)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]]; then
        # Bash built-in TCP check (no external tools)
        if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/deb.debian.org/80' 2>/dev/null; then
            print_success "Internet connectivity verified (dev/tcp)"
            internet_ok=true
        fi
    fi
    
    if [[ "$internet_ok" == false ]]; then
        print_warning "Could not verify internet with available tools"
        print_info "Will verify connectivity during package installation..."
    fi
    
    echo
}

#############################################################################
# Get Domain/IP Configuration                                              #
#############################################################################

get_domain_configuration() {
    print_header "Domain Configuration"
    
    # Check if domain provided via environment
    if [[ -n "$BOOKSTACK_DOMAIN" ]]; then
        print_success "Using domain from environment: $BOOKSTACK_DOMAIN"
        log INFO "Domain provided via BOOKSTACK_DOMAIN: $BOOKSTACK_DOMAIN"
        echo
        return 0
    fi
    
    # In silent mode, domain is required
    if is_silent; then
        die "BOOKSTACK_DOMAIN is required for silent installation"
    fi
    
    # Interactive prompt
    local default_ip
    default_ip=$(get_local_ip)
    
    echo
    print_info "Enter the domain (or IP) to host BookStack on."
    print_subheader "If using a domain, ensure DNS is configured first."
    print_subheader "Press Enter to use the detected IP address."
    echo
    
    while true; do
        printf "%b" "${C_CYAN}Domain/IP [${default_ip}]: ${C_RESET}"
        read -r BOOKSTACK_DOMAIN
        
        # Use default if empty
        if [[ -z "$BOOKSTACK_DOMAIN" ]]; then
            BOOKSTACK_DOMAIN="$default_ip"
        fi
        
        # Confirm selection
        print_success "BookStack will be accessible at: http://${BOOKSTACK_DOMAIN}/"
        echo -n "${C_CYAN}Is this correct? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r confirm
        if [[ "$confirm" =~ ^[Yy] ]] || [[ -z "$confirm" ]]; then
            break
        fi
    done
    
    log INFO "Domain configured: $BOOKSTACK_DOMAIN"
    echo
}

#############################################################################
# Display Introduction                                                      #
#############################################################################

show_intro() {
    draw_box "BookStack Wiki Installer v${SCRIPT_VERSION}"
    
    echo
    print_warning "This script is NOT officially supported by BookStack!"
    print_warning "Only Ubuntu LTS scripts are officially supported."
    
    echo
    print_header "System Information"
    print_kv "IP Address" "$(get_local_ip)"
    print_kv "Hostname" "$(hostname -s)"
    print_kv "Executing User" "$(whoami)"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_kv "OS" "${PRETTY_NAME:-$ID}"
    fi
    
    echo
    print_header "Installation Steps"
    print_subheader "Install Apache, PHP 8.4, MariaDB"
    print_subheader "Create database and user"
    print_subheader "Clone BookStack repository"
    print_subheader "Configure application"
    print_subheader "Set up Apache virtual host"
    print_subheader "Configure firewall (UFW)"
    
    echo
    print_header "Requirements"
    print_warning "Script must run as non-root user (currently: $(whoami))"
    print_warning "User must have sudo privileges"
    print_warning "Fresh server required (no existing Apache/MySQL)"
    
    echo
    print_info "Logs will be saved to: ${C_DIM}${LOG_FILE}${C_RESET}"
    echo
}

#############################################################################
# Confirm Installation                                                      #
#############################################################################

confirm_start() {
    if is_silent; then
        log INFO "Silent mode - skipping confirmation"
        return 0
    fi
    
    draw_separator
    echo
    while true; do
        echo -n "${C_BOLD}${C_CYAN}Proceed with installation? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
        read -r choice
        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        
        case "$choice" in
            yes|y)
                log INFO "User confirmed, starting installation..."
                echo
                return 0
                ;;
            no|n)
                print_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                print_error "Invalid input. Please enter 'yes' or 'no'"
                ;;
        esac
    done
}

#############################################################################
# Install System Packages                                                   #
#############################################################################

install_packages() {
    print_header "Installing System Packages"
    
    prepare_apt
    
    # Update package lists
    if ! run_with_spinner "Updating package lists" sudo apt-get update -y; then
        die "Failed to update package lists"
    fi
    
    # Install packages
    local packages=(
        git
        unzip
        curl
        apache2
        mariadb-server
        php8.4
        php8.4-fpm
        php8.4-curl
        php8.4-mbstring
        php8.4-ldap
        php8.4-xml
        php8.4-zip
        php8.4-gd
        php8.4-mysql
    )
    
    print_subheader "${C_DIM}${packages[*]}${C_RESET}"
    if ! run_with_spinner "Installing packages" sudo apt-get install -y -q "${packages[@]}"; then
        die "Failed to install packages"
    fi
    
    log SUCCESS "All packages installed successfully"
    echo
}

#############################################################################
# Configure Database                                                        #
#############################################################################

configure_database() {
    print_header "Configuring Database"
    
    # Generate database password
    DB_PASS=$(generate_password 16)
    
    # Start MariaDB if not running
    print_step "Starting MariaDB service..."
    if ! sudo systemctl start mariadb.service; then
        die "Failed to start MariaDB"
    fi
    sleep 3
    
    # Create database and user
    print_step "Creating database and user..."
    
    if ! sudo mysql -u root --execute="CREATE DATABASE ${DB_NAME};" >> "$LOG_FILE" 2>&1; then
        die "Failed to create database"
    fi
    
    if ! sudo mysql -u root --execute="CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';" >> "$LOG_FILE" 2>&1; then
        die "Failed to create database user"
    fi
    
    if ! sudo mysql -u root --execute="GRANT ALL ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;" >> "$LOG_FILE" 2>&1; then
        die "Failed to grant database privileges"
    fi
    
    log SUCCESS "Database configured: ${DB_NAME}"
    print_kv "Database" "$DB_NAME"
    print_kv "User" "$DB_USER"
    print_kv "Password" "${DB_PASS:0:4}****"
    
    echo
}

#############################################################################
# Download BookStack                                                        #
#############################################################################

download_bookstack() {
    print_header "Downloading BookStack"
    
    # Create parent directory
    sudo mkdir -p "$(dirname "$BOOKSTACK_DIR")"
    
    # Clone repository
    if ! run_with_spinner "Cloning BookStack repository" sudo git clone \
        https://github.com/BookStackApp/BookStack.git \
        --branch release --single-branch "$BOOKSTACK_DIR"; then
        die "Failed to clone BookStack repository"
    fi
    
    log SUCCESS "BookStack downloaded to: $BOOKSTACK_DIR"
    echo
}

#############################################################################
# Configure BookStack                                                       #
#############################################################################

configure_bookstack() {
    print_header "Configuring BookStack"
    
    # Download vendor files using BookStack's built-in tool
    if ! run_with_spinner "Downloading PHP dependencies" sudo bash -lc \
        "cd '$BOOKSTACK_DIR' && COMPOSER_NO_INTERACTION=1 COMPOSER_ALLOW_SUPERUSER=1 php bookstack-system-cli download-vendor"; then
        die "Failed to download vendor files"
    fi
    
    # Create .env file
    print_step "Creating environment configuration..."
    sudo cp "$BOOKSTACK_DIR/.env.example" "$BOOKSTACK_DIR/.env"
    
    # Update .env settings
    sudo sed -i "s@APP_URL=.*\$@APP_URL=http://${BOOKSTACK_DOMAIN}@" "$BOOKSTACK_DIR/.env"
    sudo sed -i "s@DB_DATABASE=.*\$@DB_DATABASE=${DB_NAME}@" "$BOOKSTACK_DIR/.env"
    sudo sed -i "s@DB_USERNAME=.*\$@DB_USERNAME=${DB_USER}@" "$BOOKSTACK_DIR/.env"
    sudo sed -i "s@DB_PASSWORD=.*\$@DB_PASSWORD=${DB_PASS}@" "$BOOKSTACK_DIR/.env"
    
    # Generate application key
    print_step "Generating application key..."
    if ! sudo bash -lc "cd '$BOOKSTACK_DIR' && php artisan key:generate --no-interaction --force" >> "$LOG_FILE" 2>&1; then
        die "Failed to generate application key"
    fi
    print_success "Application key generated"
    
    # Run database migrations
    if ! run_with_spinner "Running database migrations" sudo bash -lc \
        "cd '$BOOKSTACK_DIR' && php artisan migrate --no-interaction --force"; then
        die "Failed to run database migrations"
    fi
    
    log SUCCESS "BookStack configured"
    echo
}

#############################################################################
# Set File Permissions                                                      #
#############################################################################

set_permissions() {
    print_header "Setting File Permissions"
    
    local script_user="${SUDO_USER:-$(whoami)}"
    
    print_step "Setting ownership and permissions..."
    
    # Set ownership (user:www-data)
    sudo chown -R "${script_user}:www-data" "$BOOKSTACK_DIR"
    
    # Set base permissions
    sudo chmod -R 755 "$BOOKSTACK_DIR"
    
    # Set writable directories
    sudo chmod -R 775 "$BOOKSTACK_DIR/bootstrap/cache"
    sudo chmod -R 775 "$BOOKSTACK_DIR/public/uploads"
    sudo chmod -R 775 "$BOOKSTACK_DIR/storage"
    
    # Secure .env file
    sudo chmod 740 "$BOOKSTACK_DIR/.env"
    
    # Disable git filemode tracking
    sudo bash -lc "cd '$BOOKSTACK_DIR' && git config core.fileMode false"
    
    log SUCCESS "File permissions configured"
    print_kv "Owner" "${script_user}:www-data"
    
    echo
}

#############################################################################
# Configure Apache                                                          #
#############################################################################

configure_apache() {
    print_header "Configuring Apache"
    
    # Enable required modules
    print_step "Enabling Apache modules..."
    sudo a2enmod rewrite proxy_fcgi setenvif >> "$LOG_FILE" 2>&1
    sudo a2enconf php8.4-fpm >> "$LOG_FILE" 2>&1
    
    # Create virtual host configuration
    print_step "Creating virtual host configuration..."
    
    sudo tee /etc/apache2/sites-available/bookstack.conf > /dev/null << EOF
<VirtualHost *:80>
    ServerName ${BOOKSTACK_DOMAIN}

    ServerAdmin webmaster@localhost
    DocumentRoot ${BOOKSTACK_DIR}/public/

    <Directory ${BOOKSTACK_DIR}/public/>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
        <IfModule mod_rewrite.c>
            <IfModule mod_negotiation.c>
                Options -MultiViews -Indexes
            </IfModule>

            RewriteEngine On

            # Handle Authorization Header
            RewriteCond %{HTTP:Authorization} .
            RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

            # Redirect Trailing Slashes If Not A Folder...
            RewriteCond %{REQUEST_FILENAME} !-d
            RewriteCond %{REQUEST_URI} (.+)/\$
            RewriteRule ^ %1 [L,R=301]

            # Handle Front Controller...
            RewriteCond %{REQUEST_FILENAME} !-d
            RewriteCond %{REQUEST_FILENAME} !-f
            RewriteRule ^ index.php [L]
        </IfModule>
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/bookstack_error.log
    CustomLog \${APACHE_LOG_DIR}/bookstack_access.log combined

</VirtualHost>
EOF
    
    # Enable site and disable default
    print_step "Enabling BookStack site..."
    sudo a2dissite 000-default.conf >> "$LOG_FILE" 2>&1 || true
    sudo a2ensite bookstack.conf >> "$LOG_FILE" 2>&1
    
    # Restart services
    if ! run_with_spinner "Restarting Apache" sudo systemctl restart apache2; then
        die "Failed to restart Apache"
    fi
    
    if ! run_with_spinner "Starting PHP-FPM" sudo systemctl start php8.4-fpm.service; then
        die "Failed to start PHP-FPM"
    fi
    
    log SUCCESS "Apache configured"
    echo
}

#############################################################################
# Configure Firewall                                                        #
#############################################################################

configure_ufw() {
    print_header "Configuring Firewall"
    
    # Skip if env var set
    if [[ "${SKIP_FIREWALL:-false}" == "true" ]]; then
        log INFO "Firewall configuration skipped (BOOKSTACK_SKIP_UFW=true)"
        echo
        return 0
    fi
    
    # Test if UFW is available and functional
    local ufw_status
    if ! ufw_status=$(sudo ufw status 2>&1); then
        log WARN "UFW not available or not functional"
        log INFO "Output: $ufw_status"
        log INFO "Configure firewall on the host instead"
        log INFO "Required port: 80/tcp"
        echo
        return 0
    fi
    
    # Check if UFW is active
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        log INFO "UFW is not active - skipping firewall configuration"
        log INFO "To enable UFW manually: sudo ufw enable"
        echo
        return 0
    fi
    
    log SUCCESS "UFW is active"
    print_step "Adding firewall rules..."
    
    # Allow HTTP
    if echo "$ufw_status" | grep -qE "80/tcp.*ALLOW"; then
        log SUCCESS "Port 80/tcp already allowed"
    else
        if sudo ufw allow 80/tcp comment "BookStack HTTP" >/dev/null 2>&1; then
            log SUCCESS "Allowed port 80/tcp (BookStack HTTP)"
        else
            # Fallback: try without comment for older UFW versions
            if sudo ufw allow 80/tcp >/dev/null 2>&1; then
                log SUCCESS "Allowed port 80/tcp"
            else
                log WARN "Failed to add UFW rule for port 80/tcp"
            fi
        fi
    fi
    
    log SUCCESS "Firewall configuration complete"
    echo
}

#############################################################################
# Installation Summary                                                      #
#############################################################################

show_summary() {
    local ip_address
    ip_address=$(get_local_ip)
    
    echo
    draw_box "Installation Complete"
    
    echo
    print_header "BookStack Access Information"
    if [[ "$ip_address" == "$BOOKSTACK_DOMAIN" ]]; then
        print_kv "URL" "http://${ip_address}/"
    else
        print_kv "URL" "http://${BOOKSTACK_DOMAIN}/"
        print_kv "IP Access" "http://${ip_address}/"
    fi
    
    echo
    print_header "Default Login Credentials"
    print_kv "Email" "admin@admin.com"
    print_kv "Password" "password"
    print_warning "Change these credentials immediately after first login!"
    
    echo
    print_header "Database Information"
    print_kv "Database" "$DB_NAME"
    print_kv "User" "$DB_USER"
    print_kv "Password" "$DB_PASS"
    
    echo
    print_header "File Locations"
    print_kv "Application" "$BOOKSTACK_DIR"
    print_kv "Config File" "$BOOKSTACK_DIR/.env"
    print_kv "Apache Config" "/etc/apache2/sites-enabled/bookstack.conf"
    print_kv "Installation Log" "$LOG_FILE"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# Check status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure domain${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart services${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart apache2 php8.4-fpm${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Update BookStack${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd $BOOKSTACK_DIR && sudo git pull && sudo php artisan migrate --force${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --uninstall${C_RESET}"
    
    echo
    draw_separator
    echo
}

#############################################################################
# Prompt for Reboot                                                         #
#############################################################################

prompt_reboot() {
    if [[ "$BOOKSTACK_SKIP_REBOOT" == "true" ]]; then
        return 0
    fi
    
    if is_silent; then
        return 0
    fi
    
    echo
    print_info "A reboot is recommended but optional."
    while true; do
        echo -n "${C_CYAN}Reboot now? ${C_RESET}${C_DIM}(yes/no) [no]${C_RESET} "
        read -r response
        response="${response:-no}"
        
        case "${response,,}" in
            yes|y)
                print_info "Rebooting..."
                sudo reboot
                exit 0
                ;;
            no|n)
                print_info "Reboot skipped"
                break
                ;;
            *)
                print_error "Please answer yes or no"
                ;;
        esac
    done
}

#############################################################################
# Post-Install Commands                                                     #
#############################################################################

cmd_status() {
    print_header "BookStack Status"
    
    # Check if installed
    if [[ ! -d "$BOOKSTACK_DIR" ]]; then
        die "BookStack is not installed at $BOOKSTACK_DIR"
    fi
    
    # Get configuration
    local app_url=""
    if [[ -f "$BOOKSTACK_DIR/.env" ]]; then
        app_url=$(grep -E "^APP_URL=" "$BOOKSTACK_DIR/.env" | cut -d= -f2)
    fi
    
    print_kv "Install Directory" "$BOOKSTACK_DIR"
    print_kv "URL" "${app_url:-unknown}"
    
    # Service status
    echo
    print_header "Service Status"
    
    if service_is_active apache2; then
        print_success "Apache: running"
    else
        print_warning "Apache: not running"
    fi
    
    if service_is_active php8.4-fpm; then
        print_success "PHP-FPM: running"
    else
        print_warning "PHP-FPM: not running"
    fi
    
    if service_is_active mariadb; then
        print_success "MariaDB: running"
    else
        print_warning "MariaDB: not running"
    fi
    
    # Disk usage
    echo
    print_header "Disk Usage"
    local disk_usage
    disk_usage=$(du -sh "$BOOKSTACK_DIR" 2>/dev/null | cut -f1)
    print_kv "Application" "${disk_usage:-unknown}"
    
    echo
}

cmd_logs() {
    local lines="${1:-50}"
    
    print_header "BookStack Logs (last $lines lines)"
    echo
    
    print_subheader "Apache Error Log:"
    echo "${C_DIM}"
    sudo tail -n "$lines" /var/log/apache2/bookstack_error.log 2>/dev/null || \
        sudo tail -n "$lines" /var/log/apache2/error.log 2>/dev/null || \
        echo "  No error logs found"
    echo "${C_RESET}"
    
    echo
    print_subheader "Apache Access Log:"
    echo "${C_DIM}"
    sudo tail -n "$lines" /var/log/apache2/bookstack_access.log 2>/dev/null || \
        sudo tail -n "$lines" /var/log/apache2/access.log 2>/dev/null || \
        echo "  No access logs found"
    echo "${C_RESET}"
}

cmd_configure() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Reconfigure BookStack"
    
    if [[ ! -d "$BOOKSTACK_DIR" ]]; then
        die "BookStack is not installed at $BOOKSTACK_DIR"
    fi
    
    # Get current domain from .env
    local current_domain=""
    if [[ -f "$BOOKSTACK_DIR/.env" ]]; then
        current_domain=$(grep -E "^APP_URL=" "$BOOKSTACK_DIR/.env" | sed 's|APP_URL=http://||')
    fi
    
    print_warning "This will update the domain and restart services."
    print_info "Current configuration:"
    print_kv "Domain" "${current_domain:-unknown}"
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_CYAN}Continue? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Reconfiguration cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Get new domain (reuse existing function logic)
    if [[ -z "$BOOKSTACK_DOMAIN" ]]; then
        local default_ip
        default_ip=$(get_local_ip)
        echo
        printf "%b" "${C_CYAN}New domain/IP [${current_domain:-$default_ip}]: ${C_RESET}"
        read -r BOOKSTACK_DOMAIN
        BOOKSTACK_DOMAIN="${BOOKSTACK_DOMAIN:-${current_domain:-$default_ip}}"
    fi
    
    # Update .env
    print_step "Updating domain to: $BOOKSTACK_DOMAIN"
    sudo sed -i "s@APP_URL=.*\$@APP_URL=http://${BOOKSTACK_DOMAIN}@" "$BOOKSTACK_DIR/.env"
    
    # Update Apache vhost
    if [[ -f /etc/apache2/sites-available/bookstack.conf ]]; then
        sudo sed -i "s@ServerName .*@ServerName ${BOOKSTACK_DOMAIN}@" /etc/apache2/sites-available/bookstack.conf
    fi
    
    # Restart services
    print_step "Restarting services..."
    if sudo systemctl restart apache2 php8.4-fpm; then
        sleep 2
        if service_is_active apache2 && service_is_active php8.4-fpm; then
            log SUCCESS "BookStack reconfigured and running"
            print_kv "URL" "http://${BOOKSTACK_DOMAIN}/"
        else
            print_warning "Services may not be running correctly after restart"
        fi
    else
        print_error "Failed to restart services"
    fi
    
    echo
}

cmd_uninstall() {
    # Verify sudo access
    if ! sudo -v 2>/dev/null; then
        die "This operation requires sudo privileges"
    fi
    
    print_header "Uninstall BookStack"
    
    if [[ ! -d "$BOOKSTACK_DIR" ]]; then
        print_warning "BookStack directory not found: $BOOKSTACK_DIR"
    fi
    
    print_warning "This will remove:"
    print_subheader "BookStack application ($BOOKSTACK_DIR)"
    print_subheader "Apache configuration"
    print_subheader "Database and user (optional)"
    
    if ! is_silent; then
        echo
        while true; do
            echo -n "${C_BOLD}${C_RED}Are you sure? ${C_RESET}${C_DIM}(yes/no)${C_RESET} "
            read -r choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            
            case "$choice" in
                yes|y) break ;;
                no|n)
                    print_info "Uninstall cancelled"
                    exit 0
                    ;;
                *) print_error "Invalid input. Please enter 'yes' or 'no'" ;;
            esac
        done
    fi
    
    # Disable Apache site
    print_step "Disabling Apache site..."
    sudo a2dissite bookstack.conf 2>/dev/null || true
    sudo rm -f /etc/apache2/sites-available/bookstack.conf
    sudo systemctl reload apache2 2>/dev/null || true
    
    # Remove application directory
    print_step "Removing application directory..."
    sudo rm -rf "$BOOKSTACK_DIR"
    
    # Ask about database removal
    local remove_db=false
    if ! is_silent; then
        echo
        echo -n "${C_CYAN}Also remove database and user? ${C_RESET}${C_DIM}(yes/no) [no]${C_RESET} "
        read -r db_choice
        if [[ "$db_choice" =~ ^[Yy] ]]; then
            remove_db=true
        fi
    fi
    
    if [[ "$remove_db" == true ]]; then
        print_step "Removing database and user..."
        sudo mysql -u root --execute="DROP DATABASE IF EXISTS ${DB_NAME};" 2>/dev/null || true
        sudo mysql -u root --execute="DROP USER IF EXISTS '${DB_USER}'@'localhost';" 2>/dev/null || true
        print_success "Database removed"
    else
        print_info "Database retained: $DB_NAME"
    fi
    
    # Remove firewall rules (only if UFW active)
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        print_step "Removing firewall rules..."
        sudo ufw delete allow 80/tcp 2>/dev/null || true
    fi
    
    log SUCCESS "BookStack has been removed"
    echo
}

#############################################################################
# Show Already Installed Menu                                               #
#############################################################################

show_already_installed() {
    clear
    draw_box "BookStack - Already Installed"
    
    # Get configuration
    local app_url=""
    if [[ -f "$BOOKSTACK_DIR/.env" ]]; then
        app_url=$(grep -E "^APP_URL=" "$BOOKSTACK_DIR/.env" | cut -d= -f2)
    fi
    
    echo
    print_header "Current Installation"
    print_kv "Directory" "$BOOKSTACK_DIR"
    print_kv "URL" "${app_url:-unknown}"
    
    # Service status
    echo
    print_header "Service Status"
    service_is_active apache2 && print_success "Apache: running" || print_warning "Apache: not running"
    service_is_active php8.4-fpm && print_success "PHP-FPM: running" || print_warning "PHP-FPM: not running"
    service_is_active mariadb && print_success "MariaDB: running" || print_warning "MariaDB: not running"
    
    echo
    print_header "Management Commands"
    printf "  %b\n" "${C_DIM}# View status${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --status${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# View logs${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --logs${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Reconfigure domain${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --configure${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Restart services${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo systemctl restart apache2 php8.4-fpm${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Update BookStack${C_RESET}"
    printf "  %b\n" "${C_CYAN}cd $BOOKSTACK_DIR && sudo git pull origin release${C_RESET}"
    printf "  %b\n" "${C_CYAN}sudo php artisan migrate --force${C_RESET}"
    echo
    printf "  %b\n" "${C_DIM}# Uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --uninstall${C_RESET}"
    
    echo
    print_info "To reinstall, first uninstall the existing installation:"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh --uninstall${C_RESET}"
    printf "  %b\n" "${C_CYAN}./${SCRIPT_NAME}.sh${C_RESET}"
    echo
}

#############################################################################
# Main Execution                                                            #
#############################################################################

main() {
    # Handle post-install commands
    case "${1:-}" in
        --status)     cmd_status; exit 0 ;;
        --logs)       cmd_logs "${2:-50}"; exit 0 ;;
        --configure)  cmd_configure; exit 0 ;;
        --uninstall)  cmd_uninstall; exit 0 ;;
        --version|-v) echo "${SCRIPT_NAME}.sh v${SCRIPT_VERSION}"; exit 0 ;;
        "")           ;;  # Continue with installation
        *)            die "Unknown option: $1 (use --help for usage)" ;;
    esac
    
    # Early sudo check (before logging)
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed or not in PATH" >&2
        echo "This script requires sudo. Please install it first:" >&2
        echo "  apt update && apt install sudo" >&2
        exit 1
    fi
    
    if [[ ${EUID} -eq 0 ]]; then
        echo "ERROR: This script must NOT be run as root!" >&2
        echo "Run as a regular user with sudo privileges:" >&2
        echo "  ./$(basename "$0")" >&2
        exit 1
    fi
    
    if ! sudo -v 2>/dev/null; then
        echo "ERROR: Current user $(whoami) does not have sudo privileges" >&2
        echo "Please add user to sudo group:" >&2
        echo "  usermod -aG sudo $(whoami)" >&2
        echo "Then logout and login again" >&2
        exit 1
    fi
    
    # Check if BookStack is already installed
    if [[ -d "$BOOKSTACK_DIR" ]] && [[ -f "$BOOKSTACK_DIR/.env" ]]; then
        show_already_installed
        exit 0
    fi
    
    # Clear screen early (before any output)
    [[ -t 1 ]] && ! is_silent && clear
    
    # Show introduction (unless silent)
    if ! is_silent; then
        show_intro
    fi
    
    # Setup logging
    setup_logging
    
    # Run installation steps
    preflight_checks
    get_domain_configuration
    
    if ! is_silent; then
        confirm_start
    fi
    
    install_packages
    configure_database
    download_bookstack
    configure_bookstack
    set_permissions
    configure_apache
    configure_ufw
    
    # Show summary
    show_summary
    
    # Prompt for optional reboot
    prompt_reboot
    
    log INFO "=== BookStack Installation Completed ==="
}

main "$@"
