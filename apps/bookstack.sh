#!/bin/bash

#############################################################################
# BookStack Wiki Installer                                                  #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# Compatible with: Debian 13 (Trixie) only - VM/LXC                         #
#############################################################################

readonly SCRIPT_VERSION="1.0.0"

# Handle --help flag early (before sourcing libraries)
case "${1:-}" in
    --help|-h)
        echo "BookStack Wiki Installer v${SCRIPT_VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"BookStack Wiki\""
        echo
        echo "Interactive mode (default):"
        echo "  Prompts for domain/IP to host BookStack on"
        echo
        echo "Environment variables (for non-interactive/automation):"
        echo "  BOOKSTACK_DOMAIN   Domain or IP address (e.g., docs.example.com or 192.168.1.10)"
        echo "  SKIP_REBOOT        Skip reboot prompt (default: false)"
        echo "  QUIET_MODE         Minimal output (default: false)"
        echo
        echo "What it does:"
        echo "  - Installs Apache2, PHP 8.4-FPM, MariaDB"
        echo "  - Installs Composer (checksum-verified)"
        echo "  - Downloads and configures BookStack"
        echo "  - Creates database and user"
        echo "  - Configures Apache virtual host"
        echo "  - Opens firewall port 80"
        echo
        echo "Default credentials:"
        echo "  Email:    admin@admin.com"
        echo "  Password: changeme"
        echo
        echo "Files created:"
        echo "  /opt/bookstack                Application directory"
        echo "  /etc/apache2/sites-available/bookstack.conf  Apache vhost"
        echo "  /var/log/lab/bookstack.log   Installation log"
        echo
        echo "Post-install:"
        echo "  - Add TLS/HTTPS via reverse proxy or Certbot"
        echo "  - Update APP_URL in /opt/bookstack/.env"
        echo "  - Change default admin credentials"
        exit 0
        ;;
esac

set -euo pipefail

#############################################################################
# Resolve Script Directory and Load Formatting Library                      #
#############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)" || REPO_ROOT="$SCRIPT_DIR"

# Try multiple locations for formatting library
if [[ -f "$REPO_ROOT/lib/formatting.sh" ]]; then
    source "$REPO_ROOT/lib/formatting.sh"
elif [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
    source "$SCRIPT_DIR/../lib/formatting.sh"
elif [[ -f "$HOME/lab/lib/formatting.sh" ]]; then
    source "$HOME/lab/lib/formatting.sh"
else
    # Minimal fallback formatting
    print_header() { echo -e "\n━━━ $1 ━━━"; }
    print_success() { echo "✓ $1"; }
    print_error() { echo "✗ $1" >&2; }
    print_warning() { echo "⚠ $1"; }
    print_info() { echo "ℹ $1"; }
    print_step() { echo "→ $1"; }
    print_subheader() { echo "  • $1"; }
    print_kv() { printf "%-20s %s\n" "$1:" "$2"; }
    draw_separator() { echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
    draw_box() { echo -e "\n╔══════════════════════════════════════════════════════╗"; echo "║  $1"; echo "╚══════════════════════════════════════════════════════╝"; }
    die() { print_error "$1"; exit 1; }
fi

#############################################################################
# Configuration                                                             #
#############################################################################

# Defaults (can be overridden by environment variables)
BOOKSTACK_DOMAIN="${BOOKSTACK_DOMAIN:-}"
SKIP_REBOOT="${SKIP_REBOOT:-false}"
QUIET_MODE="${QUIET_MODE:-false}"

# Installation paths
readonly BOOKSTACK_DIR="/opt/bookstack"
readonly DB_NAME="bookstack_db"
readonly DB_USER="bookstack_user"

# Generate secure password
DB_PASS="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)"

# Logging
readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="$LOG_DIR/bookstack.log"

# Environment
export DEBIAN_FRONTEND=noninteractive

#############################################################################
# Sudo Helper (handles both root and non-root execution)                    #
#############################################################################

# Use sudo only when not root
SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

# Run command with output logged to LOG_FILE (works for non-root users)
run_logged() {
    # Usage: run_logged <cmd> [args...]
    if [[ -n "$SUDO" ]]; then
        "$@" 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
    else
        "$@" 2>&1 | tee -a "$LOG_FILE" >/dev/null
    fi
}

#############################################################################
# Logging Functions                                                         #
#############################################################################

setup_logging() {
    $SUDO mkdir -p "$LOG_DIR"
    $SUDO touch "$LOG_FILE"
    $SUDO chmod 644 "$LOG_FILE"
    echo "========================================" | $SUDO tee -a "$LOG_FILE" >/dev/null
    echo "bookstack.sh started at $(date)" | $SUDO tee -a "$LOG_FILE" >/dev/null
    echo "========================================" | $SUDO tee -a "$LOG_FILE" >/dev/null
}

log_msg() {
    local msg="$1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $msg" | $SUDO tee -a "$LOG_FILE" >/dev/null
    [[ "$QUIET_MODE" != "true" ]] && print_info "$msg"
}

#############################################################################
# Utility Functions                                                         #
#############################################################################

get_local_ip() {
    hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./) {print $i; exit}}'
}

cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        # Log failure (handle case where logging isn't set up yet)
        if [[ -f "$LOG_FILE" ]]; then
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Installation failed with exit code $exit_code" | \
                { if [[ -n "${SUDO:-}" ]]; then sudo tee -a "$LOG_FILE"; else tee -a "$LOG_FILE"; fi; } >/dev/null 2>&1 || true
        fi
        print_error "Installation failed - check log: $LOG_FILE"
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

#############################################################################
# Preflight Checks                                                          #
#############################################################################

preflight_checks() {
    print_header "Preflight Checks"
    
    # Check if running on PVE host (should not be)
    if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
        die "This script should not run on Proxmox VE host. Run inside a VM or LXC container."
    fi
    print_success "Not running on PVE host"
    
    # Check for sudo/root access
    if [[ $EUID -ne 0 ]]; then
        if ! command -v sudo &>/dev/null; then
            die "sudo is required but not installed"
        fi
        if ! sudo -v &>/dev/null; then
            die "User does not have sudo privileges"
        fi
        print_success "Running as non-root user: $(whoami)"
        print_success "sudo access verified"
    else
        print_success "Running as root"
    fi
    
    # Detect OS - require Debian 13 (Trixie) for PHP 8.4
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS - /etc/os-release not found"
    fi
    
    source /etc/os-release
    local os_id="${ID:-unknown}"
    local os_version="${VERSION_ID:-unknown}"
    
    if [[ "$os_id" != "debian" ]]; then
        die "Unsupported OS: $os_id (only Debian supported)"
    fi
    
    if [[ "$os_version" != "13" ]]; then
        die "Debian 13 (Trixie) required for PHP 8.4. Detected: Debian $os_version"
    fi
    print_success "Detected: ${PRETTY_NAME:-Debian $os_version}"
    
    # Check for existing installation (strict - any existing dir could be partial/dirty)
    if [[ -d "$BOOKSTACK_DIR" ]]; then
        die "Directory $BOOKSTACK_DIR already exists - aborting to avoid partial/dirty install"
    fi
    
    if [[ -d "/var/lib/mysql/${DB_NAME}" ]]; then
        die "BookStack database already exists - aborting to avoid data loss"
    fi
    
    # Check for systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd not found (is this container systemd-enabled?)"
    fi
    print_success "systemd available"
    
    echo
}

#############################################################################
# Interactive Configuration                                                 #
#############################################################################

configure_interactive() {
    print_header "Configuration"
    
    local ip
    ip="$(get_local_ip)"
    
    if [[ -z "$BOOKSTACK_DOMAIN" ]]; then
        echo
        print_info "Enter the domain (or IP) to host BookStack on"
        print_subheader "Examples: docs.example.com or ${ip:-<container-ip>}"
        echo
        read -rp "Domain/IP [default: ${ip:-localhost}]: " input
        BOOKSTACK_DOMAIN="${input:-${ip:-localhost}}"
    fi
    
    print_success "BookStack URL: http://$BOOKSTACK_DOMAIN"
    echo
}

#############################################################################
# Installation Functions                                                    #
#############################################################################

install_packages() {
    print_header "Installing Packages"
    
    # Stop unattended upgrades if running (it holds apt lock)
    print_subheader "Stopping unattended-upgrades if running..."
    $SUDO systemctl stop unattended-upgrades 2>/dev/null || true
    
    # Wait for any existing apt processes to finish
    local wait_count=0
    while $SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [[ $wait_count -eq 0 ]]; then
            print_subheader "Waiting for apt lock to be released..."
        fi
        sleep 2
        ((wait_count++))
        if [[ $wait_count -gt 30 ]]; then
            die "Timed out waiting for apt lock"
        fi
    done
    
    print_step "Updating package lists..."
    run_logged $SUDO apt-get update -y || die "apt-get update failed"
    
    print_step "Installing dependencies..."
    run_logged $SUDO apt-get install -y \
        ca-certificates curl git unzip tar openssl rsync \
        apache2 \
        mariadb-server \
        php8.4 php8.4-cli php8.4-fpm \
        php8.4-curl php8.4-mbstring php8.4-ldap php8.4-xml \
        php8.4-zip php8.4-gd php8.4-mysql php8.4-tidy php8.4-bz2 \
        || die "Failed to install packages"
    
    print_success "Packages installed"
}

install_composer() {
    print_header "Installing Composer"
    
    # Check if already installed
    if command -v composer &>/dev/null; then
        print_success "Composer already installed: $(composer --version 2>/dev/null | head -1)"
        return 0
    fi
    
    print_step "Downloading Composer installer..."
    local expected actual
    
    # Strip whitespace/newlines from signature (installer.sig often has trailing newline)
    expected="$(php -r 'copy("https://composer.github.io/installer.sig", "php://stdout");' | tr -d '\r\n[:space:]')"
    run_logged php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
    actual="$(php -r "echo hash_file('sha384', '/tmp/composer-setup.php');" | tr -d '\r\n[:space:]')"
    
    if [[ "$expected" != "$actual" ]]; then
        rm -f /tmp/composer-setup.php
        die "Composer installer checksum mismatch"
    fi
    print_success "Checksum verified"
    
    print_step "Installing Composer..."
    run_logged $SUDO php /tmp/composer-setup.php --quiet --install-dir=/usr/local/bin --filename=composer || die "Composer installation failed"
    rm -f /tmp/composer-setup.php
    
    print_success "Composer installed: $(composer --version 2>/dev/null | head -1)"
}

setup_mariadb() {
    print_header "Configuring MariaDB"
    
    print_step "Starting MariaDB service..."
    run_logged $SUDO systemctl enable --now mariadb.service || die "Failed to start MariaDB"
    print_success "MariaDB service running"
    
    print_step "Creating database and user..."
    run_logged $SUDO mysql -u root --execute="CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" || die "Failed to create database"
    run_logged $SUDO mysql -u root --execute="CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';" || die "Failed to create database user"
    run_logged $SUDO mysql -u root --execute="GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;" || die "Failed to grant privileges"
    print_success "Database configured"
    
    print_step "Securing MariaDB..."
    run_logged $SUDO mysql -u root --execute="DELETE FROM mysql.user WHERE User='';" || true
    run_logged $SUDO mysql -u root --execute="DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" || true
    run_logged $SUDO mysql -u root --execute="DROP DATABASE IF EXISTS test;" || true
    run_logged $SUDO mysql -u root --execute="DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
    run_logged $SUDO mysql -u root --execute="FLUSH PRIVILEGES;"
    print_success "MariaDB secured"
}

fetch_bookstack() {
    print_header "Fetching BookStack"
    
    print_step "Downloading BookStack release..."
    $SUDO rm -rf "$BOOKSTACK_DIR"
    $SUDO mkdir -p "$BOOKSTACK_DIR"
    
    run_logged curl -fsSL "https://github.com/BookStackApp/BookStack/archive/refs/heads/release.tar.gz" \
        -o /tmp/bookstack-release.tar.gz || die "Failed to download BookStack"
    
    print_step "Extracting archive..."
    run_logged tar -xzf /tmp/bookstack-release.tar.gz -C /tmp || die "Failed to extract archive"
    
    local extracted
    extracted="$(find /tmp -maxdepth 1 -type d -name 'BookStack-release*' | head -n1)"
    if [[ -z "$extracted" ]]; then
        die "Failed to find extracted BookStack directory"
    fi
    
    run_logged $SUDO rsync -a "${extracted}/" "${BOOKSTACK_DIR}/" || die "Failed to deploy BookStack"
    rm -rf /tmp/bookstack-release.tar.gz "$extracted"
    
    print_success "BookStack deployed to ${BOOKSTACK_DIR}"
}

configure_bookstack() {
    print_header "Configuring BookStack"
    
    cd "$BOOKSTACK_DIR"
    
    print_step "Creating environment configuration..."
    $SUDO cp .env.example .env
    
    $SUDO sed -i "s|^APP_URL=.*|APP_URL=http://${BOOKSTACK_DOMAIN}|g" .env
    $SUDO sed -i "s|^DB_DATABASE=.*|DB_DATABASE=${DB_NAME}|g" .env
    $SUDO sed -i "s|^DB_USERNAME=.*|DB_USERNAME=${DB_USER}|g" .env
    $SUDO sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=${DB_PASS}|g" .env
    print_success "Environment file configured"
    
    print_step "Installing PHP dependencies (this may take a while)..."
    # COMPOSER_ALLOW_SUPERUSER must be passed via env to survive sudo
    run_logged $SUDO env COMPOSER_ALLOW_SUPERUSER=1 composer install \
        --no-dev --no-interaction --prefer-dist \
        --working-dir="$BOOKSTACK_DIR" || die "Composer install failed"
    print_success "Dependencies installed"
    
    print_step "Generating application key..."
    run_logged $SUDO php artisan key:generate --no-interaction --force || die "Failed to generate app key"
    print_success "Application key generated"
    
    print_step "Running database migrations..."
    run_logged $SUDO php artisan migrate --no-interaction --force || die "Database migration failed"
    print_success "Database migrations completed"
    
    print_step "Setting permissions..."
    $SUDO chown -R www-data:www-data "$BOOKSTACK_DIR"
    $SUDO chmod -R 755 "$BOOKSTACK_DIR"
    $SUDO chmod -R 775 "$BOOKSTACK_DIR/storage" "$BOOKSTACK_DIR/bootstrap/cache" "$BOOKSTACK_DIR/public/uploads"
    $SUDO chmod 640 "$BOOKSTACK_DIR/.env"
    print_success "Permissions configured"
}

configure_php() {
    print_header "Configuring PHP"
    
    # Set reasonable upload limits for BookStack attachments
    local php_ini="/etc/php/8.4/fpm/conf.d/99-bookstack.ini"
    
    print_step "Creating PHP configuration..."
    $SUDO tee "$php_ini" >/dev/null <<'EOF'
; BookStack PHP settings
upload_max_filesize = 50M
post_max_size = 50M
memory_limit = 256M
max_execution_time = 60
EOF
    
    print_success "PHP configured (upload limit: 50MB)"
}

configure_apache() {
    print_header "Configuring Apache"
    
    print_step "Enabling Apache modules..."
    run_logged $SUDO a2enmod rewrite proxy_fcgi setenvif || die "Failed to enable Apache modules"
    run_logged $SUDO a2enconf php8.4-fpm || die "Failed to enable PHP-FPM config"
    print_success "Apache modules enabled"
    
    print_step "Creating virtual host..."
    $SUDO tee /etc/apache2/sites-available/bookstack.conf >/dev/null <<EOF
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
            RewriteCond %{REQUEST_URI} (.+)/$
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
    print_success "Virtual host created"
    
    print_step "Enabling site..."
    run_logged $SUDO a2ensite bookstack.conf || die "Failed to enable site"
    $SUDO a2dissite 000-default.conf 2>/dev/null || true
    print_success "Site enabled"
    
    print_step "Validating Apache configuration..."
    if ! run_logged $SUDO apache2ctl configtest; then
        die "Apache configuration test failed"
    fi
    print_success "Apache configuration valid"
}

configure_firewall() {
    print_header "Configuring Firewall"
    
    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        print_warning "UFW not installed - skipping firewall configuration"
        return 0
    fi
    
    # Test if UFW is functional (may fail in unprivileged containers)
    if ! $SUDO ufw status >/dev/null 2>&1; then
        print_warning "UFW not functional in this environment"
        print_info "Configure firewall on the host instead"
        print_info "Required port: 80/tcp"
        return 0
    fi
    
    # Check if UFW is active
    if ! $SUDO ufw status | grep -q "Status: active"; then
        print_warning "UFW not active - skipping firewall configuration"
        return 0
    fi
    
    print_step "Opening port 80/tcp..."
    if run_logged $SUDO ufw allow 80/tcp comment 'BookStack HTTP'; then
        print_success "Port 80/tcp opened"
    else
        print_warning "Failed to open port 80/tcp"
    fi
}

start_services() {
    print_header "Starting Services"
    
    print_step "Enabling and starting PHP-FPM..."
    run_logged $SUDO systemctl enable --now php8.4-fpm.service || die "Failed to start PHP-FPM"
    print_success "PHP-FPM running"
    
    print_step "Reloading Apache..."
    run_logged $SUDO systemctl enable --now apache2.service || die "Failed to enable Apache"
    run_logged $SUDO systemctl reload apache2.service || die "Failed to reload Apache"
    print_success "Apache running"
    
    # Verify services
    sleep 2
    
    if ! $SUDO systemctl is-active --quiet apache2; then
        die "Apache failed to start"
    fi
    
    if ! $SUDO systemctl is-active --quiet php8.4-fpm; then
        die "PHP-FPM failed to start"
    fi
    
    if ! $SUDO systemctl is-active --quiet mariadb; then
        die "MariaDB is not running"
    fi
    
    print_success "All services running"
}

#############################################################################
# Summary                                                                   #
#############################################################################

show_summary() {
    local ip
    ip="$(get_local_ip)"
    ip="${ip:-localhost}"
    
    echo
    draw_separator
    print_success "BookStack Installation Complete"
    draw_separator
    echo
    print_kv "Access URL" "http://${BOOKSTACK_DOMAIN}/"
    print_kv "Install Path" "$BOOKSTACK_DIR"
    print_kv "Database" "$DB_NAME"
    print_kv "DB User" "$DB_USER"
    print_kv "DB Password" "$DB_PASS"
    print_kv "Log File" "$LOG_FILE"
    echo
    print_header "Default Credentials"
    print_kv "Email" "admin@admin.com"
    print_kv "Password" "changeme"
    echo
    print_header "Next Steps"
    print_info "1. Access BookStack at http://${BOOKSTACK_DOMAIN}/"
    print_info "2. Login with default credentials"
    print_info "3. Change the admin password immediately"
    print_info "4. Configure HTTPS (recommended):"
    echo "     - Use a reverse proxy (NPM, Traefik, etc.), or"
    echo "     - Install Certbot: sudo apt install certbot python3-certbot-apache"
    print_info "5. Update APP_URL in ${BOOKSTACK_DIR}/.env after adding HTTPS"
    echo
    print_header "Save This Information"
    print_warning "Database password will not be shown again!"
    echo
    draw_separator
}

prompt_reboot() {
    if [[ "$SKIP_REBOOT" == "true" ]] || [[ "$QUIET_MODE" == "true" ]]; then
        return 0
    fi
    
    echo
    print_info "A reboot is recommended to ensure all services start properly."
    echo
    
    while true; do
        read -rp "Reboot now? (yes/no) [default: no]: " response
        response="${response:-no}"
        
        case "${response,,}" in
            yes|y)
                log_msg "Rebooting system..."
                $SUDO reboot
                exit 0
                ;;
            no|n)
                print_info "Reboot skipped"
                print_warning "Remember to reboot later: sudo reboot"
                break
                ;;
            *)
                print_error "Please answer yes or no"
                ;;
        esac
    done
}

#############################################################################
# Main                                                                      #
#############################################################################

main() {
    # Only clear screen if run directly (not when called from another script)
    [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
    
    echo -e "\n━━━ BookStack Wiki Installer v${SCRIPT_VERSION} ━━━\n"
    
    setup_logging
    preflight_checks
    configure_interactive
    
    install_packages
    install_composer
    setup_mariadb
    fetch_bookstack
    configure_bookstack
    configure_php
    configure_apache
    configure_firewall
    start_services
    
    show_summary
    prompt_reboot
    
    log_msg "BookStack installation completed successfully"
}

main "$@"
