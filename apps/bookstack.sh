#!/bin/bash

#############################################################################
# BookStack Wiki Installer                                                  #
# Source: https://github.com/vdarkobar/lab                                  #
#                                                                           #
# Compatible with: Debian 13 (Trixie) only - VM/LXC                         #
#############################################################################

readonly SCRIPT_VERSION="1.0.1"

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
    echo "  - Opens firewall port 80 (if UFW active)"
    echo
    echo "Default credentials:"
    echo "  Email:    admin@admin.com"
    echo "  Password: password"
    echo
    echo "Files created:"
    echo "  /opt/bookstack                  Application directory"
    echo "  /etc/apache2/sites-available/bookstack.conf  Apache vhost"
    echo "  /var/log/lab/bookstack.log     Installation log"
    exit 0
  ;;
esac

set -euo pipefail

#############################################################################
# Resolve Script Directory and Load Formatting Library                      #
#############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)" || REPO_ROOT="$SCRIPT_DIR"

if [[ -f "$REPO_ROOT/lib/formatting.sh" ]]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/lib/formatting.sh"
elif [[ -f "$SCRIPT_DIR/../lib/formatting.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/../lib/formatting.sh"
elif [[ -f "$HOME/lab/lib/formatting.sh" ]]; then
  # shellcheck source=/dev/null
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

BOOKSTACK_DOMAIN="${BOOKSTACK_DOMAIN:-}"
SKIP_REBOOT="${SKIP_REBOOT:-false}"
QUIET_MODE="${QUIET_MODE:-false}"

readonly BOOKSTACK_DIR="/opt/bookstack"
readonly DB_NAME="bookstack_db"
readonly DB_USER="bookstack_user"

DB_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32)"

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="$LOG_DIR/bookstack.log"

export DEBIAN_FRONTEND=noninteractive

# --- IMPORTANT: Avoid Composer "root prompt" when run via hardening (sudo -E bash ...) ---
# This is the fix for your “hang after Installing Composer ✓” issue.
export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_NO_INTERACTION=1

# If hardening ran us with sudo -E, HOME can be the original user's home.
# Ensure root uses a sane HOME to avoid permission pollution.
if [[ $EUID -eq 0 ]]; then
  export HOME="/root"
fi

#############################################################################
# Sudo helper + keep-alive (prevents hidden sudo prompts during spinner)    #
#############################################################################

SUDO=""
SUDO_KEEPALIVE_PID=""

if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
fi

ensure_sudo_cached() {
  [[ -z "$SUDO" ]] && return 0
  # Prompt once in the foreground, so spinners never hide password prompts.
  sudo -v >/dev/null 2>&1 || die "sudo authentication failed"
  # Keep sudo alive while script runs (best-effort).
  (
    while true; do
      sudo -n true 2>/dev/null || exit 0
      sleep 45
    done
  ) &
  SUDO_KEEPALIVE_PID="$!"
}

#############################################################################
# Logging + command runners                                                 #
#############################################################################

setup_logging() {
  $SUDO mkdir -p "$LOG_DIR"
  $SUDO touch "$LOG_FILE"
  $SUDO chmod 644 "$LOG_FILE"
  {
    echo "========================================"
    echo "bookstack.sh started at $(date)"
    echo "========================================"
  } | $SUDO tee -a "$LOG_FILE" >/dev/null
}

log_msg() {
  local msg="$1"
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $msg" | $SUDO tee -a "$LOG_FILE" >/dev/null
  [[ "$QUIET_MODE" != "true" ]] && print_info "$msg"
}

run_logged() {
  # Usage: run_logged cmd arg...
  # Runs command (with sudo if needed) and appends output to LOG_FILE.
  if [[ -n "$SUDO" ]]; then
    "$SUDO" "$@" 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
  else
    "$@" 2>&1 | tee -a "$LOG_FILE" >/dev/null
  fi
}

run_with_spinner() {
  # Usage: run_with_spinner "Message" cmd arg...
  local msg="$1"; shift
  local pid tmplog exit_code
  local i=0
  local start_ts now_ts elapsed

  local spin ok_sym fail_sym
  if [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]; then
    spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    ok_sym='✓'
    fail_sym='✗'
  else
    spin='|/-\'
    ok_sym='+'
    fail_sym='x'
  fi

  tmplog="$(mktemp)"
  start_ts="$(date +%s)"

  if [[ -n "$SUDO" ]]; then
    "$SUDO" "$@" >"$tmplog" 2>&1 &
  else
    "$@" >"$tmplog" 2>&1 &
  fi
  pid=$!

  printf "  %s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    printf "\r  %s %s (%ds)" "$msg" "${spin:i++%${#spin}:1}" "$elapsed"
    sleep 0.1
  done

  wait "$pid"
  exit_code=$?

  # Append to LOG_FILE
  if [[ -n "$SUDO" ]]; then
    sudo tee -a "$LOG_FILE" <"$tmplog" >/dev/null
  else
    tee -a "$LOG_FILE" <"$tmplog" >/dev/null
  fi
  rm -f "$tmplog"

  if [[ $exit_code -eq 0 ]]; then
    printf "\r  %s %s\n" "$msg" "$ok_sym"
  else
    printf "\r  %s %s\n" "$msg" "$fail_sym"
  fi
  return $exit_code
}

#############################################################################
# Utility + cleanup                                                         #
#############################################################################

get_local_ip() {
  hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./) {print $i; exit}}'
}

cleanup() {
  local exit_code=$?
  if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  fi
  if [[ $exit_code -ne 0 ]]; then
    print_error "Installation failed - check log: $LOG_FILE"
  fi
  exit $exit_code
}
trap cleanup EXIT INT TERM

#############################################################################
# Preflight                                                                 #
#############################################################################

preflight_checks() {
  print_header "Preflight Checks"

  if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
    die "This script should not run on Proxmox VE host. Run inside a VM or LXC container."
  fi
  print_success "Not running on PVE host"

  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "sudo is required but not installed"
    sudo -v >/dev/null 2>&1 || die "User does not have sudo privileges"
    print_success "Running as non-root user: $(whoami)"
    print_success "sudo access verified"
  else
    print_success "Running as root"
  fi

  [[ -f /etc/os-release ]] || die "Cannot detect OS - /etc/os-release not found"
  # shellcheck source=/dev/null
  source /etc/os-release

  [[ "${ID:-}" == "debian" ]] || die "Unsupported OS: ${ID:-unknown} (only Debian supported)"
  [[ "${VERSION_ID:-}" == "13" ]] || die "Debian 13 (Trixie) required for PHP 8.4. Detected: Debian ${VERSION_ID:-unknown}"
  print_success "Detected: ${PRETTY_NAME:-Debian 13}"

  if [[ -d "$BOOKSTACK_DIR" ]]; then
    die "Directory $BOOKSTACK_DIR already exists - aborting to avoid partial/dirty install"
  fi
  if [[ -d "/var/lib/mysql/${DB_NAME}" ]]; then
    die "BookStack database already exists - aborting to avoid data loss"
  fi

  command -v systemctl >/dev/null 2>&1 || die "systemd not found (is this container systemd-enabled?)"
  print_success "systemd available"
  echo
}

#############################################################################
# Interactive config                                                        #
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
# Install steps                                                             #
#############################################################################

install_packages() {
  print_header "Installing Packages"

  print_subheader "Stopping unattended-upgrades if running..."
  run_logged systemctl stop unattended-upgrades || true

  local wait_count=0
  while $SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    if [[ $wait_count -eq 0 ]]; then
      print_subheader "Waiting for apt lock to be released..."
    fi
    sleep 2
    ((wait_count++))
    [[ $wait_count -le 30 ]] || die "Timed out waiting for apt lock"
  done

  print_step "Updating package lists..."
  run_with_spinner "Updating apt cache" apt-get update -y || die "apt-get update failed"

  print_step "Installing dependencies (this may take a few minutes)..."
  run_with_spinner "Installing packages" apt-get install -y -q \
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

  if command -v composer &>/dev/null; then
    # IMPORTANT: wrap with COMPOSER_ALLOW_SUPERUSER to avoid root prompt in hardening flow
    print_success "Composer already installed: $(COMPOSER_ALLOW_SUPERUSER=1 composer --version 2>/dev/null | head -1)"
    return 0
  fi

  print_step "Downloading Composer installer..."
  local expected actual
  expected="$(curl -fsSL https://composer.github.io/installer.sig | tr -d '\r\n[:space:]')"
  run_logged curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php || die "Failed to download Composer installer"
  actual="$(php -r "echo hash_file('sha384', '/tmp/composer-setup.php');" | tr -d '\r\n[:space:]')"

  [[ "$expected" == "$actual" ]] || { rm -f /tmp/composer-setup.php; die "Composer installer checksum mismatch"; }
  print_success "Checksum verified"

  print_step "Installing Composer..."
  run_with_spinner "Installing Composer" php /tmp/composer-setup.php --quiet --install-dir=/usr/local/bin --filename=composer \
    || die "Composer installation failed"
  rm -f /tmp/composer-setup.php

  # IMPORTANT: avoid root safety prompt here too
  print_success "Composer installed: $(COMPOSER_ALLOW_SUPERUSER=1 composer --version 2>/dev/null | head -1)"
}

setup_mariadb() {
  print_header "Configuring MariaDB"

  print_step "Starting MariaDB service..."
  run_logged systemctl enable --now mariadb.service || die "Failed to start MariaDB"
  print_success "MariaDB service running"

  print_step "Creating database and user..."
  run_logged mysql -u root --execute="CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" \
    || die "Failed to create database"
  run_logged mysql -u root --execute="CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';" \
    || die "Failed to create database user"
  run_logged mysql -u root --execute="GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;" \
    || die "Failed to grant privileges"
  print_success "Database configured"

  print_step "Securing MariaDB..."
  run_logged mysql -u root --execute="DELETE FROM mysql.user WHERE User='';" || true
  run_logged mysql -u root --execute="DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" || true
  run_logged mysql -u root --execute="DROP DATABASE IF EXISTS test;" || true
  run_logged mysql -u root --execute="DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
  run_logged mysql -u root --execute="FLUSH PRIVILEGES;" || true
  print_success "MariaDB secured"
}

fetch_bookstack() {
  print_header "Fetching BookStack"

  print_step "Preparing install directory..."
  run_logged rm -rf "$BOOKSTACK_DIR"
  run_logged mkdir -p "$BOOKSTACK_DIR"

  print_step "Downloading BookStack release..."
  run_with_spinner "Downloading BookStack" curl -fsSL \
    "https://github.com/BookStackApp/BookStack/archive/refs/heads/release.tar.gz" \
    -o /tmp/bookstack-release.tar.gz || die "Failed to download BookStack"

  print_step "Extracting archive..."
  run_with_spinner "Extracting files" tar -xzf /tmp/bookstack-release.tar.gz -C /tmp || die "Failed to extract archive"

  local extracted
  extracted="$(find /tmp -maxdepth 1 -type d -name 'BookStack-release*' | head -n1)"
  [[ -n "$extracted" ]] || die "Failed to find extracted BookStack directory"

  run_logged rsync -a "${extracted}/" "${BOOKSTACK_DIR}/" || die "Failed to deploy BookStack"
  rm -rf /tmp/bookstack-release.tar.gz "$extracted"

  print_success "BookStack deployed to ${BOOKSTACK_DIR}"
}

configure_bookstack() {
  print_header "Configuring BookStack"

  cd "$BOOKSTACK_DIR"

  print_step "Creating environment configuration..."
  cp .env.example .env

  sed -i "s|^APP_URL=.*|APP_URL=http://${BOOKSTACK_DOMAIN}|g" .env
  sed -i "s|^DB_DATABASE=.*|DB_DATABASE=${DB_NAME}|g" .env
  sed -i "s|^DB_USERNAME=.*|DB_USERNAME=${DB_USER}|g" .env
  sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=${DB_PASS}|g" .env
  print_success "Environment file configured"

  print_step "Installing PHP dependencies (this may take several minutes)..."
  run_with_spinner "Installing PHP dependencies" env COMPOSER_ALLOW_SUPERUSER=1 composer install \
    --no-dev --no-interaction --no-progress --prefer-dist \
    --working-dir="$BOOKSTACK_DIR" || die "Composer install failed"
  print_success "Dependencies installed"

  print_step "Generating application key..."
  run_logged php artisan key:generate --no-interaction --force || die "Failed to generate app key"
  print_success "Application key generated"

  print_step "Running database migrations..."
  run_with_spinner "Running migrations" php artisan migrate --no-interaction --force || die "Database migration failed"
  print_success "Database migrations completed"

  print_step "Setting permissions..."
  chown -R www-data:www-data "$BOOKSTACK_DIR"
  chmod -R 755 "$BOOKSTACK_DIR"
  chmod -R 775 "$BOOKSTACK_DIR/storage" "$BOOKSTACK_DIR/bootstrap/cache" "$BOOKSTACK_DIR/public/uploads"
  chmod 640 "$BOOKSTACK_DIR/.env"
  print_success "Permissions configured"
}

configure_php() {
  print_header "Configuring PHP"

  local php_ini="/etc/php/8.4/fpm/conf.d/99-bookstack.ini"
  print_step "Creating PHP configuration..."
  tee "$php_ini" >/dev/null <<'EOF'
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
  run_logged a2enmod rewrite proxy_fcgi setenvif || die "Failed to enable Apache modules"
  run_logged a2enconf php8.4-fpm || die "Failed to enable PHP-FPM config"
  print_success "Apache modules enabled"

  print_step "Creating virtual host..."
  tee /etc/apache2/sites-available/bookstack.conf >/dev/null <<EOF
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
            RewriteCond %{HTTP:Authorization} .
            RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

            RewriteCond %{REQUEST_FILENAME} !-d
            RewriteCond %{REQUEST_URI} (.+)/$
            RewriteRule ^ %1 [L,R=301]

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
  run_logged a2ensite bookstack.conf || die "Failed to enable site"
  a2dissite 000-default.conf 2>/dev/null || true
  print_success "Site enabled"

  print_step "Validating Apache configuration..."
  run_logged apache2ctl configtest || die "Apache configuration test failed"
  print_success "Apache configuration valid"
}

configure_firewall() {
  print_header "Configuring Firewall"

  command -v ufw >/dev/null 2>&1 || { print_warning "UFW not installed - skipping firewall configuration"; return 0; }

  if ! ufw status >/dev/null 2>&1; then
    print_warning "UFW not functional in this environment"
    print_info "Configure firewall on the host instead (required port: 80/tcp)"
    return 0
  fi

  if ! ufw status | grep -q "Status: active"; then
    print_warning "UFW not active - skipping firewall configuration"
    return 0
  fi

  print_step "Opening port 80/tcp..."
  run_logged ufw allow 80/tcp comment 'BookStack HTTP' || print_warning "Failed to open port 80/tcp"
  print_success "Firewall rule applied (if allowed)"
}

start_services() {
  print_header "Starting Services"

  print_step "Enabling and starting PHP-FPM..."
  run_logged systemctl enable --now php8.4-fpm.service || die "Failed to start PHP-FPM"
  print_success "PHP-FPM running"

  print_step "Enabling and reloading Apache..."
  run_logged systemctl enable --now apache2.service || die "Failed to enable Apache"
  run_logged systemctl reload apache2.service || die "Failed to reload Apache"
  print_success "Apache running"

  sleep 2
  systemctl is-active --quiet apache2 || die "Apache failed to start"
  systemctl is-active --quiet php8.4-fpm || die "PHP-FPM failed to start"
  systemctl is-active --quiet mariadb || die "MariaDB is not running"
  print_success "All services running"
}

show_summary() {
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
  print_info "1. Login and change the admin password immediately"
  print_info "2. Add HTTPS via reverse proxy (NPM/Traefik) or Certbot"
  print_info "3. If you enable HTTPS, update APP_URL in ${BOOKSTACK_DIR}/.env"
  echo
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
      yes|y) log_msg "Rebooting system..."; $SUDO reboot; exit 0 ;;
      no|n)  print_info "Reboot skipped"; print_warning "Remember to reboot later: sudo reboot"; break ;;
      *)     print_error "Please answer yes or no" ;;
    esac
  done
}

main() {
  [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
  echo -e "\n━━━ BookStack Wiki Installer v${SCRIPT_VERSION} ━━━\n"

  ensure_sudo_cached
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
