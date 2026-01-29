#!/bin/bash
#############################################################################
# BookStack Wiki Installer (Debian 13 / Trixie)
# Based on official community Debian 13 script from BookStack
# Repo style: vdarkobar/lab (formatting + log + stage UX)
#############################################################################

readonly SCRIPT_VERSION="1.0.0"

# --- help early ---
case "${1:-}" in
  --help|-h)
    echo "BookStack Wiki Installer v${SCRIPT_VERSION}"
    echo
    echo "Usage: $0 [domain-or-ip]"
    echo
    echo "Env:"
    echo "  BOOKSTACK_DOMAIN     Domain/IP (overrides arg1)"
    echo "  BOOKSTACK_DIR        Install dir (default: /var/www/bookstack)"
    echo "  BOOKSTACK_ADMIN_USER Owner user for files (default: SUDO_USER/logname/root)"
    echo "  SKIP_REBOOT          true/false (default: false)"
    echo "  QUIET_MODE           true/false (default: false)"
    echo
    exit 0
  ;;
esac

set -euo pipefail

#############################################################################
# Load formatting (repo) with fallback (standalone)
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
  print_header() { echo -e "\n━━━ $1 ━━━"; }
  print_success() { echo "✓ $1"; }
  print_error() { echo "✗ $1" >&2; }
  print_warning() { echo "⚠ $1"; }
  print_info() { echo "ℹ $1"; }
  print_step() { echo "→ $1"; }
  print_subheader() { echo "  • $1"; }
  print_kv() { printf "%-20s %s\n" "$1:" "$2"; }
  draw_separator() { echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
  die() { print_error "$1"; exit 1; }
fi

#############################################################################
# Config
#############################################################################

BOOKSTACK_DOMAIN="${BOOKSTACK_DOMAIN:-${1:-}}"
BOOKSTACK_DIR="${BOOKSTACK_DIR:-/var/www/bookstack}"
SKIP_REBOOT="${SKIP_REBOOT:-false}"
QUIET_MODE="${QUIET_MODE:-false}"

readonly DB_NAME="bookstack"
readonly DB_USER="bookstack"
DB_PASS="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13)"

readonly LOG_DIR="/var/log/lab"
readonly LOG_FILE="${LOG_DIR}/bookstack_install_$(date +%s).log"
readonly LOG_LATEST="${LOG_DIR}/bookstack.log"

export DEBIAN_FRONTEND=noninteractive
export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_NO_INTERACTION=1

# original “admin” user for file ownership (official script uses SUDO_USER)
SCRIPT_USER="${BOOKSTACK_ADMIN_USER:-${SUDO_USER:-}}"
if [[ -z "$SCRIPT_USER" ]]; then
  SCRIPT_USER="$(logname 2>/dev/null || true)"
fi
SCRIPT_USER="${SCRIPT_USER:-root}"

#############################################################################
# Sudo helper (supports standalone non-root)
#############################################################################

SUDO=""
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
fi

ensure_sudo_cached() {
  [[ -z "$SUDO" ]] && return 0
  command -v sudo >/dev/null 2>&1 || die "sudo is required but not installed"
  sudo -v >/dev/null 2>&1 || die "sudo authentication failed"
}

run_cmd() {
  # usage: run_cmd cmd args...
  if [[ -n "$SUDO" ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

log_setup() {
  run_cmd mkdir -p "$LOG_DIR"
  run_cmd touch "$LOG_FILE"
  run_cmd chmod 644 "$LOG_FILE"
  run_cmd ln -sf "$LOG_FILE" "$LOG_LATEST"
  {
    echo "========================================"
    echo "bookstack.sh started at $(date)"
    echo "Log: $LOG_FILE"
    echo "========================================"
  } | run_cmd tee -a "$LOG_FILE" >/dev/null
}

log_line() {
  # log_line "message"
  local msg="$1"
  echo "$msg" | run_cmd tee -a "$LOG_FILE" >/dev/null
  [[ "$QUIET_MODE" != "true" ]] && print_info "$msg"
}

error_out() {
  local msg="$1"
  echo "ERROR: $msg" | run_cmd tee -a "$LOG_FILE" >/dev/null
  die "$msg"
}

# One-line feedback for long steps:
# - If stdout is a TTY, we let apt show its own progress (can include % via dpkg fancy)
# - Otherwise we show a spinner + elapsed seconds
run_with_spinner() {
  local msg="$1"; shift
  local pid tmp exit_code i=0 start_ts now_ts elapsed
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

  tmp="$(mktemp)"
  start_ts="$(date +%s)"

  # run in background, capture output to tmp
  if [[ -n "$SUDO" ]]; then
    sudo "$@" >"$tmp" 2>&1 &
  else
    "$@" >"$tmp" 2>&1 &
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

  run_cmd tee -a "$LOG_FILE" <"$tmp" >/dev/null || true
  rm -f "$tmp"

  if [[ $exit_code -eq 0 ]]; then
    printf "\r  %s %s\n" "$msg" "$ok_sym"
  else
    printf "\r  %s %s\n" "$msg" "$fail_sym"
  fi
  return $exit_code
}

#############################################################################
# Helpers
#############################################################################

get_current_ip() {
  # reliable “primary” IP
  ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}'
}

prompt_for_domain_if_needed() {
  if [[ -z "$BOOKSTACK_DOMAIN" ]]; then
    local ip
    ip="$(get_current_ip)"
    log_line ""
    log_line "Enter the domain (or IP if not using a domain) to host BookStack on, then press [ENTER]."
    log_line "Examples: my-site.com or docs.my-site.com or ${ip:-<server-ip>}"
    read -r BOOKSTACK_DOMAIN
  fi
  [[ -n "$BOOKSTACK_DOMAIN" ]] || error_out "A domain/IP must be provided"
}

#############################################################################
# Preflight (align with official “fresh server” checks)
#############################################################################

run_pre_install_checks() {
  print_header "Preflight Checks"

  # Don't run on PVE host
  if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
    error_out "Do not run on Proxmox VE host. Run inside a VM/LXC."
  fi
  print_success "Not running on PVE host"

  # Debian 13 only
  [[ -f /etc/os-release ]] || error_out "/etc/os-release not found"
  # shellcheck source=/dev/null
  source /etc/os-release
  [[ "${ID:-}" == "debian" ]] || error_out "Unsupported OS: ${ID:-unknown} (Debian required)"
  [[ "${VERSION_ID:-}" == "13" ]] || error_out "Debian 13 (Trixie) required (detected: ${VERSION_ID:-unknown})"
  print_success "Detected: ${PRETTY_NAME:-Debian 13}"

  # Official script assumes root; we allow non-root but require sudo.
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || error_out "This script must be run with sudo/root privileges"
    sudo -v >/dev/null 2>&1 || error_out "sudo privileges required"
    print_success "sudo access verified: $(whoami)"
  else
    print_success "Running as root"
  fi

  # Fresh-server checks (official)
  if [[ -d "/etc/apache2/sites-enabled" ]]; then
    error_out "Existing apache config found (/etc/apache2/sites-enabled). Aborting (fresh server expected)."
  fi
  if [[ -d "/var/lib/mysql" ]]; then
    error_out "Existing MySQL/MariaDB data found (/var/lib/mysql). Aborting (fresh server expected)."
  fi
  if [[ -d "$BOOKSTACK_DIR" ]]; then
    error_out "Install directory already exists ($BOOKSTACK_DIR). Aborting."
  fi

  print_success "Fresh-server checks passed"
  echo
}

#############################################################################
# Install steps (official flow)
#############################################################################

run_package_installs() {
  # If interactive TTY, allow dpkg fancy progress (percent) to show.
  if [[ -t 1 && "$QUIET_MODE" != "true" ]]; then
    run_cmd apt-get update
    run_cmd apt-get install -y \
      -o Dpkg::Progress-Fancy=1 \
      git unzip apache2 curl mariadb-server \
      php8.4 php8.4-fpm php8.4-curl php8.4-mbstring php8.4-ldap php8.4-xml php8.4-zip php8.4-gd php8.4-mysql
    return 0
  fi

  run_with_spinner "Updating apt cache" apt-get update || return 1
  run_with_spinner "Installing packages" apt-get install -y -q \
    git unzip apache2 curl mariadb-server \
    php8.4 php8.4-fpm php8.4-curl php8.4-mbstring php8.4-ldap php8.4-xml php8.4-zip php8.4-gd php8.4-mysql
}

run_database_setup() {
  run_cmd systemctl start mariadb.service
  sleep 3
  run_cmd mysql -u root --execute="CREATE DATABASE ${DB_NAME};"
  run_cmd mysql -u root --execute="CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  run_cmd mysql -u root --execute="GRANT ALL ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;"
}

run_bookstack_download() {
  run_cmd mkdir -p "$(dirname "$BOOKSTACK_DIR")"
  run_cmd git clone https://github.com/BookStackApp/BookStack.git \
    --branch release --single-branch "$BOOKSTACK_DIR"
}

run_download_bookstack_vendor_files() {
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && php bookstack-system-cli download-vendor"
}

run_update_bookstack_env() {
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && cp .env.example .env"
  run_cmd sed -i.bak "s@APP_URL=.*\$@APP_URL=http://${BOOKSTACK_DOMAIN}@" "$BOOKSTACK_DIR/.env"
  run_cmd sed -i.bak "s@DB_DATABASE=.*\$@DB_DATABASE=${DB_NAME}@" "$BOOKSTACK_DIR/.env"
  run_cmd sed -i.bak "s@DB_USERNAME=.*\$@DB_USERNAME=${DB_USER}@" "$BOOKSTACK_DIR/.env"
  run_cmd sed -i.bak "s@DB_PASSWORD=.*\$@DB_PASSWORD=${DB_PASS}@" "$BOOKSTACK_DIR/.env"
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && php artisan key:generate --no-interaction --force"
}

run_bookstack_database_migrations() {
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && php artisan migrate --no-interaction --force"
}

run_set_application_file_permissions() {
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && chown -R '$SCRIPT_USER':www-data ./"
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && chmod -R 755 ./"
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && chmod -R 775 bootstrap/cache public/uploads storage"
  run_cmd chmod 740 "$BOOKSTACK_DIR/.env"
  run_cmd bash -lc "cd '$BOOKSTACK_DIR' && git config core.fileMode false"
}

run_configure_apache() {
  run_cmd a2enmod rewrite proxy_fcgi setenvif
  run_cmd a2enconf php8.4-fpm

  run_cmd tee /etc/apache2/sites-available/bookstack.conf >/dev/null <<EOL
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

  ErrorLog \${APACHE_LOG_DIR}/error.log
  CustomLog \${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
EOL

  run_cmd a2dissite 000-default.conf
  run_cmd a2ensite bookstack.conf

  run_cmd systemctl restart apache2
  run_cmd systemctl start php8.4-fpm.service
}

#############################################################################
# Summary + optional reboot
#############################################################################

show_summary() {
  local ip
  ip="$(get_current_ip)"
  ip="${ip:-localhost}"

  log_line "----------------------------------------------------------------"
  log_line "Setup finished, your BookStack instance should now be installed!"
  log_line "- Default login email: admin@admin.com"
  log_line "- Default login password: password"
  log_line "- Access URL: http://${ip}/ or http://${BOOKSTACK_DOMAIN}/"
  log_line "- BookStack install path: ${BOOKSTACK_DIR}"
  log_line "- DB name/user: ${DB_NAME}/${DB_USER}"
  log_line "- DB password: ${DB_PASS}"
  log_line "- Install script log: ${LOG_FILE}"
  log_line "----------------------------------------------------------------"
}

prompt_reboot() {
  [[ "$SKIP_REBOOT" == "true" ]] && return 0
  [[ "$QUIET_MODE" == "true" ]] && return 0

  echo
  print_info "Reboot is optional. If this is a fresh VM/LXC, reboot can be a clean finish."
  while true; do
    read -rp "Reboot now? (yes/no) [default: no]: " r
    r="${r:-no}"
    case "${r,,}" in
      yes|y) run_cmd reboot; exit 0 ;;
      no|n)  print_info "Reboot skipped"; break ;;
      *)     print_error "Please answer yes or no" ;;
    esac
  done
}

#############################################################################
# Main
#############################################################################

main() {
  [[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true
  echo -e "\n━━━ BookStack Wiki Installer v${SCRIPT_VERSION} ━━━\n"

  print_warning "THIS SCRIPT IS NOT CONSIDERED OFFICIALLY SUPPORTED!"
  print_warning "Only Ubuntu LTS scripts are supported by BookStack. Use with caution."
  echo

  ensure_sudo_cached
  log_setup
  log_line "This script logs full output to ${LOG_FILE} (also symlinked to ${LOG_LATEST})."

  run_pre_install_checks
  prompt_for_domain_if_needed
  log_line ""
  log_line "Installing using the domain or IP \"${BOOKSTACK_DOMAIN}\""
  log_line ""

  log_line "[1/8] Installing required system packages... (This may take several minutes)"
  run_package_installs >>"$LOG_FILE" 2>&1 || error_out "Package install failed"

  log_line "[2/8] Preparing MySQL database..."
  run_database_setup >>"$LOG_FILE" 2>&1 || error_out "Database setup failed"

  log_line "[3/8] Downloading BookStack to ${BOOKSTACK_DIR}..."
  run_bookstack_download >>"$LOG_FILE" 2>&1 || error_out "BookStack download failed"

  log_line "[4/8] Downloading PHP dependency files..."
  # spinner for non-tty; otherwise just stream
  if [[ -t 1 && "$QUIET_MODE" != "true" ]]; then
    run_download_bookstack_vendor_files >>"$LOG_FILE" 2>&1 || error_out "Vendor download failed"
  else
    run_with_spinner "Downloading vendor files" bash -lc "cd '$BOOKSTACK_DIR' && php bookstack-system-cli download-vendor" \
      || error_out "Vendor download failed"
  fi

  log_line "[5/8] Creating and populating BookStack .env file..."
  run_update_bookstack_env >>"$LOG_FILE" 2>&1 || error_out ".env setup failed"

  log_line "[6/8] Running initial BookStack database migrations..."
  if [[ -t 1 && "$QUIET_MODE" != "true" ]]; then
    run_bookstack_database_migrations >>"$LOG_FILE" 2>&1 || error_out "Migrations failed"
  else
    run_with_spinner "Running migrations" bash -lc "cd '$BOOKSTACK_DIR' && php artisan migrate --no-interaction --force" \
      || error_out "Migrations failed"
  fi

  log_line "[7/8] Setting BookStack file & folder permissions..."
  run_set_application_file_permissions >>"$LOG_FILE" 2>&1 || error_out "Permissions step failed"

  log_line "[8/8] Configuring apache server..."
  run_configure_apache >>"$LOG_FILE" 2>&1 || error_out "Apache configuration failed"

  show_summary
  prompt_reboot
}

main "$@"
