#!/usr/bin/env bash

########################################
# Docker + Docker Compose (v2) install #
########################################

readonly VERSION="1.1.0"

# Handle --help flag
case "${1:-}" in
    --help|-h)
        echo "Docker + Compose (v2) Installer v${VERSION}"
        echo
        echo "Usage: $0 [--help]"
        echo
        echo "Installation:"
        echo "  bootstrap.sh → hardening.sh → Select \"Docker\""
        echo
        echo "What it does:"
        echo "  - Installs Docker CE, CLI, containerd"
        echo "  - Installs Docker Compose v2 plugin"
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

set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo "FATAL: Docker install failed at line '"$LINENO"': '"$BASH_COMMAND"'" >&2; exit 1' ERR

# Check if running on PVE host (should not be)
if [[ -f /etc/pve/.version ]] || command -v pveversion &>/dev/null; then
    echo "ERROR: This script should not run on Proxmox VE host. Run inside a VM or LXC container." >&2
    exit 1
fi

# Only clear screen if run directly (not when called from another script)
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true

echo
echo "Docker / Compose (v2) installer (idempotent, inline)"
echo

#################################################################
# Source Helper Library (optional but recommended)              #
#################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to source helpers for get_supported_codename
HELPERS_LOADED=false
if [[ -f "${SCRIPT_DIR}/../lib/helpers.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/helpers.sh"
    HELPERS_LOADED=true
elif [[ -f "${SCRIPT_DIR}/lib/helpers.sh" ]]; then
    source "${SCRIPT_DIR}/lib/helpers.sh"
    HELPERS_LOADED=true
fi

#################################################################
# Codename Detection (inline fallback if helpers not loaded)    #
#################################################################

get_docker_codename() {
    # If helpers loaded, use the proper function
    if [[ "$HELPERS_LOADED" == true ]] && type get_supported_codename &>/dev/null; then
        get_supported_codename docker
        return
    fi
    
    # Inline fallback implementation
    local detected override_val
    
    # Check for env override first
    override_val="${DOCKER_DIST:-}"
    if [[ -n "$override_val" ]]; then
        echo "$override_val"
        return 0
    fi
    
    # Detect codename (use subshell to avoid variable conflicts with readonly VERSION)
    if [[ -f /etc/os-release ]]; then
        detected="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    fi
    [[ -z "$detected" ]] && detected="$(lsb_release -cs 2>/dev/null || echo "unknown")"
    
    # Check if supported, fallback if not
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
}

#################################################################
# Main Installation                                              #
#################################################################

# Verify sudo access early
if ! sudo -n true 2>/dev/null; then
  echo "This script requires sudo privileges. Requesting password..."
  sudo -v
fi

# Stop unattended upgrades if running (best effort, non-fatal)
sudo systemctl stop unattended-upgrades 2>/dev/null || true

NEED_APT_UPDATE=1

# --- prerequisites (install only if missing) ---
for pkg in ca-certificates curl gnupg lsb-release; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "OK: package already installed: $pkg"
  else
    if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
      echo "Updating apt package index..."
      sudo apt-get update
      NEED_APT_UPDATE=0
    fi
    echo "Installing package: $pkg"
    sudo apt-get install -y "$pkg"
  fi
done

# --- docker keyring (idempotent) ---
sudo mkdir -p /etc/apt/keyrings

if [[ ! -s /etc/apt/keyrings/docker.gpg ]]; then
  echo "Adding Docker GPG key..."
  curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
else
  echo "OK: Docker GPG key already present: /etc/apt/keyrings/docker.gpg"
fi

# --- docker repo (idempotent) ---
DOCKER_LIST="/etc/apt/sources.list.d/docker.list"
ARCH="$(dpkg --print-architecture)"
CODENAME="$(get_docker_codename)"

echo "Using Debian codename for Docker repo: $CODENAME"

DESIRED_LINE="deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable"

if [[ -f "$DOCKER_LIST" ]] && grep -Fqx "$DESIRED_LINE" "$DOCKER_LIST"; then
  echo "OK: Docker apt repo already configured: $DOCKER_LIST"
else
  echo "Configuring Docker apt repository: $DOCKER_LIST"
  echo "$DESIRED_LINE" | sudo tee "$DOCKER_LIST" >/dev/null
  NEED_APT_UPDATE=1
fi

# --- docker packages (install only if missing) ---
for pkg in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "OK: package already installed: $pkg"
  else
    if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
      echo "Updating apt package index..."
      sudo apt-get update
      NEED_APT_UPDATE=0
    fi
    echo "Installing package: $pkg"
    sudo apt-get install -y "$pkg"
  fi
done

# --- enable/start docker service ---
echo "Enabling and starting Docker service..."
if sudo systemctl enable --now docker 2>&1; then
  echo "OK: Docker service enabled and started"
else
  echo "WARNING: Failed to enable Docker service via systemctl, attempting start..."
  sudo systemctl start docker || echo "WARNING: Could not start Docker service"
fi

# --- ensure docker group exists ---
if getent group docker >/dev/null 2>&1; then
  echo "OK: docker group exists"
else
  echo "Creating docker group..."
  sudo groupadd docker
fi

# --- add current user to docker group (idempotent) ---
USER_NAME="$(id -un)"
if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx docker; then
  echo "OK: user already in docker group: $USER_NAME"
else
  echo "Adding user to docker group: $USER_NAME"
  sudo usermod -aG docker "$USER_NAME"
  echo "NOTE: Group membership will be active after logout/login or running: newgrp docker"
fi

# --- verify installation ---
echo
echo "Verifying installation..."
if sudo docker --version && sudo docker compose version; then
  echo "OK: Docker and Docker Compose are working"
else
  echo "ERROR: Docker installation verification failed"
  exit 1
fi

# --- ensure package manager is in good state ---
sudo dpkg --configure -a 2>&1 | grep -v "^$" || true

echo
echo "✓ DONE: Docker and Docker Compose (v2) are installed successfully."
echo
echo "To use Docker without sudo in your current session:"
echo "  - Log out and log back in, OR"
echo "  - Run: newgrp docker"
echo "  - Your calling script can use: exec sg docker -c \"\$0 \$*\""
echo

# Explicit success exit
exit 0
