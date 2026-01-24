#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo "FATAL: Docker install failed at line '"$LINENO"': '"$BASH_COMMAND"'" >&2; exit 1' ERR

# Only clear screen if run directly (not when called from another script)
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && clear || true

########################################
# Docker + Docker Compose (v2) install #
########################################

echo
echo "Docker / Compose (v2) installer (idempotent, inline)"
echo

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
CODENAME="$(lsb_release -cs)"
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
