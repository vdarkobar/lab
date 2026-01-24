#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
trap 'echo "FATAL: line '"$LINENO"': '"$BASH_COMMAND"'" >&2' ERR

clear

########################################
# Docker + Docker Compose (v2) install #
########################################

# Stop unattended upgrades if running (best effort)
sudo systemctl stop unattended-upgrades 2>/dev/null || true

echo
echo "Docker / Compose (v2) installer (idempotent, inline)"
echo

NEED_APT_UPDATE=1

# --- prerequisites (install only if missing) ---
if dpkg -s ca-certificates >/dev/null 2>&1; then
  echo "OK: package already installed: ca-certificates"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: ca-certificates"
  sudo apt-get install -y ca-certificates
fi

if dpkg -s curl >/dev/null 2>&1; then
  echo "OK: package already installed: curl"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: curl"
  sudo apt-get install -y curl
fi

if dpkg -s gnupg >/dev/null 2>&1; then
  echo "OK: package already installed: gnupg"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: gnupg"
  sudo apt-get install -y gnupg
fi

if dpkg -s lsb-release >/dev/null 2>&1; then
  echo "OK: package already installed: lsb-release"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: lsb-release"
  sudo apt-get install -y lsb-release
fi

# --- docker keyring (idempotent) ---
sudo mkdir -p /etc/apt/keyrings

if [[ ! -s /etc/apt/keyrings/docker.gpg ]]; then
  echo "Adding Docker GPG key..."
  curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg || true
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
if dpkg -s docker-ce >/dev/null 2>&1; then
  echo "OK: package already installed: docker-ce"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: docker-ce"
  sudo apt-get install -y docker-ce
fi

if dpkg -s docker-ce-cli >/dev/null 2>&1; then
  echo "OK: package already installed: docker-ce-cli"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: docker-ce-cli"
  sudo apt-get install -y docker-ce-cli
fi

if dpkg -s containerd.io >/dev/null 2>&1; then
  echo "OK: package already installed: containerd.io"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: containerd.io"
  sudo apt-get install -y containerd.io
fi

if dpkg -s docker-buildx-plugin >/dev/null 2>&1; then
  echo "OK: package already installed: docker-buildx-plugin"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: docker-buildx-plugin"
  sudo apt-get install -y docker-buildx-plugin
fi

if dpkg -s docker-compose-plugin >/dev/null 2>&1; then
  echo "OK: package already installed: docker-compose-plugin"
else
  if [[ "$NEED_APT_UPDATE" -eq 1 ]]; then
    echo "Updating apt package index..."
    sudo apt-get update
    NEED_APT_UPDATE=0
  fi
  echo "Installing package: docker-compose-plugin"
  sudo apt-get install -y docker-compose-plugin
fi

# --- enable/start docker service (idempotent) ---
echo "Enabling and starting Docker service..."
sudo systemctl enable --now docker >/dev/null 2>&1 || sudo systemctl start docker >/dev/null 2>&1 || true

# --- ensure docker group exists (safe) ---
if getent group docker >/dev/null 2>&1; then
  :
else
  echo "Creating docker group..."
  sudo groupadd docker || true
fi

# --- add current user to docker group (idempotent) ---
USER_NAME="$(id -un)"
if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx docker; then
  echo "OK: user already in docker group: $USER_NAME"
else
  echo "Adding user to docker group: $USER_NAME"
  sudo usermod -aG docker "$USER_NAME"
fi

# --- verify installation (root-level; avoids group refresh issues) ---
echo
echo "Verifying installation..."
sudo docker --version
sudo docker compose version

# --- ensure package manager status is okay (safe, idempotent) ---
sudo dpkg --configure -a >/dev/null 2>&1 || true

echo
echo "DONE: Docker and Docker Compose (v2) are installed."
echo
echo "To use Docker without sudo in your current session:"
echo "  - log out and log back in, OR"
echo "  - run: newgrp docker"
echo
