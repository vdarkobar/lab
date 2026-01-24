# Adding New Apps to hardening.sh - Quick Guide

## 🎯 Super Easy App Addition

Adding a new app to the hardening script is as simple as **adding one line** to the APP_REGISTRY array!

## 📝 How to Add a New App

### Step 1: Open hardening.sh

Find the APP_REGISTRY section (around line 26):

```bash
# Application Registry - ADD NEW APPS HERE
readonly APP_REGISTRY=(
    "Nginx Proxy Manager|npm.sh|docker ps -a --format '{{.Names}}' | grep -q 'npm'"
    "Docker|docker.sh|command -v docker >/dev/null 2>&1"
    "Portainer|portainer.sh|docker ps -a --format '{{.Names}}' | grep -q 'portainer'"
    # Add your new app here ↓
)
```

### Step 2: Add Your App

Add one line in this format:

```
"Display Name|script_filename.sh|detection_command"
```

**Example - Adding Jellyfin:**
```bash
readonly APP_REGISTRY=(
    "Nginx Proxy Manager|npm.sh|docker ps -a --format '{{.Names}}' | grep -q 'npm'"
    "Docker|docker.sh|command -v docker >/dev/null 2>&1"
    "Portainer|portainer.sh|docker ps -a --format '{{.Names}}' | grep -q 'portainer'"
    "Jellyfin Media Server|jellyfin.sh|docker ps -a --format '{{.Names}}' | grep -q 'jellyfin'"
)
```

### Step 3: Done!

That's it! The script automatically:
- ✅ Shows it in the menu
- ✅ Checks if it's installed
- ✅ Downloads from apps/ folder
- ✅ Verifies checksum
- ✅ Executes the script

## 📋 Format Breakdown

```
"Display Name|script_filename.sh|detection_command"
 ↑            ↑                   ↑
 │            │                   │
 │            │                   └─ Command to check if installed
 │            │                      (returns 0 if installed)
 │            │
 │            └─ Filename in apps/ folder
 │
 └─ What users see in menu
```

## 🔍 Detection Commands

### For Docker Containers

```bash
# Check if container exists (any state)
docker ps -a --format '{{.Names}}' | grep -q 'container_name'

# Check if container is running
docker ps --format '{{.Names}}' | grep -q 'container_name'
```

### For System Commands

```bash
# Check if command exists
command -v binary_name >/dev/null 2>&1

# Examples:
command -v docker >/dev/null 2>&1
command -v git >/dev/null 2>&1
command -v node >/dev/null 2>&1
```

### For System Services

```bash
# Check if service is active
systemctl is-active service_name >/dev/null 2>&1

# Check if service exists
systemctl list-units --full --all | grep -q 'service_name.service'
```

### For Files/Directories

```bash
# Check if file exists
test -f /path/to/file

# Check if directory exists
test -d /path/to/directory

# Check if binary in standard location
test -x /usr/local/bin/app
```

## 📚 Complete Examples

### Example 1: Docker-based App (Nextcloud)

```bash
"Nextcloud|nextcloud.sh|docker ps -a --format '{{.Names}}' | grep -q 'nextcloud'"
```

### Example 2: System Package (Git)

```bash
"Git Version Control|git.sh|command -v git >/dev/null 2>&1"
```

### Example 3: System Service (PostgreSQL)

```bash
"PostgreSQL Database|postgres.sh|systemctl is-active postgresql >/dev/null 2>&1"
```

### Example 4: Custom Binary (Caddy)

```bash
"Caddy Web Server|caddy.sh|test -x /usr/bin/caddy"
```

### Example 5: Always Show (No Detection)

```bash
"Custom Setup Script|custom.sh|false"
```
(Using `false` means it always shows as "not installed")

## 🎨 Menu Display Examples

### Before Adding Apps
```
Available applications to install:
1) Docker (docker.sh)
2) Skip - No application installation
```

### After Adding 3 Apps
```
Available applications to install:
Nginx Proxy Manager - Already installed ✓
1) Docker (docker.sh)
2) Portainer (portainer.sh)
3) Jellyfin Media Server (jellyfin.sh)
4) Skip - No application installation
```

## ✅ Checklist for Adding a New App

- [ ] Create the app script in `apps/` folder (e.g., `jellyfin.sh`)
- [ ] Generate checksum: `sha256sum jellyfin.sh > jellyfin.sh.sha256`
- [ ] Add one line to APP_REGISTRY in hardening.sh
- [ ] Test the detection command works correctly
- [ ] Commit both files to repository:
  ```bash
  git add apps/jellyfin.sh apps/jellyfin.sh.sha256 server/hardening.sh
  git commit -m "Add Jellyfin installation option"
  git push
  ```

## 🛠️ Testing Your Addition

### Test Detection Command

Before adding to the registry, test your detection command:

```bash
# Should return 0 (success) if installed
docker ps -a --format '{{.Names}}' | grep -q 'jellyfin' && echo "Installed" || echo "Not installed"

# Should show nothing if not installed
command -v jellyfin >/dev/null 2>&1 && echo "Found" || echo "Not found"
```

### Test the Full Script

1. Add your app to APP_REGISTRY
2. Run hardening.sh
3. Check that:
   - App appears in menu
   - Detection works (shows "Already installed" if installed)
   - Installation works when selected

## 🔄 Real-World Example

### Scenario: Adding Home Assistant

**1. Create the script:**
```bash
# In apps/ folder
vim home-assistant.sh
```

**2. Generate checksum:**
```bash
sha256sum home-assistant.sh > home-assistant.sh.sha256
```

**3. Add to hardening.sh:**
```bash
readonly APP_REGISTRY=(
    "Nginx Proxy Manager|npm.sh|docker ps -a --format '{{.Names}}' | grep -q 'npm'"
    "Docker|docker.sh|command -v docker >/dev/null 2>&1"
    "Portainer|portainer.sh|docker ps -a --format '{{.Names}}' | grep -q 'portainer'"
    "Home Assistant|home-assistant.sh|docker ps -a --format '{{.Names}}' | grep -q 'homeassistant'"
)
```

**4. Commit:**
```bash
git add apps/home-assistant.sh apps/home-assistant.sh.sha256 server/hardening.sh
git commit -m "Add Home Assistant installation"
git push
```

**Done!** Home Assistant now appears in the menu.

## 💡 Pro Tips

### Order Matters
Apps appear in menu in the order listed. Put most common apps first:
```bash
readonly APP_REGISTRY=(
    "Docker|docker.sh|..."           # Most users need this first
    "Nginx Proxy Manager|npm.sh|..." # Then this
    "Portainer|portainer.sh|..."     # Then management
    "Jellyfin|jellyfin.sh|..."       # Then optional apps
)
```

### Descriptive Names
Use clear display names:
```bash
# ✅ Good
"Nginx Proxy Manager|npm.sh|..."
"PostgreSQL 16 Database|postgres.sh|..."

# ❌ Unclear
"NPM|npm.sh|..."
"DB|postgres.sh|..."
```

### Reliable Detection
Make detection commands specific:
```bash
# ✅ Good - checks exact container
docker ps -a --format '{{.Names}}' | grep -q '^jellyfin$'

# ⚠️ Risky - might match "jellyfin-backup"
docker ps -a --format '{{.Names}}' | grep -q 'jellyfin'
```

## 🎯 Summary

**Adding a new app requires:**
1. One line in APP_REGISTRY
2. App script in apps/ folder
3. Checksum file (.sha256)

**The script automatically handles:**
- Menu display
- Installation detection
- Download & verification
- Execution

**Result:** Infinitely extensible with minimal effort! 🚀

## 📖 Related Files

- **hardening.sh** - Contains APP_REGISTRY (line ~26)
- **apps/** - Directory where all app scripts live
- **update-checksums.sh** - Generates checksums for all scripts

---

**Adding new apps is literally a one-line change!** ✨
