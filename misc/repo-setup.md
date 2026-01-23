<a href="https://github.com/vdarkobar/lab">back</a>  
  
# Simple Repository Setup - Complete Guide
  
### 1. Add Checksum Files (One Time)

```bash
# In your repo
cd apps

# Generate checksum for npm.sh
sha256sum npm.sh > npm.sh.sha256

# Commit both
git add npm.sh npm.sh.sha256
git commit -m "Add npm.sh with checksum"
git push
```

### 2. Add the Helper Script (Optional)

Copy `update-checksums.sh` to your repo root:

```bash
# Make it executable
chmod +x update-checksums.sh

# Add to repo
git add update-checksums.sh
git commit -m "Add checksum helper script"
git push
```

### 3. Update README

Copy the content from `README_TEMPLATE.md` to your repo's README.md:

```bash
# Replace or update your README.md
cp README_TEMPLATE.md /path/to/your/repo/README.md

# Review and customize
vim README.md

# Commit
git add README.md
git commit -m "Update README"
git push
```

### 4. Update Hardening Script URL

In `hardening.sh` line 26:

```bash
# Use this URL:
readonly REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh"

# Keep line 27 empty for auto-detection:
readonly REMOTE_SCRIPT_SHA256=""
```

## 📁 Final Repository Structure

```
lab/
├── README.md                    # Nice, professional README
├── update-checksums.sh         # Helper script (optional)
├── apps/
│   ├── npm.sh                   # Your script
│   └── npm.sh.sha256           # Checksum (66 bytes)
└── server/
    └── hardening.sh            # Hardening script
```


## 🔄 Daily Workflow

### When You Update npm.sh:

**Option A: Using Helper Script (Recommended)**
```bash
# 1. Edit your script
vim apps/npm.sh

# 2. Run helper
./update-checksums.sh

# 3. Commit
git add apps/npm.sh apps/npm.sh.sha256
git commit -m "Update npm script"
git push
```

**Option B: Manual**
```bash
# 1. Edit your script
vim apps/npm.sh

# 2. Regenerate checksum
cd apps
sha256sum npm.sh > npm.sh.sha256
cd ..

# 3. Commit
git add apps/npm.sh apps/npm.sh.sha256
git commit -m "Update npm script"
git push
```

## ✅ What Happens When Script Runs

```
User runs: ./hardening.sh
    ↓
Script downloads npm.sh from:
https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh
    ↓
Script looks for checksum at:
https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh.sha256
    ↓
Finds it! ✓
    ↓
Verifies: Downloaded hash == Checksum file hash
    ↓
Match? Execute ✓
Mismatch? Abort ✗
```

## 🎨 Repository Appearance

- ✅ **Professional** - Clear structure and documentation
- ✅ **Welcoming** - Easy for others to understand and use
- ✅ **Secure** - Checksums clearly explained
- ✅ **Simple** - No unnecessary complexity
- ✅ **Maintainable** - Easy to update

## 🔐 Security Level

| Feature | Status |
|---------|--------|
| Integrity verification | ✅ SHA256 |
| Tamper detection | ✅ Yes |
| Auto-verification | ✅ Built-in |
| Complexity | ✅ Minimal |
| Maintenance | ✅ Easy |


## 🚀 Getting Started

### Complete Setup in 5 Minutes:

```bash
# 1. Navigate to your repo
cd /path/to/lab

# 2. Generate checksums
cd apps
sha256sum npm.sh > npm.sh.sha256
cd ..

# 3. Add helper script
# (copy update-checksums.sh to repo root)
chmod +x update-checksums.sh

# 4. Update README
# (copy README_TEMPLATE.md content to README.md)

# 5. Commit everything
git add .
git commit -m "Add checksums and update README"
git push

# Done! ✓
```

---

## 🆘 Quick Reference

### Generate Checksum
```bash
sha256sum npm.sh > npm.sh.sha256
```

### Verify Manually
```bash
sha256sum -c npm.sh.sha256
```

### Update All Checksums
```bash
./update-checksums.sh
```

### Commit Changes
```bash
git add *.sha256
git commit -m "Update checksums"
git push
```
