# Simple Repository Setup - Complete Guide

<a href="https://github.com/vdarkobar/lab">back</a>  

## 🎯 Your Choice: Simple & Clean

You've chosen to keep your repository simple without GitHub Actions, workflows, or releases. Great choice for personal projects!

## 📦 What You Need to Do

### 1. Add Checksum Files (One Time)

Generate checksums for **both** scripts:

```bash
# In your repo - generate checksum for npm.sh
cd apps
sha256sum npm.sh > npm.sh.sha256
cd ..

# Generate checksum for hardening.sh
cd server
sha256sum hardening.sh > hardening.sh.sha256
cd ..

# Commit all files
git add apps/npm.sh apps/npm.sh.sha256 server/hardening.sh server/hardening.sh.sha256
git commit -m "Add scripts with checksums"
git push
```

**Or use the helper script:**
```bash
# Generates checksums for all scripts at once
./update-checksums.sh
git add apps/*.sha256 server/*.sha256
git commit -m "Add checksums"
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

### 3. Update Your README

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
    ├── hardening.sh            # Hardening script
    └── hardening.sh.sha256     # Checksum (66 bytes)
```

Clean, simple, no bloat!

## 🔄 Your Daily Workflow

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

With the README template, your repo will look:

- ✅ **Professional** - Clear structure and documentation
- ✅ **Welcoming** - Easy for others to understand and use
- ✅ **Secure** - Checksums clearly explained
- ✅ **Simple** - No unnecessary complexity
- ✅ **Maintainable** - Easy to update

## 📊 File Sizes

Your repository stays lean:

```
README.md                 ~8 KB  (comprehensive but concise)
update-checksums.sh       ~2 KB  (helper script)
npm.sh                   ~15 KB  (your script)
npm.sh.sha256            66 bytes (just the hash!)
hardening.sh             ~40 KB  (the hardening script)
hardening.sh.sha256      66 bytes (just the hash!)
```

**Total overhead for security: 132 bytes (2 checksums)!**

## 🔐 Security Level

| Feature | Status |
|---------|--------|
| Integrity verification | ✅ SHA256 |
| Tamper detection | ✅ Yes |
| Auto-verification | ✅ Built-in |
| Complexity | ✅ Minimal |
| Maintenance | ✅ Easy |

**You get enterprise-level security without enterprise-level complexity!**

## 🚀 Getting Started Right Now

### Complete Setup in 5 Minutes:

```bash
# 1. Navigate to your repo
cd /path/to/lab

# 2. Generate checksums for apps
cd apps
sha256sum npm.sh > npm.sh.sha256
cd ..

# 3. Generate checksum for hardening script
cd server
sha256sum hardening.sh > hardening.sh.sha256
cd ..

# 4. Add helper script (optional but recommended)
# Copy update-checksums.sh to repo root
chmod +x update-checksums.sh

# 5. Update README
# Copy README_TEMPLATE.md content to README.md

# 6. Commit everything
git add .
git commit -m "Add checksums and update README"
git push

# Done! ✓
```

## 📝 Files Provided to You

1. **SIMPLE_SETUP_COMPLETE.md** - This complete guide
2. **README_TEMPLATE.md** - Professional README for your repo
3. **update-checksums.sh** - Helper script for easy updates
4. **hardening.sh** - Already updated to support this!

## ✨ Benefits Recap

✅ **No GitHub Actions** - No workflows to maintain  
✅ **No Releases** - No tagging complexity  
✅ **Simple Updates** - Edit → checksum → commit  
✅ **Still Secure** - Full SHA256 verification  
✅ **Professional** - Nice README, clean structure  
✅ **Easy Maintenance** - Anyone can understand it  

## 🎯 Summary

**Three files make it work:**
1. `npm.sh` - Your script
2. `npm.sh.sha256` - The checksum (auto-generated)
3. `README.md` - Professional documentation

**One command updates checksums:**
```bash
./update-checksums.sh
```

**Zero complexity, maximum security!**

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

---

**Your repository will be:**
- Clean ✓
- Simple ✓
- Secure ✓
- Professional ✓

Exactly what you wanted! 🎉
