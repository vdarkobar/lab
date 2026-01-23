<a href="https://github.com/vdarkobar/lab">back</a>  
  
# Checksum Verification Guide

## 🔐 Why Verify Checksums?

Both scripts in your lab repository have checksums to ensure:
- ✅ Files haven't been tampered with
- ✅ Download completed successfully
- ✅ You're running the exact code from the repository

## 📦 Scripts with Checksums

Your repository provides checksums for **both** scripts:

1. **hardening.sh** - The main hardening script (users download first)
2. **npm.sh** - Application installer (downloaded by hardening.sh)

## 🔍 Manual Verification (For Users)

### Verify hardening.sh Before Running

Users should verify `hardening.sh` **before** executing it:

```bash
# Download both files
wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh.sha256

# Verify integrity
sha256sum -c hardening.sh.sha256

# Expected output:
# hardening.sh: OK ✓

# If verification passes, run it
chmod +x hardening.sh
./hardening.sh
```

### What the Output Means

```bash
# ✅ Success - Safe to run
hardening.sh: OK

# ❌ Failure - DO NOT RUN
hardening.sh: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
```

## 🤖 Automatic Verification (Built-in)

The `hardening.sh` script **automatically** verifies `npm.sh`:

```
User runs: ./hardening.sh
    ↓
Script downloads npm.sh
    ↓
Script downloads npm.sh.sha256
    ↓
Script verifies checksum automatically
    ↓
Match? ✓ Execute
Mismatch? ✗ Abort with error
```

**Users don't need to manually verify npm.sh** - it's done automatically!

## 📋 Checksum Workflow

### User's Perspective

```
1. Download hardening.sh + checksum
2. Verify manually (sha256sum -c)
3. Run hardening.sh
4. hardening.sh verifies npm.sh automatically
5. Everything is verified! ✓
```

### Your Perspective (Maintenance)

```
1. Edit any script (npm.sh or hardening.sh)
2. Run: ./update-checksums.sh
3. Commit both script and .sha256 file
4. Push to GitHub
5. Checksums auto-updated! ✓
```

## 🛠️ Generating Checksums

### Automatic (Recommended)

```bash
# In your lab repository root
./update-checksums.sh

# Output:
━━━ Processing apps/ ━━━
  ✓ npm.sh
    abc123def456...

━━━ Processing server/ ━━━
  ✓ hardening.sh
    789ghi012jkl...

✓ Generated checksums for 2 script(s)
```

### Manual (If Needed)

```bash
# For npm.sh
cd apps
sha256sum npm.sh > npm.sh.sha256

# For hardening.sh
cd server
sha256sum hardening.sh > hardening.sh.sha256
```

## 📝 Checksum File Format

Each `.sha256` file contains one line:

```
abc123def456789...  npm.sh
```

Format: `<hash><space><filename>`

## ✅ Best Practices

### For Repository Maintainers (You)

1. **Always update checksums** after editing scripts
2. **Use update-checksums.sh** for consistency
3. **Commit both files together**:
   ```bash
   git add apps/npm.sh apps/npm.sh.sha256
   git commit -m "Update npm script"
   ```
4. **Never commit script without checksum**

### For Users

1. **Always verify hardening.sh** before first run
2. **Trust automatic verification** for subsequent scripts
3. **If checksum fails, DO NOT RUN** - contact you
4. **Keep checksums with scripts** if storing locally

## 🔗 Quick Reference URLs

### For Manual Verification

```bash
# hardening.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh.sha256
sha256sum -c hardening.sh.sha256

# npm.sh (if needed manually)
wget https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh.sha256
sha256sum -c npm.sh.sha256
```

## 🆘 Troubleshooting

### Checksum Mismatch

**Problem:**
```
npm.sh: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
```

**Causes:**
- Download was corrupted
- File was modified
- Wrong version downloaded
- Cache issue

**Solution:**
```bash
# Delete and re-download
rm npm.sh npm.sh.sha256
wget https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/apps/npm.sh.sha256

# Verify again
sha256sum -c npm.sh.sha256
```

### Checksum File Not Found

**Problem:**
```
wget: ERROR 404: Not Found.
```

**Causes:**
- Checksum file not committed
- Wrong URL
- File not pushed to GitHub

**Solution:**
```bash
# Verify checksum file exists in repo
# Regenerate if needed
sha256sum npm.sh > npm.sh.sha256
git add npm.sh.sha256
git commit -m "Add missing checksum"
git push
```

## 📊 Security Level

| Check | Without Checksum | With Checksum |
|-------|------------------|---------------|
| **Tamper Detection** | ❌ None | ✅ Immediate |
| **Download Corruption** | ❌ Unknown | ✅ Detected |
| **MITM Attack** | ❌ Vulnerable | ✅ Protected* |
| **Trust Verification** | ❌ Blind trust | ✅ Verified |

*Assuming attacker can't compromise both script AND checksum

## 🎯 Summary

**Two-layer verification:**

1. **Layer 1 (Manual):** Users verify `hardening.sh`
   - Prevents running tampered hardening script
   - One-time verification before first run

2. **Layer 2 (Automatic):** Script verifies `npm.sh`
   - Prevents running tampered applications
   - Happens automatically every time

**Result:** Complete chain of trust from repository to execution! 🔐

## 📚 Additional Resources

- **SIMPLE_SETUP_COMPLETE.md** - Complete setup guide
- **README_TEMPLATE.md** - User-facing documentation
- **update-checksums.sh** - Automatic checksum generator

---

**Remember:** Checksums are only 66 bytes each, but provide enterprise-level security! 🛡️
