## *Self-hosted Home(lab) Cloud*
  
  
#### *Install <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
# Quick Install (convenient, medium security):
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
```

```bash
# Secure Install (verified, high security - RECOMMENDED):
wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh
wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256
sha256sum -c bootstrap.sh.sha256
```

```bash
chmod +x bootstrap.sh
./bootstrap.sh  
```

<br>

<a href="https://github.com/vdarkobar/lab/blob/main/misc/repo-setup.md#simple-repository-setup---complete-guide">*Repo setup*</a>, <a href="https://github.com/vdarkobar/lab/blob/main/misc/checksum-verification.md#checksum-verification-guide">*Checksum verification*</a>, <a href="https://github.com/vdarkobar/lab/blob/main/misc/adding-apps.md#adding-new-apps-to-hardeningsh---quick-guide">*Adding apps*</a>  
