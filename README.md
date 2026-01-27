## *Self-hosted Home(lab) Cloud*
  
  
#### *Install <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
# Quick Install (convenient):
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
```

```bash
# Verified Install (RECOMMENDED):
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

<br>

```
bootstrap.sh
│
└── Menu
    ├── 1) Debian VM Template
    ├── 2) Debian LXC Template
    ├── 3) Harden Debian System ──┐
    └── 4) Exit                   │
                                  ▼
                             App Menu
                             ├── 1) Docker
                             ├── 2) Nginx Proxy Manager
                             ├── 3) Portainer
                             ├── 4) Unbound DNS ──┐
                             └── N) Done          │
                                                  ▼
                                             Config Menu
                                             ├── 1) Configure VLANs
                                             ├── 2) Configure Hosts
                                             └── 3) Skip
```
