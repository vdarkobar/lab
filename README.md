## *Self-hosted Home(lab) Cloud*
<p align="center">
  <em>
    <a href="https://github.com/vdarkobar/lab/tree/main/misc/Proxmox.md">Proxmox</a> > 
    <a href="https://github.com/vdarkobar/lab/tree/main/misc/Debian.md">Debian VM/LXC</a>
  </em>
</p>
  
#### *Install <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
# Quick Install (convenient):
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh)"
```
```bash
# Verified Install (recomended):
wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh && \
wget https://raw.githubusercontent.com/vdarkobar/lab/main/bootstrap.sh.sha256 && \
sha256sum -c bootstrap.sh.sha256
```
```bash
chmod +x bootstrap.sh && \
./bootstrap.sh  
```

<br>

<pre>
<a href="https://github.com/vdarkobar/lab/tree/main/misc/Bootstrap.md">bootstrap.sh</a> (context-aware)


ON PVE HOST:
├── 1) <a href="https://github.com/vdarkobar/lab/tree/main/misc/DebianVMTemplate.md">Create Debian VM Template</a>
├── 2) <a href="https://github.com/vdarkobar/lab/tree/main/misc/DebianLXCTemplate.md">Create Debian LXC Template</a>
└── 3) Exit

ON DEBIAN VM/LXC:
├── 1) <a href="https://github.com/vdarkobar/lab/tree/main/misc/HardenDebianSystem.md">Harden Debian System</a> ───────────┐
├── 2) <a href="https://github.com/vdarkobar/lab/tree/main/misc/JumpServer.md">Setup Jump Server</a>               │
└── 3) Exit                            │
                                       ▼
                                   App Menu
                                   ├── 1) <a href="https://github.com/vdarkobar/lab/tree/main/misc/Docker.md">Docker</a>
                                   ├── 2) <a href="https://github.com/vdarkobar/lab/tree/main/misc/NginxProxyManager.md">Nginx Proxy Manager (native)</a>
                                   ├── 3) <a href="https://github.com/vdarkobar/lab/tree/main/misc/NginxProxyManagerDocker.md">Nginx Proxy Manager (Docker)</a>
                                   ├── 4) <a href="https://github.com/vdarkobar/lab/tree/main/misc/Cloudflared.md">Cloudflared</a>
                                   ├── 5) <a href="https://github.com/vdarkobar/lab/tree/main/misc/UnboundDNS.md">Unbound DNS</a> ───────┐
                                   ├── 6) <a href="https://github.com/vdarkobar/lab/tree/main/misc/SambaFileServer.md">Samba File Server</a>   │
                                   ├── 7) <a href="https://github.com/vdarkobar/lab/tree/main/misc/BookStack.md">BookStack</a>           │
                                   ├── 8) <a href="https://github.com/vdarkobar/lab/tree/main/misc/BentoPDF.md">BentoPDF</a>            │
                                   └── N) Done                │
                                                              ▼
                                                         Config Menu
                                                         ├── 1) Configure VLANs
                                                         ├── 2) Configure Hosts
                                                         └── 3) Skip


CLI (Non-Interactive):
./bootstrap.sh --vm-template   # Create VM template
./bootstrap.sh --lxc-template  # Create LXC template  
./bootstrap.sh --harden        # Run hardening
./bootstrap.sh --jump          # Setup jump server
./bootstrap.sh --download-only # Download only
</pre>
