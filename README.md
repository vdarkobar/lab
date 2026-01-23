## *Self-hosted Home(lab) Cloud*
  
<a href="https://github.com/vdarkobar/lab/blob/main/misc/repo-setup.md#simple-repository-setup---complete-guide">*Repo setup*</a>  
<a href="https://github.com/vdarkobar/lab/blob/main/misc/checksum-verification.md#checksum-verification-guide">*Checksum verification*</a>  

  
#### *VM Template <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
# run inside pve shell
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/refs/heads/main/all/debvm/vm01.sh)"
```
  
#### *LXC Template <a href="https://github.com/vdarkobar/cloud/blob/main/all/debct/setup.md"> * </a>*:
```bash
# run inside pve shell
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/cloud/refs/heads/main/all/debct/lxc01.sh)"
```  
  
#### *Server hardening script, download + verify <a href="https://github.com/vdarkobar/cloud/blob/main/all/debvm/setup.md"> * </a>*:
```bash
# run inside VM/LXC shell
wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh && wget https://raw.githubusercontent.com/vdarkobar/lab/main/server/hardening.sh.sha256 && sha256sum -c hardening.sh.sha256
```
