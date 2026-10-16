# Troubleshooting

Problems hit while building the lab, with the cause and the fix. Useful as a checklist when rebuilding it.

| Symptom | Cause | Fix |
|---|---|---|
| Guest freezes at boot with `RCU stall`, `soft lockup`, or a long kernel stack trace | Windows hypervisor / VBS competing with VirtualBox | Memory integrity off, unticked Windows features, `bcdedit /set hypervisorlaunchtype off`, restart. Use 1 to 2 CPUs and plug the laptop in |
| VM state `Aborted`, `WHvSetupPartition failed: E_ACCESSDENIED` | Hypervisor half-enabled | Full hypervisor-off procedure above, then restart Windows |
| Boot stops at `Begin: Loading essential drivers` | Same timing issue; occasionally a slow first boot after a snapshot | Wait about 3 minutes; if kernel errors appear, power off, use 1 CPU, start again |
| VM boots the Ubuntu **installer** every time | ISO is in the optical drive and ahead of the disk in the boot order | Remove the ISO under Storage, put **Disque dur** first under System |
| Attacker boots the Desktop ISO instead of Server | Wrong ISO attached | Power off, swap the ISO under Storage (the optical drive is only editable while off) |
| Root filesystem uses half the disk | LVM default only takes part of the disk | Untick LVM during the Ubuntu Server install |
| Multi-line YAML typed in the VM console lost its indentation | Keyboard layout mismatch in the VM window | Do configuration over SSH and paste there |
| `ssh` times out, VM is up | `ssh.service` disabled (socket-activated) | `sudo systemctl enable --now ssh` |
| `enp0s8` has two addresses (static + DHCP) | `50-cloud-init.yaml` still has `dhcp4: true` | Set it to `false`, disable cloud-init network config, `netplan apply` |
| `Permissions for ... are too open` from netplan | Netplan files readable by everyone | `sudo chmod 600 /etc/netplan/*.yaml` |
| `curl: command not found` on the victim | Ubuntu Desktop minimal | `sudo apt install -y curl` |
| `HTTP 405` from `curl -I` against Caldera | HEAD request; the page only serves GET | Not an error: Caldera answered |
| Caldera UI build fails or hangs at "Building VueJS front-end" | Node 18 from apt; Vite 7 needs Node 20.19+ | Install Node 22 from NodeSource, delete `plugins/magma/node_modules`, rebuild |
| Caldera looks stuck after the build | The atomic plugin is cloning Atomic Red Team | Check `du -sh plugins/atomic/data/atomic-red-team`, wait for it to finish |
| `[Errno 98] address already in use` (8888 / 8022) | A second `server.py` is already running | `ps aux \| grep [s]erver.py`; use the existing one or stop it first |
| Login returns 401 after regenerating config | State encrypted with the old key | Restart with `python3 server.py --fresh` |
| Passwords in `local.yml` turned into `$argon2id$...` | Caldera hashes passwords at startup | Expected. Save the password from the first-start log |
| Agent never appears in the UI | `app.contact.http` was `http://0.0.0.0:8888` | Change it to `http://192.168.56.30:8888` before copying the command |
| Hostname in the prompt did not change | The prompt is fixed when the session starts | Reconnect; `hostname` already shows the new name |
