# Lab build log

How the lab was built, in order, with the exact settings and commands used. Dates are 2026-10-14 to 2026-10-16. Hostnames and IPs follow [architecture.md](architecture.md).

## 1. Host preparation (Windows 11 Home, VirtualBox)

VirtualBox needs the Windows hypervisor off. With it on, guests froze at boot with `RCU stall` / `soft lockup` kernel traces, or aborted with `WHvSetupPartition failed: E_ACCESSDENIED`.

1. Windows Security → Device security → Core isolation → turn **Memory integrity** off.
2. Windows Features → untick **Virtual Machine Platform** and **Windows Hypervisor Platform**.
3. In an administrator PowerShell:
   ```powershell
   bcdedit /set hypervisorlaunchtype off
   ```
4. Restart Windows. Confirm with `bcdedit /enum {current} | findstr hypervisorlaunchtype` (should say `Off`).

Also: plug the laptop in while running the VMs. On battery the CPU is throttled and guests are more likely to stall.

## 2. Victim VM (`soc-victim`)

- Ubuntu Desktop 24.04, 4 GB RAM, 25 GB disk, two adapters (NAT + Host-only).
- After installing, remove the ISO and make **Disque dur** first in the boot order. Otherwise the installer menu appears on every boot.

Static host-only address with NetworkManager (Ubuntu Desktop uses NetworkManager, not plain netplan):

```bash
sudo hostnamectl set-hostname soc-victim
sudo sed -i 's/mus-VirtualBox/soc-victim/g' /etc/hosts
sudo apt install -y openssh-server auditd curl
sudo systemctl enable --now ssh

CON=$(nmcli -g GENERAL.CONNECTION device show enp0s8)
sudo nmcli con mod "$CON" ipv4.method manual ipv4.addresses 192.168.56.20/24 ipv6.method ignore
sudo nmcli con up "$CON"
```

`50-cloud-init.yaml` still set `dhcp4: true` on `enp0s8`, so the interface kept a second DHCP address. Fix:

```bash
sudo sed -i 's/dhcp4: true/dhcp4: false/' /etc/netplan/50-cloud-init.yaml
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
sudo netplan apply
sudo chmod 600 /etc/netplan/*.yaml
```

### auditd rule

Log every executed command, tagged so Splunk can filter on it:

```bash
echo '-a always,exit -F arch=b64 -S execve -k exec_cmd' | sudo tee /etc/audit/rules.d/soc.rules
sudo augenrules --load
sudo auditctl -l
```

The same rule is stored in [`infra/auditd/soc.rules`](../infra/auditd/soc.rules).

## 3. Attacker VM (`soc-attacker`) and Caldera

- Ubuntu Server 24.04.5, 4 GB RAM, 2 CPUs, 20 GB disk. **LVM was left unticked** during install, otherwise the root volume uses only half of the disk.
- Static address `192.168.56.30/24` on `enp0s8` through `/etc/netplan/50-cloud-init.yaml`, written over SSH because the VM console mangles pasted YAML.

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.56.30/24
```

- Ubuntu 24.04 starts SSH through socket activation; if the service is disabled, run `sudo systemctl enable --now ssh`.

### Installing Caldera

```bash
sudo apt install -y git python3-venv python3-pip golang-go tmux
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile

# Caldera's web UI build (Vite 7) needs Node >= 20.19. Ubuntu's apt ships Node 18, so use NodeSource:
sudo apt remove -y nodejs npm
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

cd ~ && git clone https://github.com/mitre/caldera.git --recursive && cd caldera
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

tmux new -s caldera
python3 server.py --build     # first run only; later: python3 server.py
```

First start notes:

- The UI build takes about 7 minutes, and the **atomic** plugin then clones the Atomic Red Team repo (hundreds of MB), which looks like a hang but is a download.
- Caldera prints the `red` and `blue` credentials once, then stores them **hashed** in `conf/local.yml`. Save the password at that moment.
- If you regenerate `conf/local.yml`, Caldera must be started with `--fresh` so it drops state encrypted with the old key.
- The `builder` plugin error (`No module named 'docker'`), the Gist C2 warning and the `mingw-gcc` warning are harmless for this lab.
- Run **one** server instance. A second one fails with `[Errno 98] address already in use` on ports 8888 and 8022.

Web UI: `http://192.168.56.30:8888`, user `red`.

## 4. First attack

1. In the UI: **Agents → Deploy an agent → Sandcat → linux**. Set `app.contact.http` to `http://192.168.56.30:8888`. The default `0.0.0.0` is the listen address, not a reachable one.
2. Paste the generated command on the victim. The agent beacons within about 30 seconds (`Beacon (HTTP): ALIVE`).
3. **Operations → Create operation**: adversary **Discovery**, group `red`, planner `atomic`, obfuscator `plain-text`.
4. Check the evidence on the victim:
   ```bash
   sudo ausearch -k exec_cmd -i --start recent | grep proctitle | grep -vE 'ausearch|tail|sudo|grep' | tail -20
   ```

Result: see [`attack-scenarios/01-discovery.md`](../attack-scenarios/01-discovery.md).

## 5. Snapshots (VirtualBox)

| VM | Snapshot chain |
|---|---|
| `soc-attacker` | `clean base` → `caldera installed` |
| `soc-victim` | `clean base` → `network ready` → `agent working` |

## 6. Next

- Build `soc-siem` (Ubuntu Server 24.04, 8 GB RAM, `192.168.56.10`) with Splunk and Logstash in Docker.
- Install Filebeat on the victim and ship `/var/log/audit/audit.log` and `/var/log/auth.log`.
- Write SPL detections, add the alert webhook, finish the bot refactor.
