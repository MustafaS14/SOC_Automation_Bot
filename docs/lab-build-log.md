# Lab build log

How the lab was built, in order, with the exact settings and commands used. Dates are 2026-10-14 to 2026-10-16. Hostnames and IPs follow [architecture.md](architecture.md). Day-to-day running of the lab (start order, SSH, Caldera, shutdown) is in [lab-operations.md](lab-operations.md).

## Background and goal

This project is a SOC automation bot and incident triage assistant: a Discord bot that lets an analyst triage, enrich, hunt and contain security incidents from chat.

It was first designed around Microsoft Sentinel and Defender for Endpoint in Azure. It was then rebuilt as a fully local lab on Splunk, for these reasons:

- **Cost and access.** Sentinel and Defender for Endpoint need an Azure tenant, a subscription and licences that cost money or expire. A local lab is free and keeps working.
- **Safety.** Attacks are simulated between virtual machines on an isolated host-only network, never near a cloud tenant or the real LAN.
- **Control and realism.** The log pipeline (endpoint logs, Filebeat, Logstash, Splunk) is built by hand, so every stage (parsing, filtering, enrichment, detection) is understood. Splunk and Logstash are used in many real SOCs.
- **Reproducible.** Anyone with a laptop can rebuild the lab from this repository.
- **Same bot ideas, new back end.** Access control, confirm buttons, input validation and the audit log stay. Only the alert source (Splunk instead of Sentinel) and the containment method (SSH to a restricted user instead of the Defender API) change. See [bot-refactor-plan.md](bot-refactor-plan.md).

The target pipeline is: Caldera attack → victim logs (auditd, auth.log) → Filebeat → Logstash → Splunk → alert webhook → Discord bot → analyst actions. See [architecture.md](architecture.md) for the diagram.

A licensing note for the SIEM step: Splunk Free does not include alerting. Use a Splunk Enterprise trial or a developer licence, and check Splunk's current terms when you install it.

## Before you start

| Item | Used here |
|---|---|
| Computer | Windows 11 Home laptop with about 32 GB RAM. The three VMs use 4 + 4 + 8 = 16 GB |
| Disk space | About 25 GB for the victim, 20 GB for the attacker, and more for the SIEM. Keep roughly 100 GB free |
| Hypervisor | VirtualBox for Windows. The Windows hypervisor must be off (section 1). Write down your VirtualBox version when you build it |
| Terminal | Windows PowerShell, which includes an OpenSSH client |
| Browser | Any browser, for the Caldera web UI (`:8888`) and later the Splunk web UI |

ISO images, both from the Ubuntu download page:

- **Ubuntu Server 24.04.5 LTS** (live server, 64-bit PC) for the attacker and the SIEM.
- **Ubuntu Desktop 24.04.5 LTS** (64-bit PC) for the victim.

The VirtualBox interface in this build was in French, so menu names differ from English guides (for example "Disque dur" is the hard disk and "Instantané" is a snapshot).

Each VM has a user you choose during the install. Use a strong password for each and keep them in a password manager. Do not put passwords, tokens or keys in this repository.

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

## 1b. Creating the VMs (VirtualBox)

| Setting | `soc-victim` | `soc-attacker` | `soc-siem` (planned) |
|---|---|---|---|
| Operating system | Ubuntu Desktop 24.04.5 | Ubuntu Server 24.04.5 | Ubuntu Server 24.04 |
| RAM | 4 GB | 4 GB | 8 GB |
| CPUs | 1 to 2 | 2 | 2 to 4 |
| Disk | 25 GB | 20 GB | 40 GB or more |
| Adapter 1 | NAT | NAT | NAT |
| Adapter 2 | Host-only | Host-only | Host-only |
| Interfaces inside the VM | `enp0s3` (NAT), `enp0s8` (host-only) | same | same |
| Static host-only address | 192.168.56.20 | 192.168.56.30 | 192.168.56.10 |

**Network.** The NAT adapter gives each VM internet access for package installs; it appears as 10.0.2.15 inside every VM. The second adapter must be set to **Host-only** on VirtualBox's default host-only network, where Windows itself is `192.168.56.1` on `192.168.56.0/24`. The VMs use fixed addresses on that network, so the lab does not depend on DHCP.

**Installer choices.**

- **Attacker (Server installer):** tick *Install OpenSSH server*; on the storage screen untick *Set up this disk as an LVM group* so the whole disk is used; use the hostname `soc-attacker`.
- **Victim (Desktop installer):** a minimal installation is enough. The hostname is set to `soc-victim` after the install (section 2). When the install finishes, shut the VM down, remove the ISO from the optical drive, and put the hard disk first in the boot order. Otherwise the installer appears on every boot.

After the install and the network configuration in sections 2 and 3, take a snapshot called `clean base` before changing anything else. How to take and restore snapshots is in [lab-operations.md](lab-operations.md).

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

## 6. Bot migration and review (2026-10-16 to 2026-10-17)

The Discord bot was first written for Microsoft Sentinel and Defender. It was migrated to this lab's design: Splunk alert webhook, SQLite incident store, `/hunt` through the Splunk REST API, and isolation over SSH as a restricted `responder` user. The plan is in [bot-refactor-plan.md](bot-refactor-plan.md).

How it was done: the plan was written here, the code was written by a coding assistant in a separate editor, and each commit was then read back and checked against a list. Findings were fixed and the next commit was checked again.

| Commit | What it did |
|---|---|
| `7cc13eb` | Moved the bot from Azure to Splunk, SQLite and SSH |
| `13439f5` | Hardened the webhook, SSH name resolution and config; removed the last Azure code |
| `8e8432a` | Deny-list on unisolate, safer mock mode, escaped Splunk text, command tests |
| `49f9f49` | Cleanup: verb-specific refusal text, alert link host checks, mock banner, enrichment edge cases |

The findings and fixes are listed in [security-review.md](security-review.md). Status: unit-tested, but not yet run against a live Splunk or a real isolation.

## 7. Next

- Build `soc-siem` (Ubuntu Server 24.04, 8 GB RAM, `192.168.56.10`) with Splunk and Logstash in Docker.
- Install Filebeat on the victim and ship `/var/log/audit/audit.log` and `/var/log/auth.log`.
- Write the first SPL detection (for the Discovery scenario) and the webhook alert action.
- On the victim, create the `responder` user from [`infra/responder/`](../infra/responder/): install the scripts and the sudoers entry, and restrict the SSH key with a forced command.
- Run the bot in real mode, send a test alert with `curl`, then a real Caldera run; test isolation from a snapshot first.
- Further ideas are in [roadmap.md](roadmap.md).
