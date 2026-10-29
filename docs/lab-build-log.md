# Lab build log

How the lab was built, in order, with the exact settings and commands used. Dates are 2026-10-14 to 2026-10-21. Hostnames and IPs follow [architecture.md](architecture.md). Day-to-day running of the lab (start order, SSH, Caldera, shutdown) is in [lab-operations.md](lab-operations.md).

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

| Setting | `soc-victim` | `soc-attacker` | `soc-siem` |
|---|---|---|---|
| Operating system | Ubuntu Desktop 24.04.5 | Ubuntu Server 24.04.5 | Ubuntu Server 24.04.5 |
| RAM | 4 GB | 4 GB | 8 GB |
| CPUs | 1 to 2 | 2 | 2 |
| Disk | 25 GB | 20 GB | 50 GB |
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

## 7. SIEM VM: Splunk in Docker (2026-10-21)

The `soc-siem` VM hosts Splunk Enterprise in a container. Logstash and the bot are added to the same VM later.

**VM and install.** Settings are in the table in section 1b (8 GB RAM, 2 CPUs, 50 GB disk, both adapters). Installer choices: Ubuntu Server 24.04.5, *Install OpenSSH server*, hostname `soc-siem`. After the install the VM was started without a GUI window and reached over SSH from PowerShell.

**Network.** The installer showed `enp0s3` (NAT, 10.0.2.15) and `enp0s8` (host-only, a DHCP address). The host-only interface was given the fixed address `192.168.56.10`. `/etc/netplan/50-cloud-init.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.56.10/24
```

Cloud-init is told to leave the network alone (`network: {config: disabled}` in `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`), the file is set to mode 600, and `sudo netplan apply` is run from the SSH session. The same steps as for the other two VMs, see [troubleshooting.md](troubleshooting.md).

**Updates and Docker.** After `sudo apt update && sudo apt upgrade -y`, Docker came from the Ubuntu packages:

```bash
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER      # log out and in again
docker run --rm hello-world        # test
```

This Docker version stores images through containerd, so the space is used under `/var/lib/containerd`, not `/var/lib/docker`. Watch that directory when checking disk use.

**Splunk container.** The files live in `~/siem/` on the VM. The compose file is in [`infra/siem/docker-compose.yml`](../infra/siem/docker-compose.yml) and the variable names are in [`infra/siem/.env.example`](../infra/siem/.env.example). The real `.env` holds the admin password and the HEC token, is created on the VM with mode 600 (`chmod 600 .env`), and is never committed (`.env` is in `.gitignore`).

```bash
mkdir -p ~/siem && cd ~/siem
# create .env from infra/siem/.env.example, then:
chmod 600 .env
docker compose up -d
docker compose logs -f             # Ctrl+C leaves the log view, the container keeps running
docker ps                          # wait for "(healthy)"
```

- The image is `splunk/splunk:latest` (about 1.9 GB). The pull can look stuck for several minutes because the layers are extracted after the download; disk use and the load average show that it is still working.
- The first start runs an Ansible playbook that sets up Splunk. It finished with `failed=0` and the line `Ansible playbook complete, will begin streaming splunkd_stderr.log`, and `docker ps` then showed the container as `healthy`.
- `SPLUNK_START_ARGS: --accept-license` and `SPLUNK_GENERAL_TERMS` in the compose file mean that you accept Splunk's licence terms. Read them first. The Enterprise trial lasts 60 days and includes alerting. After that the licence drops to Free, which has no alerting, so a developer licence is needed later.
- Ports: 8000 (web), 8088 (HEC), 8089 (REST). The web UI is at `http://192.168.56.10:8000` (plain HTTP), user `admin`, password from `.env`.

**Problem during the first login.** Soon after the first login the page showed *Disconnected from Splunk server*, and the Splunk health panel showed *IOWait* as red. `dmesg` on the VM listed `watchdog: BUG: soft lockup` messages (CPU stuck for 114 s and more). The cause is the same hypervisor and slow-disk problem described in [troubleshooting.md](troubleshooting.md), made visible by Splunk's heavy first-start disk use. Settings changed on the VM: *Use host I/O cache* on the SATA controller, *Solid-state Drive* on the disk, and *Paravirtualization Interface = KVM* under System, Acceleration. These settings alone were not enough; the final fix is in section 7b.

**Status.** Splunk runs and the web UI works. The indexes, the HEC token and Logstash are covered in sections 8 and 9.

**7b. The freezes, and the final fix (2026-10-28).** The freezes came back on the next start: the load average climbed to 47 and then 121, the web page showed *Disconnected*, and the kernel printed *soft lockup* messages. Everything was then tried in this order:

1. The I/O settings above helped a little but did not remove the problem.
2. The Windows hypervisor was still on `auto`. It cannot simply be switched off on this laptop because WSL (Linux inside Windows) is needed for other work.
3. The VM had only 2 CPUs, which is too few when Splunk starts, because it runs a long setup script and many helper processes at the same time.
4. **Fix: 4 CPUs for `soc-siem`** (the laptop has 8 cores / 16 logical processors, so there is room). With this, the load average stays around 1 and no lockups appear, **with the hypervisor still on `auto`**.

If freezes ever return, the fallback is `bcdedit /set hypervisorlaunchtype off` followed by a Windows restart. A less drastic variant is a second Windows boot entry with the hypervisor off (`bcdedit /copy {current} /d "Windows - SOC lab (no hypervisor)"`, then set that new entry to off), so WSL keeps working in the normal entry. Section 1 of this log recommends turning the hypervisor off; that is still the safest setting, but it is not required for the lab as it is now.

Two habits make the SIEM much more comfortable:

- **A slow boot is normal.** Splunk's container repeats its setup script every time it starts, so it takes 10 to 15 minutes to become `healthy` in `docker ps`. During that time the health check may show *starting* or *unhealthy*. Wait; do not open the web page until it says `healthy`.
- **Do not power the SIEM off; save its state.** In VirtualBox use *Close, Save the machine state* instead of `poweroff`. The VM then resumes in seconds with Splunk already running. Keep about 20 GB of the 50 GB disk free.

**In simple words.** The control-room computer was too weak for the job and kept freezing. Giving it more processor power fixed it, and instead of turning it off every day we "pause" it, like a laptop lid, so it wakes up fast.

## 8. Indexes, HEC and the first test event (2026-10-28)

**In simple words.** Splunk is an archive. Before it can store anything we create labelled drawers (*indexes*) and a front door with a password (*HEC*, the HTTP Event Collector) that the sorting office will use to deliver the notes.

1. **Two indexes** were created in Splunk Web (Settings, Indexes, New Index): `linux` for everything from the victim, and `soc_audit` reserved for later use (detections and the bot's own records).
2. **The HEC token** (`splunk_hec_token`, created from the value in `.env`) was edited to allow both indexes, with `linux` as the default.
3. **HEC test.** HEC listens on port 8088 over **HTTPS with a self-signed certificate**, so a test needs `curl -k`. The token comes from `.env` and is never typed into the chat or committed:

   ```bash
   cd ~/siem && set -a && . ./.env && set +a
   curl -k https://localhost:8088/services/collector/event \
     -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
     -d '{"event":"hello from hec","index":"linux"}'
   ```

   The answer is `{"text":"Success","code":0}`. In Splunk Search, `index=linux` then showed the event.
4. **A first mistake worth remembering:** a search that returns nothing usually means the *time range* (it was on "Previous month") or a typo (`iindex`), not missing data. Use *Last 24 hours*.

## 9. Logstash: the sorting office (2026-10-28)

**In simple words.** Raw logs are messy. Logstash reads each line, throws away what we do not need, adds a label saying what kind of line it is, works out the true time of the event, and hands it to Splunk.

Logstash 8.17.0 runs as a second container in the same compose file, [`infra/siem/docker-compose.yml`](../infra/siem/docker-compose.yml), and starts only after Splunk reports `healthy`. Its pipeline is [`infra/siem/logstash/pipeline/soc.conf`](../infra/siem/logstash/pipeline/soc.conf), which on the VM lives in `~/siem/logstash/pipeline/`. It does three things:

- **Input:** listens for Filebeat on port 5044. TLS is not used between Filebeat and Logstash; the traffic stays on the isolated host-only network, which is an acceptable simplification for a lab and is noted as such.
- **Filter:** labels each line `linux:audit` or `linux:auth`, drops the repeated bulky audit record types (see section 11) and the hourly `debian-sa1` job, and extracts the **real event time**. For audit lines that is the number inside `msg=audit(…)` (seconds since 1970); for auth lines it is the ISO date at the start of the line. Without this, every event would carry the time it *arrived* instead of the time it *happened*.
- **Output:** sends each event to Splunk's HEC over HTTPS with the token from the environment variable `SPLUNK_HEC_TOKEN` (never written in the file). `ssl_verification_mode => none` is used because the certificate is self-signed; this is acceptable **only** in this closed lab.

Problems met:

- Logstash logged errors about `elasticsearch:9200` and `licensereader`. It tries to report its own health to Elasticsearch by default. Fixed with `XPACK_MONITORING_ENABLED: "false"` in the compose file.
- **Logstash reads every file in the pipeline folder.** A backup called `soc.conf.bak` was left there; Logstash loaded it as a second pipeline, so events got the label twice (`linux:auth,linux:auth`) and audit events disappeared. Backups must live outside that folder.
- Long commands pasted into the SSH window arrived garbled (stray `[200~` characters, a trailing `~`). The fix was to check the file with `wc -l` and `cat` and to type short commands by hand.

## 10. Filebeat on the victim (2026-10-28)

**In simple words.** Filebeat is the courier. It sits on the victim, watches two log files and sends every new line to Logstash, remembering how far it has read so nothing is sent twice.

- Installed from Elastic's apt repository (version 8.x, matching Logstash 8.17.0). The configuration is [`infra/filebeat/filebeat.yml`](../infra/filebeat/filebeat.yml): two `filestream` inputs (`/var/log/audit/audit.log` and `/var/log/auth.log`) and `output.logstash` pointing at `192.168.56.10:5044`.
- Checks before starting: `sudo filebeat test config` printed `Config OK` and `sudo filebeat test output` reached Logstash. Then `sudo systemctl enable --now filebeat`.
- Filebeat remembers its position in `/var/lib/filebeat/registry`. Deleting that folder (with Filebeat stopped) makes it read the files again from the start, which is useful after wiping an index.
- Reading the audit log needs root; the Filebeat service runs as root, which is the default.
- Connecting to the victim by SSH needs the user created during the installation, not the VM's name (a login with the VM name gave *Invalid user*).

## 11. Tuning: cutting the noise (2026-10-29)

**In simple words.** The first run was like recording every sound in the shop, including the fridge hum: more than **135,000 events**. A real analyst cannot read that. We told the cameras to record only people, and told the sorting office to drop the repetitive parts.

What was wrong: the first auditd rule recorded every program started on the machine, including thousands by background services (including the Splunk container's own activity). Each command also produced several extra audit lines (`PATH`, `CWD`, `BPRM_FCAPS`, `PROCTITLE`) that repeat information already in the main record.

What was changed:

1. **auditd rule limited to login sessions.** [`infra/auditd/soc.rules`](../infra/auditd/soc.rules) now has `-F auid>=1000 -F auid!=4294967295`. The *audit user id* (`auid`) is the person who originally logged in, even after `sudo`; background services have no login and are skipped. The Caldera agent was started from a login session, so it is still seen (`auid=1000`, `uid=0`).
2. **Logstash drops** the four repetitive record types and the `debian-sa1` cron job.
3. **A clean restart of the data:** the `linux` index was deleted and re-created in Splunk (Settings, Indexes), and Filebeat's registry was reset so the victim's logs were read again from the start through the new filters.

Trade-off, on purpose: **a command started by a service with no login session is not recorded.** For the first detection (an attacker acting through a session) that is acceptable. A second, narrow rule watching known reconnaissance tools could be added later if needed.

Result: the `linux` index held 213 audit events and 965 auth events (1,178 in total) instead of well over 135,000, with only the wanted audit record types (`SYSCALL`, `EXECVE`, `USER_*`, `CRED_*` and similar).

## 12. Checking the result (2026-10-29)

**In simple words.** We did a live test: type four ordinary commands on the victim and see if they show up in the archive, with the right time.

- Commands typed on the victim: `whoami`, `id`, `uname -a`, `hostname`.
- Splunk search: `index=linux sourcetype=linux:audit earliest=-5m type=EXECVE | table _time a0 a1 a2`. All four commands appeared, with times such as `14:39:29.724` UTC, which is 15:39 on the victim's local clock (CET). The fields `a0`, `a1` (the command and its first argument) are already split out, which makes writing detections easier.
- **Clocks:** both VMs report *System clock synchronized: yes*. The victim shows local time (CET, UTC+1), the SIEM shows UTC; Splunk compares real instants, so this does not matter. Always compare times in UTC when in doubt.
- **Lag:** the search `| eval lag=round(_indextime-_time) | stats count avg(lag) max(lag)` compares when an event *happened* with when Splunk *stored* it. Over the last 15 minutes it gave an average of 67 s and a maximum of 253 s, and right after the reset 434 s and 984 s. These high numbers come from the backlog Filebeat replayed after the reset (old lines delivered late), not from wrong timestamps. Fresh events arrive within a few seconds. When measuring, look at a short recent window.

Snapshots taken at this point: `soc-siem` and `SOC-Victim-Ubuntu`, both named `pipeline tuned`.

## 13. Next

- Start `SOC-Attacker`, run a fresh Caldera *Discovery* operation (group `red`, adversary Discovery, planner atomic, obfuscator plain-text) and look at what reaches Splunk.
- Write the first SPL detection for it (commands such as `whoami`, `id`, `uname`, `ps`, `hostname` run by a login session as root), labelled with MITRE ATT&CK techniques (T1087.001, T1057, T1033, T1082), then a Splunk alert that calls the bot's webhook. The built-in Splunk webhook cannot add the secret header the bot expects, so a small custom alert action or a relay is needed.
- On the victim, create the `responder` user from [`infra/responder/`](../infra/responder/): install the scripts and the sudoers entry, and restrict the SSH key with a forced command.
- Run the bot in real mode, send a test alert with `curl`, then a real Caldera run; test isolation from a snapshot first.
- Add an AI triage layer to the bot: short summaries of incidents and an `/ask` command, with read-only tools only, log content treated as untrusted, every model call logged. See [roadmap.md](roadmap.md).
- Housekeeping: delete old intermediate snapshots to keep the disk chains short.
- Further ideas are in [roadmap.md](roadmap.md).
# Lab build log

How the lab was built, in order, with the exact settings and commands used. Dates are 2026-10-14 to 2026-10-21. Hostnames and IPs follow [architecture.md](architecture.md). Day-to-day running of the lab (start order, SSH, Caldera, shutdown) is in [lab-operations.md](lab-operations.md).

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

| Setting | `soc-victim` | `soc-attacker` | `soc-siem` |
|---|---|---|---|
| Operating system | Ubuntu Desktop 24.04.5 | Ubuntu Server 24.04.5 | Ubuntu Server 24.04.5 |
| RAM | 4 GB | 4 GB | 8 GB |
| CPUs | 1 to 2 | 2 | 2 |
| Disk | 25 GB | 20 GB | 50 GB |
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

## 7. SIEM VM: Splunk in Docker (2026-10-21)

The `soc-siem` VM hosts Splunk Enterprise in a container. Logstash and the bot are added to the same VM later.

**VM and install.** Settings are in the table in section 1b (8 GB RAM, 2 CPUs, 50 GB disk, both adapters). Installer choices: Ubuntu Server 24.04.5, *Install OpenSSH server*, hostname `soc-siem`. After the install the VM was started without a GUI window and reached over SSH from PowerShell.

**Network.** The installer showed `enp0s3` (NAT, 10.0.2.15) and `enp0s8` (host-only, a DHCP address). The host-only interface was given the fixed address `192.168.56.10`. `/etc/netplan/50-cloud-init.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.56.10/24
```

Cloud-init is told to leave the network alone (`network: {config: disabled}` in `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`), the file is set to mode 600, and `sudo netplan apply` is run from the SSH session. The same steps as for the other two VMs, see [troubleshooting.md](troubleshooting.md).

**Updates and Docker.** After `sudo apt update && sudo apt upgrade -y`, Docker came from the Ubuntu packages:

```bash
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER      # log out and in again
docker run --rm hello-world        # test
```

This Docker version stores images through containerd, so the space is used under `/var/lib/containerd`, not `/var/lib/docker`. Watch that directory when checking disk use.

**Splunk container.** The files live in `~/siem/` on the VM. The compose file is in [`infra/siem/docker-compose.yml`](../infra/siem/docker-compose.yml) and the variable names are in [`infra/siem/.env.example`](../infra/siem/.env.example). The real `.env` holds the admin password and the HEC token, is created on the VM with mode 600 (`chmod 600 .env`), and is never committed (`.env` is in `.gitignore`).

```bash
mkdir -p ~/siem && cd ~/siem
# create .env from infra/siem/.env.example, then:
chmod 600 .env
docker compose up -d
docker compose logs -f             # Ctrl+C leaves the log view, the container keeps running
docker ps                          # wait for "(healthy)"
```

- The image is `splunk/splunk:latest` (about 1.9 GB). The pull can look stuck for several minutes because the layers are extracted after the download; disk use and the load average show that it is still working.
- The first start runs an Ansible playbook that sets up Splunk. It finished with `failed=0` and the line `Ansible playbook complete, will begin streaming splunkd_stderr.log`, and `docker ps` then showed the container as `healthy`.
- `SPLUNK_START_ARGS: --accept-license` and `SPLUNK_GENERAL_TERMS` in the compose file mean that you accept Splunk's licence terms. Read them first. The Enterprise trial lasts 60 days and includes alerting. After that the licence drops to Free, which has no alerting, so a developer licence is needed later.
- Ports: 8000 (web), 8088 (HEC), 8089 (REST). The web UI is at `http://192.168.56.10:8000` (plain HTTP), user `admin`, password from `.env`.

**Problem during the first login.** Soon after the first login the page showed *Disconnected from Splunk server*, and the Splunk health panel showed *IOWait* as red. `dmesg` on the VM listed `watchdog: BUG: soft lockup` messages (CPU stuck for 114 s and more). The cause is the same hypervisor and slow-disk problem described in [troubleshooting.md](troubleshooting.md), made visible by Splunk's heavy first-start disk use. Settings changed on the VM: *Use host I/O cache* on the SATA controller, *Solid-state Drive* on the disk, and *Paravirtualization Interface = KVM* under System, Acceleration. To be confirmed after the next start with `sudo dmesg | grep -ci lockup` (expected `0`); if the freezes continue, set `bcdedit /set hypervisorlaunchtype off` and restart Windows.

**Status.** Splunk runs and the web UI works. Not done yet: the `linux` and `soc_audit` indexes, giving the HEC token access to them, a HEC test with `curl`, and a snapshot of `soc-siem` (planned name: `splunk running`).

## 8. Next

- On `soc-siem`: create the `linux` and `soc_audit` indexes, test HEC with `curl`, take the `splunk running` snapshot, then add Logstash in Docker (Beats input on 5044, HEC output to Splunk).
- Install Filebeat on the victim and ship `/var/log/audit/audit.log` and `/var/log/auth.log`.
- Write the first SPL detection (for the Discovery scenario) and the webhook alert action.
- On the victim, create the `responder` user from [`infra/responder/`](../infra/responder/): install the scripts and the sudoers entry, and restrict the SSH key with a forced command.
- Run the bot in real mode, send a test alert with `curl`, then a real Caldera run; test isolation from a snapshot first.
- Further ideas are in [roadmap.md](roadmap.md).
