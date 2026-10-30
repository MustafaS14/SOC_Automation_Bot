# Running the lab day to day

How to start, use and stop the lab. For how it was built, see [lab-build-log.md](lab-build-log.md); for problems, see [troubleshooting.md](troubleshooting.md).

## Quick reference

| Machine | Address | What runs there | How to reach it |
|---|---|---|---|
| Windows host | 192.168.56.1 | VirtualBox, PowerShell, browser | local |
| `soc-attacker` | 192.168.56.30 | MITRE Caldera on port 8888 | `ssh <your-user>@192.168.56.30`, web UI at `http://192.168.56.30:8888` |
| `soc-victim` | 192.168.56.20 | Sandcat agent, auditd | `ssh <your-user>@192.168.56.20` |
| `soc-siem` | 192.168.56.10 | Splunk, Logstash, the bot | `ssh <your-user>@192.168.56.10` |

`<your-user>` is the user you created during each VM's install.

## Starting the lab

1. **Plug the laptop in.** The Windows hypervisor can stay on `Auto` (needed for WSL) as long as `soc-siem` has 4 CPUs. If freezes with *soft lockup* messages return, see the hypervisor fallback in [troubleshooting.md](troubleshooting.md).
2. **Start the VMs** in VirtualBox, the SIEM first, then the victim, then the attacker. A normal start is fine. **Splunk needs 10 to 15 minutes to become healthy after a cold boot**, so check `docker ps` on `soc-siem` for `(healthy)` before opening the web page; a VM resumed from a saved state is ready much sooner. to run without a window, right-click the VM and choose a headless start. Give each VM a minute or two to finish booting. If a guest freezes with kernel stack traces, power it off, set it to 1 CPU and try again.
3. **Open one PowerShell window per VM** and connect:
   ```powershell
   ssh <your-user>@192.168.56.30
   ```
   The first time, SSH asks you to confirm the host's fingerprint; type `yes`. If you later rebuild a VM and SSH warns that the host key changed, remove the old entry with `ssh-keygen -R 192.168.56.30` and connect again.
4. **Start Caldera on the attacker.** It runs inside tmux so it keeps running if the SSH window closes:
   ```bash
   cd ~/caldera
   source venv/bin/activate
   tmux new -s caldera          # or: tmux attach -t caldera, if the session already exists
   python3 server.py            # no --build after the first run
   ```
   Detach from tmux with `Ctrl+b` then `d`; the server keeps running. Check what is running with `tmux ls`. If Caldera reports `[Errno 98] address already in use`, a server is already running: attach to it instead of starting another.
5. **Open the Caldera web UI** at `http://192.168.56.30:8888` and sign in as `red`. The password was printed when Caldera first started; see "Credentials" below.
6. **Start the Sandcat agent on the victim.** In Caldera go to *Agents → Deploy an agent → Sandcat → linux*, check that `app.contact.http` is `http://192.168.56.30:8888` (not `0.0.0.0`), copy the command and run it in the victim's terminal. Unless you set the agent up as a service, it does not start by itself after a reboot, so repeat this step each time. The agent shows up in the *Agents* page within about 30 seconds.
7. **Check that auditd is recording** on the victim:
   ```bash
   sudo auditctl -l
   sudo ausearch -k exec_cmd -i --start recent | grep proctitle | tail
   ```

Then run an operation. The first one is described in [../attack-scenarios/01-discovery.md](../attack-scenarios/01-discovery.md).

## Stopping the lab

1. Stop the Sandcat agent on the victim (`Ctrl+C` in the terminal where it runs).
2. Stop Caldera: `tmux attach -t caldera`, press `Ctrl+C`, then `exit` to close the tmux session.
3. Shut `soc-attacker` and `soc-victim` down from inside with `sudo poweroff` and wait for the window to close. For `soc-siem`, prefer **Close, Save the machine state** in VirtualBox: it resumes in seconds with Splunk already running, instead of the 10 to 15 minute cold start. Make sure the host disk has about 20 GB free.
4. Unplugging or sleeping the laptop with VMs running can corrupt a guest; shut down first.

## Snapshots

A snapshot is a saved state of a VM that you can return to. Take one before anything risky: a fresh install, a large package install, or a containment test that cuts the host off from the network.

- **Take one:** in VirtualBox select the VM, open its **Snapshots** tab (called *Instantanés* in the French interface), click *Take*, and give it a clear name.
- **Restore one:** select the snapshot and choose *Restore*. Anything done after that snapshot is lost, so shut the VM down first and take a new snapshot if you want to keep the current state.
- **Current chain:** attacker `clean base` → `caldera installed`; victim `clean base` → `network ready` → `agent working` → `pipeline tuned`; SIEM `splunk running` (if taken) → `pipeline tuned`.

## Credentials and secrets

- Caldera creates the `red` and `blue` passwords at first start, prints them once, and then stores them hashed. Save the password from that first start in a password manager. If it is lost, see the Caldera entries in [troubleshooting.md](troubleshooting.md).
- Change the default operating-system passwords with `passwd` on each VM, and use a different password for each.
- Never commit tokens, API keys, SSH keys, `.env` files or passwords. The repository is private, but treat everything in it as if it were public. The bot reads its secrets from a local `.env` file, which is in `.gitignore`.

## Resource tips

- The three VMs need 4 + 4 + 8 = 16 GB of RAM. Close other heavy programs while the lab runs.
- If the attacker or victim becomes slow or freezes, lower it to 1 or 2 CPUs and check the laptop is plugged in. `soc-siem` is the opposite: it needs **4 CPUs** (2 caused freezes).
- You do not need every VM for every task: for attack tests only the attacker and victim are needed; the SIEM is needed once logs flow into Splunk.
- After `soc-siem` boots, Splunk starts by itself (`restart: unless-stopped`). Check with `docker ps` in `~/siem`: it should say `healthy` after 10 to 15 minutes from a cold boot; Logstash starts after Splunk is healthy. The web UI is at `http://192.168.56.10:8000`. Use *Save the machine state* or `sudo poweroff` so the Splunk data is written cleanly. On the victim, auditd and Filebeat start by themselves; check Filebeat with `sudo systemctl status filebeat`. A quick end-to-end test: run `whoami` on the victim, then search `index=linux sourcetype=linux:audit earliest=-5m type=EXECVE | table _time a0 a1` in Splunk.

## After resuming a saved VM

- **Fix the clock first.** A VM resumed from a saved state keeps the old time until it re-syncs, and Splunk then stamps and searches events wrongly. On `soc-siem` run `sudo timedatectl set-ntp true`, `sudo systemctl restart systemd-timesyncd`, then `timedatectl` and check *System clock synchronized: yes*. Compare `date` with the victim.
- **Do not start Caldera twice.** If `tmux ls` shows a `caldera` session, attach to it (`tmux attach -t caldera`) instead of running `python3 server.py` again.
- **Login name.** All three VMs use the account `mus` for SSH. Passwords are never written in the repository.
- **A VM that shows *Méditation profonde* (Guru Meditation) has crashed.** Power it off, start it again and wait for Splunk to be `healthy`. See [troubleshooting.md](troubleshooting.md).

## Ports used in the lab

| Port | Used by | Machine |
|---|---|---|
| 22 | SSH | all VMs |
| 5044 | Logstash (Filebeat sends logs here) | `soc-siem` |
| 8000 | Splunk Web | `soc-siem` |
| 8088 | Splunk HEC (Logstash sends logs here) | `soc-siem` |
| 8089 | Splunk REST API (hunts, AI lookups) | `soc-siem` |
| 8765 | Bot webhook (Splunk alerts arrive here) | where the bot runs |
| 8080 | Web console | where the console runs |
| 8888 | Caldera web interface | `soc-attacker` |
| 7010, 7011, 7012 | Caldera agent contact ports | `soc-attacker` |
