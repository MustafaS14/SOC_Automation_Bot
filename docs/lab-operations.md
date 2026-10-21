# Running the lab day to day

How to start, use and stop the lab. For how it was built, see [lab-build-log.md](lab-build-log.md); for problems, see [troubleshooting.md](troubleshooting.md).

## Quick reference

| Machine | Address | What runs there | How to reach it |
|---|---|---|---|
| Windows host | 192.168.56.1 | VirtualBox, PowerShell, browser | local |
| `soc-attacker` | 192.168.56.30 | MITRE Caldera on port 8888 | `ssh <your-user>@192.168.56.30`, web UI at `http://192.168.56.30:8888` |
| `soc-victim` | 192.168.56.20 | Sandcat agent, auditd | `ssh <your-user>@192.168.56.20` |
| `soc-siem` (planned) | 192.168.56.10 | Splunk, Logstash, the bot | `ssh <your-user>@192.168.56.10` |

`<your-user>` is the user you created during each VM's install.

## Starting the lab

1. **Plug the laptop in** and check the Windows hypervisor is still off. In an administrator PowerShell:
   ```powershell
   bcdedit /enum {current} | findstr hypervisorlaunchtype
   ```
   It should say `Off`. If it says `Auto`, follow section 1 of the build log and restart.
2. **Start the VMs** in VirtualBox, the SIEM first (once it exists), then the victim, then the attacker. A normal start is fine; to run without a window, right-click the VM and choose a headless start. Give each VM a minute or two to finish booting. If a guest freezes with kernel stack traces, power it off, set it to 1 CPU and try again.
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
3. Shut each VM down from inside with `sudo poweroff` and wait for the window to close. Closing the VirtualBox window or saving the machine state is not the same as a clean shutdown.
4. Unplugging or sleeping the laptop with VMs running can corrupt a guest; shut down first.

## Snapshots

A snapshot is a saved state of a VM that you can return to. Take one before anything risky: a fresh install, a large package install, or a containment test that cuts the host off from the network.

- **Take one:** in VirtualBox select the VM, open its **Snapshots** tab (called *Instantanés* in the French interface), click *Take*, and give it a clear name.
- **Restore one:** select the snapshot and choose *Restore*. Anything done after that snapshot is lost, so shut the VM down first and take a new snapshot if you want to keep the current state.
- **Current chain:** attacker `clean base` → `caldera installed`; victim `clean base` → `network ready` → `agent working`.

## Credentials and secrets

- Caldera creates the `red` and `blue` passwords at first start, prints them once, and then stores them hashed. Save the password from that first start in a password manager. If it is lost, see the Caldera entries in [troubleshooting.md](troubleshooting.md).
- Change the default operating-system passwords with `passwd` on each VM, and use a different password for each.
- Never commit tokens, API keys, SSH keys, `.env` files or passwords. The repository is private, but treat everything in it as if it were public. The bot reads its secrets from a local `.env` file, which is in `.gitignore`.

## Resource tips

- The three VMs need 4 + 4 + 8 = 16 GB of RAM. Close other heavy programs while the lab runs.
- If a VM becomes slow or freezes, lower it to 1 or 2 CPUs and check the laptop is plugged in.
- You do not need every VM for every task: for attack tests only the attacker and victim are needed; the SIEM is needed once logs flow into Splunk.
