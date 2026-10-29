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
| Splunk web UI shows *Disconnected from Splunk server*; health panel shows IOWait red; `dmesg` shows `watchdog: BUG: soft lockup - CPU stuck for 114s` | The guest CPUs were frozen by the host. The Windows hypervisor was set to `auto` (it worked for the lighter VMs) and the heavy disk use of Splunk's first start exposed it | In VirtualBox: Storage, tick *Use host I/O cache* on the SATA controller and *Solid-state Drive* on the disk; System, Acceleration, set *Paravirtualization Interface* to KVM. Check with `sudo dmesg \| grep -ci lockup`. If freezes continue, use `bcdedit /set hypervisorlaunchtype off` and restart Windows |
| `docker compose pull` looks stuck for minutes | The Splunk image (about 1.9 GB) is extracted after the download | Check progress with `du -sh /var/lib/containerd` and `uptime`; if the size grows, wait |
| `--accept-license: command not found` (or the `--accept-sgt...` string) | The option strings were typed in the shell | They belong in the compose file as environment values (`SPLUNK_START_ARGS`, `SPLUNK_GENERAL_TERMS`); nothing to run |
| Splunk login fails or the admin password is not remembered | The password was set through `SPLUNK_PASSWORD` in `~/siem/.env` | Show it with `grep SPLUNK_PASSWORD ~/siem/.env` (do not paste it anywhere). If it is lost, set a new value in `.env`, then `docker compose down -v && docker compose up -d` (this wipes Splunk's data, so only do it before data is loaded) |
| Freezes and load average 47 to 121 came back after the first fix; Windows hypervisor still on `auto` (needed for WSL) | `soc-siem` had only 2 CPUs; Splunk's first start is very heavy | Give `soc-siem` **4 CPUs**. Load stays about 1 and lockups stop, with the hypervisor on `auto`. Fallback: `bcdedit /set hypervisorlaunchtype off` and restart, or a second Windows boot entry with the hypervisor off |
| After every boot Splunk takes 10 to 15 minutes; `docker ps` shows *starting* or *unhealthy* | The Splunk container repeats its Ansible setup on each start | Wait for `healthy` before opening the web page. Prefer *Save the machine state* in VirtualBox over `poweroff` so the VM resumes with Splunk already running |
| Splunk search returns 0 events although data was sent | Time range on *Previous month*, or a typo such as `iindex=` | Use *Last 24 hours* (or *All time*) and check the spelling |
| Logstash logs errors about `elasticsearch:9200` or `licensereader` | Logstash tries to send its own monitoring to an Elasticsearch that does not exist | Add `XPACK_MONITORING_ENABLED: "false"` to the Logstash service |
| Events labelled `linux:auth,linux:auth` and audit events missing | Logstash loads **every** file in its pipeline folder; a `soc.conf.bak` left there ran as a second pipeline | Keep backups outside `~/siem/logstash/pipeline/`, restart Logstash, delete and re-create the Splunk index, reset Filebeat's registry |
| 135,000+ audit events in a few hours | The first auditd rule recorded every program started by every background service, plus four repeating record types per command | Rule limited to login sessions (`-F auid>=1000 -F auid!=4294967295`); Logstash drops `PATH`, `CWD`, `BPRM_FCAPS`, `PROCTITLE`. Trade-off: commands from services without a login session are not recorded |
| Events seem *late*: the lag search shows hundreds of seconds | Filebeat replayed an old backlog after a reset, so old events were delivered late. Timestamps are still correct | Test with fresh events (type a command, search `earliest=-5m`). Check `timedatectl` on both VMs: *System clock synchronized: yes* |
| `ssh` to the victim says *Invalid user* | The VM name was used as the user name | Use the account created during the Ubuntu install (`whoami` on the VM console shows it) |
| `ls /etc/audit/rules.d/` gives *Permission denied* | The folder is readable by root only | `sudo ls /etc/audit/rules.d/`, and `sudo sh -c 'cat /etc/audit/rules.d/*.rules'` for the contents |
| Pasted long text in SSH arrives garbled (`[200~` at the start, a stray `~` at the end) | Bracketed paste of multi-line text | Check the result (`wc -l`, `cat`), type short commands by hand, or create files in smaller pieces |
| `apt` says *waiting for cache lock* | Ubuntu's automatic updates are running | Wait a few minutes and retry |
| Splunk HEC test fails over plain HTTP | HEC uses HTTPS with a self-signed certificate | Use `https://` and `curl -k` (lab only); Logstash uses `ssl_verification_mode => none` for the same reason |
