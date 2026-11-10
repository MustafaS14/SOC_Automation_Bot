# Live lab: the web console on your PC, reading real incidents

This page covers running the web console on your own PC against the incidents the bot holds on the SIEM VM, with the assistant answering through your own `claude` login. Nothing here is exposed beyond your machine and the host-only lab network.

```
PC (console on 127.0.0.1:8000)  --SSH tunnel-->  soc-siem 172.18.0.1:8765  (bot, read-only /api)
        |
        +-- claude CLI (your own login, tools disabled)
        +-- SSH tunnel to Splunk 8089 (read-only token), only for the Hunt page
```

Why a tunnel: the bot's webhook and API listen on the Docker bridge address (`WEBHOOK_HOST=172.18.0.1`), which is how Splunk's container reaches it. That address is not reachable from the PC, so the PC forwards a local port to it over SSH.

## 1. On soc-siem: enable the incident API

The API is read-only (`GET /api/incidents`, `/api/incidents/{id}`, `/api/counts`) and shares the webhook's listener.

1. Add a long random value to the bot's `.env` as `API_SECRET` (at least 32 characters, and different from `WEBHOOK_SECRET`). Generate it without printing it:
   ```
   echo "API_SECRET=$(openssl rand -hex 32)" >> .env
   grep -c '^API_SECRET=' .env      # must print 1
   ```
2. Restart the bot from the project folder with the venv active:
   ```
   cd ~/SOC_Automation_Bot
   source .venv/bin/activate
   python -m soc_bot
   ```
3. Check it from a second window. Without the secret you expect `401`; with it you expect JSON counts.
   ```
   ss -ltnp | grep 8765
   curl -s -o /dev/null -w '%{http_code}\n' http://172.18.0.1:8765/api/counts
   curl -s -H "X-Api-Secret: $(grep ^API_SECRET .env | cut -d= -f2)" http://172.18.0.1:8765/api/counts
   ```
   If `ss` shows nothing, the bot is not running: look at the bot window for a configuration error.

If the bot restarts, alerts only reach Discord once it is listening again. Run a Caldera operation afterwards and confirm a card arrives.

## 2. On the PC: open the tunnel

Run this in its own terminal on the PC (not on the VM) and leave it open. After the password it prints nothing.

```
ssh -N -L 18765:172.18.0.1:8765 soc-siem@192.168.56.10
```

Check it from a second terminal. In PowerShell use `curl.exe`, because `curl` is an alias for another command there:

```
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:18765/api/counts
```

`401` means the tunnel works.

## 3. On the PC: start the console

Settings the console needs:

| Setting | Value |
| --- | --- |
| `SOC_BOT_MOCK` | `false` |
| `SOC_BOT_API_URL` | `http://127.0.0.1:18765` |
| `SOC_BOT_API_SECRET` | the bot's `API_SECRET`, supplied at start-up |
| `AI_BACKEND` | `claude_code` |
| `SOC_WEB_HOST` | `127.0.0.1` (the relay guard refuses `claude_code` on any other address) |
| `SOC_WEB_PORT` | a free port, for example `8000` |
| `SOC_WEB_SECRET_KEY` | a fresh random value of at least 32 characters |
| `SOC_WEB_SECURE_COOKIES` | `false` when serving plain HTTP on localhost |

Do not put the API secret in a file. Either keep an `op://` reference in `.env` and start with `op run --env-file=.env -- python -m soc_web` ([secrets](secrets.md)), or type it at a hidden prompt, which keeps it in that process only. [scripts/run-live.example.ps1](../scripts/run-live.example.ps1) is a PowerShell launcher that does the second: copy it, set the two paths at the top, and run it from your own terminal. Run it with `adduser` once to create your account, then without arguments to start the console.

Accounts are created at the command line and the password is typed at a prompt:

```
python -m soc_web user add <name> --tier admin
```

Open `http://127.0.0.1:8000/login`. The status strip should say live, and the incident list should match what the bot counted. If it says offline, the tunnel is closed or the secret is wrong. When you are done, close the console window, because the secret stays in that window's environment until it closes.

## 4. The assistant relay

`AI_BACKEND=claude_code` runs the `claude` command-line program with tools disabled and a minimal environment, using your own login. It is for one person on their own PC. The bot refuses this backend and the console accepts it only on a loopback address, so it cannot be enabled on the SIEM VM by mistake. Page text sent to the assistant goes to Anthropic. Set `AI_COMMAND` to the full path of `claude` if it is not on your `PATH`.

## 5. Optional: connect Splunk so the Hunt page works

Hunt runs predefined, read-only searches in Splunk. The console talks to Splunk's management port (8089) with a token that can only search one index. Without this section the status strip says Splunk "not configured" and everything else still works.

On soc-siem, check that Splunk publishes the management port (`docker ps` shows `0.0.0.0:8089->8089`). Then, in Splunk Web as an administrator:

1. **Role.** Settings, Access controls, Roles, new role `soc_readonly`. Inherit from `user`, give it only the `search` capability, and allow only the `linux` index.
2. **User.** Settings, Users, new user `soc_console` with only that role and a strong password kept in your password manager. Nobody logs in with it; it exists to own the token.
3. **Token.** Settings, Tokens. Turn token authentication on if Splunk asks, then create a token for `soc_console` with a short expiry (30 days is a good start). Splunk shows it once, so copy it straight into the next step. A token is a long string, about 500 characters.

Open the second tunnel in its own terminal on the PC and leave it open:

```
ssh -N -L 18089:127.0.0.1:8089 soc-siem@192.168.56.10
```

Settings the console needs, in addition to the table in section 3:

| Setting | Value |
| --- | --- |
| `SPLUNK_URL` | `https://127.0.0.1:18089` |
| `SPLUNK_TOKEN` | the read-only token |
| `SPLUNK_VERIFY_TLS` | `false`, because the lab's Splunk uses a self-signed certificate |

[scripts/run-live.example.ps1](../scripts/run-live.example.ps1) asks for the token at a hidden prompt when `SPLUNK_URL` is set. If you set it by hand instead, type `$env:SPLUNK_TOKEN = '`, paste the token, and close with exactly one `'`. Do not copy a `PS C:\...>` prompt along with it. Then check the length without printing the token:

```
$env:SPLUNK_TOKEN.Length
```

A real token is about 500 characters. A length of a few characters means the paste failed.

Prove the account is read-only: one request that must work and one that must be refused. The token stays in the environment variable, so it never appears on the command line.

```
curl.exe -k -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $env:SPLUNK_TOKEN" https://127.0.0.1:18089/services/server/info
curl.exe -k -s -o NUL -w "%{http_code}`n" -X POST -H "Authorization: Bearer $env:SPLUNK_TOKEN" https://127.0.0.1:18089/services/authentication/users
```

The first must print `200` and the second `403`. Then start the console: the strip should say Splunk **reachable**, and Hunt, for example "Events mentioning an IP" with the attacker's address, returns rows. Tokens expire; when Hunt stops working after a month, create a new one.

### If the Splunk container restarts in a loop

The Splunk Docker image's start-up script logs in as `admin` with the `SPLUNK_PASSWORD` stored in the container's settings every time it starts. If the real admin password is different, because it was changed in the web UI or reset, the script gets `401 Unauthorized` partway through and exits. Docker restarts the container, so `docker ps` shows an uptime that keeps resetting and `docker inspect splunk --format '{{.RestartCount}}'` keeps rising, with exit code 0 and no out-of-memory kill. To see it: `docker logs splunk 2>&1 | grep -E "fatal:|401|Unauthorized"`.

The fix is to make `admin` use the container's own password. The password never needs to be printed: read it straight from the container into a seed file. Splunk reads `user-seed.conf` only when there is no `passwd` file, and it removes the seed file itself afterwards, so do not delete it early.

```
E=/var/lib/docker/volumes/siem_splunk-etc/_data
docker stop splunk
sudo cp -a $E/passwd $E/passwd.bak
sudo mv $E/passwd $E/passwd.removed
PW=$(docker inspect splunk --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^SPLUNK_PASSWORD=//p')
printf '[user_info]\nUSERNAME = admin\nPASSWORD = %s\n' "$PW" | sudo tee $E/system/local/user-seed.conf >/dev/null
sudo chmod 600 $E/system/local/user-seed.conf
unset PW
docker start splunk
```

Wait until `docker ps` says `healthy` and a new `passwd` exists. That file now holds only `admin`, so restore the read-only user from the backup, with Splunk stopped, and start it again:

```
docker stop splunk
sudo grep '^:soc_console:' $E/passwd.bak | sudo tee -a $E/passwd >/dev/null
sudo chown 41812:41812 $E/passwd
sudo chmod 600 $E/passwd
docker start splunk
```

Check `sudo cut -d: -f2 $E/passwd` lists `admin` and `soc_console` (it prints names only), and that the token still returns `200`. If it does not, create a new token. Keep `passwd.bak`. To change the admin password for good, change `SPLUNK_PASSWORD` in the compose settings and recreate the container so that the two always match.

## Lessons from running it

- **Throttle while testing.** The repo default suppresses repeat alerts per host for 30 minutes. While testing, install the alerts with `infra/siem/splunk/install_alerts.sh 5m`, and pass the period every time, because the script writes it into the live file.
- **Events stop arriving in Splunk.** Filebeat logs `connection reset by peer` every few minutes when a connection sits idle; that is harmless. If events genuinely stall, restart Logstash first. Then compare the clocks on all three VMs, because a skewed victim clock puts events outside the alert's 15-minute window.
- **Caldera.** An agent only beacons until an operation runs; start an operation to produce commands. auditd records commands typed in login sessions.
- **No retry on alerts.** The Splunk alert action does not retry. If the bot is down when an alert fires, the card is lost, so restart the bot before running a demo.
- **Python on the VM.** The system Python is externally managed. Always `source .venv/bin/activate` before `pip` or `python -m soc_bot`.
- **PowerShell.** Use `curl.exe`, not `curl`. Put a repository path that contains `&` in quotes. Paste a secret only at its hidden prompt, never into the command line: the line ends up in the shell history and anywhere it is shared.
- **One console at a time.** The mock console and the live console look alike. Check the status strip and the port before concluding anything about the data.
- **Events with the wrong date.** A VM clock that was off, or resumed from a pause, stamps events with a wrong day. The Hunt page then misses them. Find them with `index=linux sourcetype=linux:audit "<ip>" earliest=-48h latest=+2d | eval indexed=strftime(_indextime,"%F %T") | table _time indexed host _raw` and compare `_time` with `indexed`. Compare `date -u` on all VMs before a demo.
- **Hunt shows nothing for an IP.** The template only returns events that mention that IP, so cron and sysstat noise never matches. If nothing is there from today, check that the agent is running on the victim (`ps -eo pid,lstart,cmd | grep splunkd`) before blaming Splunk.
- **Caldera.** The server may already be running inside a tmux session (`tmux attach -t caldera`); check `pgrep -af server.py` before starting a second one, which fails with "address already in use". When you deploy an agent by hand, the server address has no trailing slash: with one, the download URL has a double slash and Caldera answers `405`, which the shell then tries to run as a script.
- **Pasting into PowerShell.** Copy only the command, never the `PS C:\...>` prompt. PowerShell reads `PS` as a command (`Get-Process`). A pasted secret that ends in a doubled quote leaves the shell waiting at a `>>` prompt.
