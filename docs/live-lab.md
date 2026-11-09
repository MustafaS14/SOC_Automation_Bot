# Live lab: the web console on your PC, reading real incidents

This page covers running the web console on your own PC against the incidents the bot holds on the SIEM VM, with the assistant answering through your own `claude` login. Nothing here is exposed beyond your machine and the host-only lab network.

```
PC (console on 127.0.0.1:8000)  --SSH tunnel-->  soc-siem 172.18.0.1:8765  (bot, read-only /api)
        |
        +-- claude CLI (your own login, tools disabled)
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

## Lessons from running it

- **Throttle while testing.** The repo default suppresses repeat alerts per host for 30 minutes. While testing, install the alerts with `infra/siem/splunk/install_alerts.sh 5m`, and pass the period every time, because the script writes it into the live file.
- **Events stop arriving in Splunk.** Filebeat logs `connection reset by peer` every few minutes when a connection sits idle; that is harmless. If events genuinely stall, restart Logstash first. Then compare the clocks on all three VMs, because a skewed victim clock puts events outside the alert's 15-minute window.
- **Caldera.** An agent only beacons until an operation runs; start an operation to produce commands. auditd records commands typed in login sessions.
- **No retry on alerts.** The Splunk alert action does not retry. If the bot is down when an alert fires, the card is lost, so restart the bot before running a demo.
- **Python on the VM.** The system Python is externally managed. Always `source .venv/bin/activate` before `pip` or `python -m soc_bot`.
- **PowerShell.** Use `curl.exe`, not `curl`. Put a repository path that contains `&` in quotes. Paste a secret only at its hidden prompt, never into the command line: the line ends up in the shell history and anywhere it is shared.
- **One console at a time.** The mock console and the live console look alike. Check the status strip and the port before concluding anything about the data.
