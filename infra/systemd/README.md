# Running the bot and console under systemd, with secrets as credentials

The unit files here are samples with placeholders (user `soc`, `/opt/soc-bot`, `/var/lib/soc`, `192.168.56.10`). Change them to match the VM.

Each secret lives in its own file that only root can read. systemd hands the service a private copy through `LoadCredential=`, in the directory named by `$CREDENTIALS_DIRECTORY`. The programs read a secret from the environment first (this is how `op run` works on Windows) and, if it is not set, from the file in that directory. The secret is never put into the service's environment or into the unit file, so it does not appear in `systemctl show` or a process listing. Non-secret settings (ports, paths, role and channel IDs) stay in a normal `EnvironmentFile`.

The file name is the setting name in lower case: `DISCORD_TOKEN` is read from `discord_token`. Secrets that can be supplied this way: `DISCORD_TOKEN`, `WEBHOOK_SECRET`, `SPLUNK_TOKEN`, `SPLUNK_HEC_TOKEN`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `SOC_WEB_SECRET_KEY`.

## Set up

```bash
# a service account that owns the data, with no login
sudo useradd --system --home /var/lib/soc --shell /usr/sbin/nologin soc
sudo install -d -o soc -g soc -m 750 /var/lib/soc

# the credentials directory: root only
sudo install -d -o root -g root -m 700 /etc/soc/credentials

# one file per secret. Type the value instead of putting it in the command line, so it stays out of shell history
sudo bash -c 'umask 077; read -r -s -p "Discord token: " v; printf "%s" "$v" > /etc/soc/credentials/discord_token'
sudo bash -c 'umask 077; python3 -c "import secrets; print(secrets.token_hex(32), end=\"\")" > /etc/soc/credentials/soc_web_secret_key'
sudo chown root:root /etc/soc/credentials/*
sudo chmod 600 /etc/soc/credentials/*

# non-secret settings (no tokens in here)
sudo install -o root -g soc -m 640 /dev/null /etc/soc/soc.env
sudoedit /etc/soc/soc.env

# install the units, then start them
sudo cp infra/systemd/soc-bot.service infra/systemd/soc-console.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-bot soc-console
```

Remove the `LoadCredential=` lines for secrets you do not use: a listed file that does not exist stops the service from starting.

## Check it

```bash
sudo ls -l /etc/soc/credentials            # -rw------- root root
systemctl show soc-bot | grep -i token     # prints nothing: no secret in the unit's environment
sudo cat /proc/$(systemctl show -p MainPID --value soc-bot)/environ | tr '\0' '\n' | grep -i token   # nothing
journalctl -u soc-bot -n 20                # the configuration error, if a secret is missing
```

## Console accounts on the VM

Accounts are managed on the machine, as the service user, against the same database the console uses:

```bash
sudo -u soc bash -c 'set -a; . /etc/soc/soc.env; exec /opt/soc-bot/.venv/bin/python -m soc_web user add alice --tier triage'
```

Rotate a secret by replacing its file and restarting the service (`sudo systemctl restart soc-bot`).
