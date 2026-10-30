# Keeping secrets out of `.env`

This is for the development side: the bot and the console read their tokens and keys from `.env`. With a password manager, `.env` holds only **references**, and the real values are filled in while the program starts. They are never written to disk. This page uses 1Password.

## In plain words

Instead of pasting a token into `.env`, you store it in a 1Password vault and write a pointer to it in `.env`. When you start the bot, the 1Password command-line tool looks up the real value and hands it to the program. If someone copies `.env`, they get pointers, not secrets.

## Set up

1. Install the [1Password CLI](https://developer.1password.com/docs/cli/) (`op`; on Windows `winget install AgileBits.1Password.CLI`) and sign in (the desktop app can unlock it with biometrics).
2. Make a vault (for example `SOC-Lab`) and one item per secret, with the secret in a field.
3. In `.env`, replace each value with a reference in the form `op://<vault>/<item>/<field>`:

```
DISCORD_TOKEN=op://SOC-Lab/discord/token
SPLUNK_TOKEN=op://SOC-Lab/splunk/token
SPLUNK_HEC_TOKEN=op://SOC-Lab/splunk-hec/token
ABUSEIPDB_API_KEY=op://SOC-Lab/abuseipdb/key
VIRUSTOTAL_API_KEY=op://SOC-Lab/virustotal/key
WEBHOOK_SECRET=op://SOC-Lab/webhook/secret
SOC_WEB_SECRET_KEY=op://SOC-Lab/soc-console/secret-key
```

Settings that are not secret (ports, URLs, role IDs) stay as plain values.

4. Start everything through `op run`:

```powershell
op run --env-file=.env -- python -m soc_bot
op run --env-file=.env -- python -m soc_web
op run --env-file=.env -- python -m soc_web user add alice --tier triage
```

`op run` replaces each reference with the real value in the process's environment before Python starts, and hides those values if the program prints them. The programs' own `.env` loading never overrides variables that are already set, so the real values win.

## If you forget `op run`

Both programs refuse to start and name the variables that still hold a reference (`... still hold 1Password references (op://...) instead of values`), instead of using the reference text as a token.

## Notes

- `.env` stays out of git (it is in `.gitignore`). The references are not secrets, but the file also holds your own IDs and addresses, so keep ignoring it.
- The VS Code 1Password extension can spot secrets typed into files and offer to move them into a vault.
- `SOC_BOT_MOCK=true` needs no secrets at all, so demos do not need 1Password.
- This does not change how the console's own user passwords are stored: those are scrypt hashes in `web_users.db`, and nobody, including an admin, can read them back.

## On the Linux VM: systemd credentials

`op run` is for the Windows development machine. On the VM, each secret is a root-only file under `/etc/soc/credentials/`, and the service unit lists it with `LoadCredential=`. systemd gives the service a private copy in `$CREDENTIALS_DIRECTORY`. The programs read a secret from the environment first (so `op run` and a plain environment variable still work) and fall back to that file, named after the setting in lower case (`discord_token` for `DISCORD_TOKEN`). The secret is never put in the process environment or the unit file, so `systemctl show` and a process listing do not reveal it. Sample units and the `chown` / `chmod` commands: [infra/systemd/](../infra/systemd/README.md).
