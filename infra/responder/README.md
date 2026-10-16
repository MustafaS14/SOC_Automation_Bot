# Responder setup (victim host)

The bot isolates a host by SSH-ing in as `responder` and running one of two scripts. Three layers keep a stolen bot key from becoming a shell on the victim.

| Layer | File | Effect |
|---|---|---|
| Forced command | `soc-gate` + the `authorized_keys` options below | The key can only run the two exact isolate/unisolate commands; no shell, no PTY, no forwarding |
| sudoers | `responder.sudoers` | `responder` may run only `soc-isolate` and `soc-unisolate` as root |
| Scripts | `soc-isolate`, `soc-unisolate` | Fixed behaviour; the SIEM address stays reachable so the host can be released |

## Install

On the victim, as root:

```bash
useradd --create-home --shell /bin/bash responder
passwd --lock responder                      # key-only login

install -o root -g root -m 0755 soc-isolate soc-unisolate soc-gate /usr/local/sbin/
install -o root -g root -m 0440 responder.sudoers /etc/sudoers.d/responder
visudo -cf /etc/sudoers.d/responder
```

Edit `MGMT_IP` in `soc-isolate` if the SIEM address is not `192.168.56.10`.

## Restrict the key

Generate a dedicated key on the bot host (never reuse a personal key):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/soc_bot_responder -C soc-bot
```

Add its public key to `/home/responder/.ssh/authorized_keys` as a single line with these options in front:

```
restrict,from="192.168.56.1",command="/usr/local/sbin/soc-gate" ssh-ed25519 AAAA... soc-bot
```

- `restrict` turns off PTY allocation, port, agent and X11 forwarding and `~/.ssh/rc`. It needs OpenSSH 7.2 or newer. On older versions use `no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc` instead.
- `from="..."` limits the key to the bot host's address. Replace `192.168.56.1` with the address the victim sees for the bot.
- `command="..."` runs `soc-gate` whatever the client asks for. The gate compares `SSH_ORIGINAL_COMMAND` with the two allowed strings, which are the same ones hard-coded in `soc_bot/clients/ssh_response.py`.

Permissions:

```bash
chown -R responder:responder /home/responder/.ssh
chmod 700 /home/responder/.ssh && chmod 600 /home/responder/.ssh/authorized_keys
```

## Verify

From the bot host:

```bash
ssh -i ~/.ssh/soc_bot_responder responder@<victim> "sudo -n /usr/local/sbin/soc-unisolate"   # runs
ssh -i ~/.ssh/soc_bot_responder responder@<victim> "id"                                        # prints "denied", exit 126
ssh -i ~/.ssh/soc_bot_responder responder@<victim>                                             # no shell: "denied"
```

Connect once interactively so the victim's host key lands in `known_hosts`. The bot always verifies host keys.

## Notes

- `soc-unisolate` assumes `ufw` is normally disabled on the victim, as on a default Ubuntu install. If you keep it enabled, change the script to restore your normal rules.
- `soc-isolate` runs `ufw --force reset`, which also removes any rules you added by hand.
