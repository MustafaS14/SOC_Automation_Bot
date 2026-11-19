# Scenario 03: one Caldera operation for every detection

A single adversary, **SOC full coverage**, that runs one attack for each row of the console's Coverage page, so every alert can be tested from Caldera and not by hand. The profiles are files in this repository ([`caldera/`](caldera/)), so they can be reinstalled after a rebuild with one command.

## What it runs

| Order | Ability | Technique | Alert it should raise |
|---|---|---|---|
| 1 | SOC demo recon | T1082 and friends | Discovery burst |
| 2 | SOC history off | T1070.003 | Shell history cleared or switched off |
| 3 | SOC cron persistence | T1053.003 | Cron job added or changed |
| 4 | SOC new local user | T1136.001 | New local user account created |
| 5 | SOC sudo root shell | T1548.003 | Risky sudo use |
| 6 | SOC SSH brute force | T1110 | SSH brute force |

Starting the agent itself raises **Masquerading** (a process named `splunkd`) and, through the agent's own history command, **Shell history cleared**. Every command is harmless and cleans up after itself: the cron entry and the test account are removed again, and the history ability only switches history off for its own shell.

## Install (once, and after every Caldera rebuild)

On `soc-attacker`, in a copy of this repository (a `git clone`, or copy the `caldera` folder across with `scp`):

```
bash attack-scenarios/caldera/install.sh
```

Then restart Caldera so it reads the new files: `tmux attach -t caldera`, Ctrl+C, `python3 server.py`, then Ctrl+b and d. The profile **SOC full coverage** appears under *Adversaries*.

## Run

1. On `soc-victim`, start the agent **as root**, because creating an account and using sudo need it: `sudo ./splunkd -server http://192.168.56.30:8888 -group red -v`. The login session keeps the audit user id, so the auditd rules still record it. If `sudo` asks for a password and you would rather not use root, the account and sudo abilities will fail, and the other four still work.
2. In Caldera: *Operations*, new operation, adversary **SOC full coverage**, group `red`, start.
3. The six abilities run within about two minutes. Allow another 5 to 10 minutes for the cards.

## Notes

- **Brute force source:** the failed logins come from the victim to itself, so the card shows `127.0.0.1` as the source address. That tests the rule. A realistic source address needs a second agent on `soc-attacker`.
- **Throttle:** each alert is quiet for the throttle period per host after it fires. Wait for it to pass (5 minutes with `install_alerts.sh 5m`) before running the whole operation again.
- **Tested status:** a technique moves from *Built* to *Tested* on the Coverage page after you have seen its card appear from a real run.
