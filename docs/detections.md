# Detections

The tripwires that turn recorded commands into alerts. Each one is written in SPL, Splunk's search language, and labelled with the MITRE ATT&CK technique it matches. Background: [lab-build-log.md](lab-build-log.md), sections 14 to 16. Scenario: [../attack-scenarios/01-discovery.md](../attack-scenarios/01-discovery.md).

## In simple words

An attacker who has just got into a machine usually looks around first: who am I, what is running, who else has an account. Each command is harmless alone, so the first tripwire watches for *several different kinds of looking around in a short time*. A second tripwire catches the attack tool itself: a program called `splunkd` (the real Splunk's name) started from someone's home folder, which the real one never does. Both were tested against a real Caldera attack and both work.

## Summary

| # | Name | MITRE ATT&CK | Status |
|---|---|---|---|
| 1 | Discovery burst: several reconnaissance commands in ten minutes | T1033, T1057, T1082, T1087.001 (T1016 is also in the rule) | **Proven** on 2 November: one row with four kinds of activity; alert saved |
| 2 | `./splunkd` started from a home directory | T1036.004 (masquerading) | **Proven**: found the agent start and the alert fired at 14:05 UTC on 2 November, severity High |
| 3 | Shell history cleared (`> $HOME/.bash_history && unset HISTFILE`) | T1070.003 | Idea only. The agent runs it at every start, so it is easy to catch |

## How commands are read (important)

Caldera runs its commands as `sh -c '...'`. When a command contains spaces or special characters, auditd writes it in **hexadecimal**, so field `a2` looks like `3E2024484F4D45...` and a plain search cannot match it. Every rule here first decodes it:

```
| eval a2d=if(a0="sh" AND a1="-c" AND match(a2,"^([0-9A-Fa-f]{2})+$"), urldecode(replace(a2,"([0-9A-Fa-f]{2})","%\1")), a2)
| eval cmd=if(a0="sh" AND a1="-c", a2d, a0)
```

After this, `cmd` holds the readable command, for example `cut -d: -f1 /etc/passwd | grep -v '_'`. The first version of detection 1 did not decode and only ever saw two plain commands, which is why it was not proven on 30 October.

## 1. Discovery burst: several reconnaissance commands in ten minutes

```
index=linux sourcetype=linux:audit type=EXECVE
| eval a2d=if(a0="sh" AND a1="-c" AND match(a2,"^([0-9A-Fa-f]{2})+$"), urldecode(replace(a2,"([0-9A-Fa-f]{2})","%\1")), a2)
| eval cmd=if(a0="sh" AND a1="-c", a2d, a0)
| eval technique=case(match(cmd,"^(whoami|id)(\s|$)"),"T1033 who am I", match(cmd,"(/etc/passwd|^getent\s+passwd)"),"T1087.001 account list", match(cmd,"^ps(\s|$)"),"T1057 process list", match(cmd,"^(uname|hostname)(\s|$)"),"T1082 system info", match(cmd,"^(ifconfig|netstat|ss|ip)(\s|$)"),"T1016 network config")
| where isnotnull(technique)
| bin _time span=10m
| stats dc(technique) AS techniques values(technique) AS what values(cmd) AS commands BY host _time
| where techniques>=3
| eval severity="Medium"
```

- **What it does:** each command is sorted into a kind of activity (who am I, account list, process list, system info, network config). It fires when one host shows **three or more different kinds** inside ten minutes. It counts kinds, not commands, so two `ps` commands count once.
- **Result on the test run:** one row, `soc-victim`, window 14:20 UTC, four kinds (T1033, T1057, T1082, T1087.001). The commands included `whoami`, `id`, `uname`, `ps aux | grep sshd` and `cut -d: -f1 /etc/passwd | grep -v '_'`.
- **Severity:** Medium, set in the last line (the bot reads the `severity` column).
- **Known limits:** the ten-minute windows are fixed, so a burst that straddles a boundary can be split in two; only commands started from a login session are recorded (see the auditd rule in [`infra/auditd/soc.rules`](../infra/auditd/soc.rules)); these are ordinary admin tools, so on a busy machine the threshold would need tuning. There is no `src_ip` column because local commands have no source address; the bot treats it as optional.

## 2. `./splunkd` started from a home directory

```
index=linux sourcetype=linux:audit type=EXECVE a0="./splunkd"
| rex field=a2 "https?://(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval severity="High"
| table _time host src_ip severity a0 a1 a2
```

- **Fires when** any process named `./splunkd` is started. The real Splunk is never started like this.
- **Result:** one row, `soc-victim`, `192.168.56.30` (the attacker), `High`. The columns `host`, `src_ip` and `severity` are what the bot's webhook reads, together with the alert's name.
- **Fired for real:** on 2 November the alert triggered at 14:05 UTC after a new agent was started. The next run found the same event and was held back by the throttle, as intended.

## Alert settings (saved in Splunk)

| Setting | Alert 1 (discovery burst) | Alert 2 (masquerading) |
|---|---|---|
| Title | `Discovery burst: several reconnaissance commands in ten minutes` | `Masquerading process: ./splunkd from home directory` |
| Schedule | Cron `*/5 * * * *`, last 15 minutes | Cron `*/5 * * * *`, last 15 minutes |
| Trigger | Results greater than 0, *For each result* | Results greater than 0, *For each result* |
| Throttle | Field `host`, 30 minutes | Field `host`, 30 minutes |
| Severity | Medium (in the search) | High (in the search and Splunk level 4) |
| Action | *Add to Triggered Alerts* for now; later a custom action that posts to the bot's webhook with the `X-Webhook-Secret` header | The same |
| Sharing | App (admin read and write, everyone read) | App |

## Stored copy and restoring

The definitions of both alerts are stored in [`infra/siem/splunk/savedsearches.conf`](../infra/siem/splunk/savedsearches.conf). To restore them, copy that file to `/opt/splunk/etc/apps/search/local/savedsearches.conf` inside the Splunk container (as the `splunk` user) and restart Splunk. A new alert is private and is first saved under `etc/users/admin/search/local/`; sharing it with the app (*Edit Permissions*) moves it to the app folder. Check with `docker exec -u splunk splunk grep "^\[" /opt/splunk/etc/apps/search/local/savedsearches.conf`.

## Idea: shell history cleared

Every agent start runs `> $HOME/.bash_history && unset HISTFILE`, which hides what an attacker did (MITRE T1070.003). A rule only needs to decode the command as above and match `bash_history` together with `unset HISTFILE`. Not built yet.
