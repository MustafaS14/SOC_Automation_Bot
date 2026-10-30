# Detections

The tripwires that turn recorded commands into alerts. Each one is written in SPL, Splunk's search language, and labelled with the MITRE ATT&CK technique it matches. Background: [lab-build-log.md](lab-build-log.md), section 14. Scenario: [../attack-scenarios/01-discovery.md](../attack-scenarios/01-discovery.md).

## In simple words

An attacker who has just got into a machine usually looks around first: who am I, what is running, who else has an account. Each command is harmless alone, so the tripwire watches for *several in a short time*. A second tripwire catches the attack tool itself: a program called `splunkd` (the real Splunk's name) started from someone's home folder, which the real one never does.

## Summary

| # | Name | MITRE ATT&CK | Status |
|---|---|---|---|
| 1 | Several discovery commands in ten minutes | T1033, T1082, T1057, T1087.001 | Written; ran without error; **not yet proven** (only two different commands fell in the test window) |
| 2 | `./splunkd` started from a home directory | T1036.004 (masquerading) | **Proven**: found the one agent start and extracted the attacker's address |

## 1. Several discovery commands in ten minutes

Caldera runs commands through `sh -c '...'`, so the real command can be in field `a2`. The rule reads it from `a2` when `a0` is `sh`, otherwise from `a0`.

```
index=linux sourcetype=linux:audit type=EXECVE
| eval cmd=if(a0="sh" AND a1="-c", a2, a0)
| rex field=cmd "^(?<prog>\S+)"
| eval prog=replace(prog, "^.*/", "")
| where prog IN ("whoami","id","uname","hostname","ps","ifconfig","netstat","ss","w","last","getent")
| bin _time span=10m
| stats dc(prog) AS distinct_cmds values(prog) AS commands min(_time) AS first_seen BY host _time
| where distinct_cmds>=3
```

- **Fires when** one host runs three or more different commands from the list inside a ten-minute window.
- **Tuning:** use `>=2` while testing; raise it to 3 after a full Discovery run. Login-banner scripts (`tr`, `cut -c2-`) are noise and are not in the list.
- **Known limit:** only commands started from a login session are recorded (see the auditd rule in [`infra/auditd/soc.rules`](../infra/auditd/soc.rules)).

## 2. `./splunkd` started from a home directory

```
index=linux sourcetype=linux:audit type=EXECVE a0="./splunkd"
| rex field=a2 "https?://(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval severity="High"
| table _time host src_ip severity a0 a1 a2
```

- **Fires when** any process named `./splunkd` is started. The real Splunk is never started like this.
- **Result:** one row, `soc-victim`, `192.168.56.30` (the attacker), `High`. The columns `host`, `src_ip` and `severity` are what the bot's webhook reads, together with the alert's name.

## Alert settings (to recreate in Splunk)

| Setting | Value |
|---|---|
| Title | `Masquerading process: ./splunkd from home directory` |
| Type | Scheduled, cron `*/5 * * * *`, time range *Last 15 minutes* |
| Trigger | Number of results greater than 0, *For each result* |
| Throttle | Suppress on field `host` for 30 minutes |
| Action | *Add to Triggered Alerts* for now; later a custom action that posts to the bot's webhook with the `X-Webhook-Secret` header |

The first attempt to save this alert was lost when the SIEM VM crashed. Once the alerts exist and work, a copy of their definitions (`savedsearches.conf`) should be stored under `infra/` so they can be restored.
