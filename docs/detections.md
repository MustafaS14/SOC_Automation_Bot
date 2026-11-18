# Detections

The tripwires that turn recorded commands into alerts. Each one is written in SPL, Splunk's search language, and labelled with the MITRE ATT&CK technique it matches. Background: [lab-build-log.md](lab-build-log.md), sections 14 to 16. Scenario: [../attack-scenarios/01-discovery.md](../attack-scenarios/01-discovery.md).

## In simple words

An attacker who has just got into a machine usually looks around first: who am I, what is running, who else has an account. Each command is harmless alone, so the first tripwire watches for *several different kinds of looking around in a short time*. A second tripwire catches the attack tool itself: a program called `splunkd` (the real Splunk's name) started from someone's home folder, which the real one never does. Both were tested against a real Caldera attack and both work.

## Summary

| # | Name | MITRE ATT&CK | Status |
|---|---|---|---|
| 1 | Discovery burst: several reconnaissance commands in ten minutes | T1033, T1057, T1082, T1087.001 (T1016 is also in the rule) | **Proven** on 2 November: one row with four kinds of activity; alert saved |
| 2 | `./splunkd` started from a home directory | T1036.005 (match legitimate name) | **Proven**: found the agent start and the alert fired at 14:05 UTC on 2 November, severity High |
| 3 | Shell history cleared (`> $HOME/.bash_history && unset HISTFILE`) | T1070.003 | Idea only. The agent runs it at every start, so it is easy to catch |
| 4 | Heartbeat: no pipeline heartbeat from a host for 15 minutes | none (health check, not an attack) | Written, not yet proven: needs the cron file on the victim and a real outage test |

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
| stats dc(technique) AS kinds values(technique) AS what values(cmd) AS commands BY host _time
| where kinds>=3
| eval severity="Medium"
| eval techniques=mvjoin(mvmap(what, replace(what," .*","")), ",")
| eval description="Reconnaissance burst: ".kinds." different techniques in ten minutes (".mvjoin(what,", ")."). Commands: ".mvjoin(commands,"; ")
```

- **What it does:** each command is sorted into a kind of activity (who am I, account list, process list, system info, network config). It fires when one host shows **three or more different kinds** inside ten minutes. It counts kinds, not commands, so two `ps` commands count once.
- **Result on the test run:** one row, `soc-victim`, window 14:20 UTC, four kinds (T1033, T1057, T1082, T1087.001). The commands included `whoami`, `id`, `uname`, `ps aux | grep sshd` and `cut -d: -f1 /etc/passwd | grep -v '_'`.
- **Severity and description:** Medium, set in the `severity` column. The `description` column lists the techniques and the exact commands, and the Discord card shows it (see below).
- **Known limits:** the ten-minute windows are fixed, so a burst that straddles a boundary can be split in two; only commands started from a login session are recorded (see the auditd rule in [`infra/auditd/soc.rules`](../infra/auditd/soc.rules)); these are ordinary admin tools, so on a busy machine the threshold would need tuning. There is no `src_ip` column because local commands have no source address; the bot treats it as optional.

## 2. `./splunkd` started from a home directory

```
index=linux sourcetype=linux:audit type=EXECVE a0="./splunkd"
| rex field=a2 "https?://(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval severity="High"
| eval cmd=trim(a0." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")." ".coalesce(a5,""))
| eval techniques="T1036.005"
| eval description="T1036.005 Masquerading: a process named splunkd was started from the current directory. Command: ".cmd
| table _time host src_ip severity techniques description a0 a1 a2
```

- **Fires when** any process named `./splunkd` is started. The real Splunk is never started like this.
- **Result:** one row, `soc-victim`, `192.168.56.30` (the attacker), `High`. The columns `host`, `src_ip`, `severity` and `description` are what the bot's webhook reads, together with the alert's name. The `description` holds the full command line.
- **Fired for real:** on 2 November the alert triggered at 14:05 UTC after a new agent was started. The next run found the same event and was held back by the throttle, as intended.

## 4. Heartbeat: no pipeline heartbeat from a host for 15 minutes

```
index=linux sourcetype=linux:auth "soc-heartbeat: alive"
| stats latest(_time) AS last_seen BY host
| eval silent_min=round((now()-last_seen)/60)
| where silent_min>=15
| eval severity="Medium"
| eval description="No heartbeat from ".host." for ".silent_min." minutes. Filebeat, Logstash, Splunk or the host itself may have stopped; a quiet host still sends one every five minutes."
| table host severity description silent_min
```

- **Why:** the other rules only speak when something happens. If Filebeat, Logstash or the network link stops, nothing is logged and nothing alerts, which looks the same as a quiet night. A host that is alive writes one line every five minutes, so silence is a signal.
- **How:** a cron file on the victim ([`infra/heartbeat/soc-heartbeat.cron`](../infra/heartbeat/soc-heartbeat.cron)) writes `soc-heartbeat: alive` to `auth.log` every five minutes. Filebeat already ships that file. The search takes the newest heartbeat per host over the last 24 hours and fires when it is 15 minutes old or more.
- **Safe to install in any order:** a host that has never sent a heartbeat has no row, so the alert stays silent until the cron file is installed. The search covers 24 hours, so a host silent for longer than that drops out.
- **Limits:** it proves the path from the victim to Splunk, not the path from Splunk to the bot. If Splunk or the bot itself is down, no card appears, and the console's status strip is the place to see that. The throttle repeats the card every 30 minutes (or 5 minutes with `install_alerts.sh 5m`) for as long as the host stays silent. It has no ATT&CK technique, so the Coverage page does not list it.

## How techniques reach the incident

Each search ends with a `techniques` column holding the ATT&CK IDs it matched, for example `T1036.005` or `T1033,T1057,T1082`. The alert action already forwards the whole result row, so nothing in the Splunk app changes. The bot's webhook keeps only values shaped like `T1234` or `T1234.567` (anything else is dropped, so free text cannot reach a card or a page), stores them with the incident and shows them on the Discord card, on the incident page and in the read-only API (`/api/incidents?technique=T1036` filters, and a parent ID also matches its sub-techniques). The console's **Coverage** page lists what is covered and what is still a gap, and offers the list as an ATT&CK Navigator layer. The list lives in [`soc_bot/attack_coverage.py`](../soc_bot/attack_coverage.py), and a test checks that every technique marked tested really appears in a saved search.

## What the Discord card shows

The `description` column becomes the text of the card, so an analyst sees what happened without opening Splunk. Example from a live run (card #10): *Reconnaissance burst: 3 different techniques in ten minutes (T1016 network config, T1033 who am I, T1082 system info). Commands: hostname; ip; uname; whoami.* The masquerading card shows the full `./splunkd ...` command line and the attacker address from `src_ip`. Keep the description to a few hundred characters: the card shows the first 1000.

## Alert settings (saved in Splunk)

| Setting | Alert 1 (discovery burst) | Alert 2 (masquerading) |
|---|---|---|
| Title | `Discovery burst: several reconnaissance commands in ten minutes` | `Masquerading process: ./splunkd from home directory` |
| Schedule | Cron `*/5 * * * *`, last 15 minutes | Cron `*/5 * * * *`, last 15 minutes |
| Trigger | Results greater than 0, *For each result* | Results greater than 0, *For each result* |
| Throttle | Field `host`, 30 minutes (the repo default; `infra/siem/splunk/install_alerts.sh 5m` installs a shorter one for demos) | Field `host`, 30 minutes (same) |
| Severity | Medium (in the search) | High (in the search and Splunk level 4) |
| Action | *Add to Triggered Alerts*, plus the custom action `soc_bot_webhook` that posts to the bot's webhook with the `X-Webhook-Secret` header (see [`soc_bot_alert`](../infra/siem/splunk/soc_bot_alert/README.md); enabled by `action.soc_bot_webhook = 1` in `savedsearches.conf`) | The same |
| Sharing | App (admin read and write, everyone read) | App |

## Stored copy and restoring

The definitions of both alerts are stored in [`infra/siem/splunk/savedsearches.conf`](../infra/siem/splunk/savedsearches.conf). To restore them, copy that file to `/opt/splunk/etc/apps/search/local/savedsearches.conf` inside the Splunk container (as the `splunk` user) and restart Splunk. A new alert is private and is first saved under `etc/users/admin/search/local/`; sharing it with the app (*Edit Permissions*) moves it to the app folder. Check with `docker exec -u splunk splunk grep "^\[" /opt/splunk/etc/apps/search/local/savedsearches.conf`.

## Idea: shell history cleared

Every agent start runs `> $HOME/.bash_history && unset HISTFILE`, which hides what an attacker did (MITRE T1070.003). A rule only needs to decode the command as above and match `bash_history` together with `unset HISTFILE`. Not built yet.

## Proven end to end

A real alert has travelled the whole path: commands on the victim, auditd, Filebeat, Logstash, Splunk, the *Discovery burst* alert, the custom alert action, the bot and a card in `#soc-alerts`. The Caldera Discovery run only repeated `ps`, so `whoami`, `id`, `uname -a`, `hostname` and `ip a` were typed on the victim to reach three techniques in one ten-minute window. The alert throttle (30 minutes per host) means a second firing in that window is silent by design.
