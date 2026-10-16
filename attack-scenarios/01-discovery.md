# Scenario 01: Caldera "Discovery" operation

First end-to-end test of the attack side: Caldera runs discovery commands on the victim, and auditd records them.

## Setup

| Item | Value |
|---|---|
| Operation name | `first-test` |
| Adversary | Discovery |
| Agent group | `red` (agent `splunkd`, Sandcat, on `soc-victim`) |
| Planner / obfuscator | atomic / plain-text |
| Collection on victim | auditd, rule `-a always,exit -F arch=b64 -S execve -k exec_cmd` |

## What the victim recorded (2026-10-16, UTC+2)

Excerpt from `ausearch -k exec_cmd -i`, with the lab's own housekeeping removed:

| Time | Command | Meaning |
|---|---|---|
| 17:11:58 | `whoami` | Agent's first instruction: identify the current user |
| 17:12:47 | `cut -d: -f1 /etc/passwd` | **Account discovery** (MITRE ATT&CK T1087.001) |
| 17:13:23 | `ps aux` | **Process discovery** (T1057) |
| 17:14:06 | `ps aux` | Repeated process listing |
| 17:15:00 | `ps aux` | Repeated process listing |

Benign background in the same window, which the pipeline should filter out:

| Time | Command | Why it is noise |
|---|---|---|
| 17:15:00 to 17:15:01 | `/bin/sh -c command -v debian-sa1 > /dev/null && debian-sa1 1 1` | sysstat cron job |
| 17:12:01 | `augenrules --load`, `auditctl -R ...`, `mktemp`, `awk` | Lab setup: loading the auditd rule |

## Detection ideas for this scenario

- A non-interactive process tree (`splunkd` → `sh` → `cut`/`ps`) running several discovery commands in a short time.
- Repeated `ps aux` from the same parent within a few minutes.
- Reads of `/etc/passwd` followed by process listing from one session.

These become SPL rules under `detections/` once Splunk is up.

## Reproduce

1. Start Caldera on `soc-attacker` and log in as `red`.
2. Start the Sandcat agent on `soc-victim`.
3. Create the operation above and start it.
4. On the victim: `sudo ausearch -k exec_cmd -i --start recent | grep proctitle`.
