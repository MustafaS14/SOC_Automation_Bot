# Scenario 02: Caldera "SOC demo discovery" operation

A Caldera operation that, on its own, produces the three reconnaissance techniques the *Discovery burst* detection needs, so the Discord alert comes from the attack tool and not from commands typed by hand. [Scenario 01](01-discovery.md) used Caldera's built-in Discovery adversary, which on Linux only repeated `ps` (one technique), so it never reached the threshold.

## What it proves

Caldera operation, then auditd on the victim, Filebeat, Logstash, Splunk, the *Discovery burst* alert, the custom alert action, the bot, and a card in `#soc-alerts`.

## Build it once in Caldera

**1. The ability** (*abilities*, then create):

| Field | Value |
|---|---|
| Name | `SOC demo recon` |
| Tactic | `discovery` |
| Technique | `T1082`, System Information Discovery |
| Executor | `sh`, platform `linux` |
| Command | `whoami; id; uname -a; hostname; ip a` |

Leave payloads, cleanup, requirements and parsers empty.

**2. The adversary** (*adversaries*, New Profile): name it `SOC demo discovery` (click the heading to edit the name, not the search box of the profile list), add the ability `SOC demo recon`, and save. The Executors column shows the Linux icon.

## Run it

1. Check that exactly one agent is alive on `soc-victim` (group `red`). See [lab operations](../docs/lab-operations.md) for starting it in the background.
2. *Operations*, new operation: name `SOC demo`, adversary `SOC demo discovery`, group `red`. Start it.
3. The ability runs once, within about a minute.

## What the evidence looks like

In Splunk (`index=linux sourcetype=linux:audit type=EXECVE | table _time a0 a1 a2`) one run gives, within about 20 ms of each other:

| `a0` | `a1` | Note |
|---|---|---|
| `sh` | `-c` | The agent starting the command; `a2` holds the command as hexadecimal (the detection decodes it) |
| `whoami` | | T1033 |
| `id` | | T1033 |
| `uname` | `-a` | T1082 |
| `hostname` | | T1082 |
| `ip` | `a` | T1016 |

That is three different techniques inside one ten-minute block, so the next 5-minute run of the alert returns a row and the bot posts **Discovery burst: several reconnaissance commands in ten minutes** (severity Medium, host `soc-victim`). The card has no source IP, so *Enrich IP* answers that there is none.

## Timing and repeats

The alert searches run every 5 minutes and look back 15 minutes; a throttle (`alert.suppress.period`) limits cards per host. With a 30-minute period you get one card per burst. With a 5-minute period (handy for a demo) the same burst can post up to three cards, 5 minutes apart, until its events leave the window. Details in [lab operations](../docs/lab-operations.md#when-a-card-appears).
