# Roadmap

What is built, what comes next, and ideas for extending the project. The ideas are not commitments; the order is by value for effort. Current status is in the [README](../README.md).

## Phase 1: finish the pipeline

Done: `soc-siem` with Splunk and Logstash, the victim's auditd logs shipped through Filebeat, the Discovery and Masquerading detections, the Splunk alert action posting to the bot, and the web console reading live incidents and running hunts against Splunk ([live-lab.md](live-lab.md)).

Still to do:

1. ~~Create the `responder` user on the victim, restrict its SSH key with a forced command, and test isolation~~ **Done**: the key is limited to two exact commands (`restrict`, `from=` the SIEM, forced `soc-gate`), and the Isolate button and `/unisolate` were proven on a real card from Discord, with both actions in the audit channel. The firewall blocks TCP from the attacker while the SIEM can still reach the host. Ping still gets through an isolated host (UFW accepts ICMP echo by default); close that if it matters.
2. Add a retry path for the alert action: a card is lost today when the bot is down at the moment an alert fires.
3. Record a short demo: attack, alert in Discord, triage, isolation.

## Phase 2: make it look like real SOC work

| Idea | Why it matters |
|---|---|
| ~~Tag each detection with its MITRE ATT&CK technique and keep a coverage table~~ **Done**: techniques travel with each incident, and the console has a Coverage page with a Navigator export. Rules for cron, new user, sudo, SSH brute force and history clearing are built and each fired a real card | Real teams track detection coverage; it also shows the gaps |
| A detection test script: run a Caldera operation, wait, and check the expected alert reached the bot | Proves each rule works ("detection as code") |
| More scenarios, each with a write-up and a detection: SSH brute force, persistence through cron or a new user, privilege escalation attempt | A small library beats one demo |
| Alert noise control: ~~merge repeated alerts into one incident~~ **Done** (repeats fold into the open incident for an hour; `close-stale` sweeps untouched incidents after 24 hours, see [detections.md](detections.md#keeping-the-noise-down-three-layers)). Still open: suppress known-benign activity, raise severity on repetition | False positives are the everyday problem in a SOC; show alert counts before and after |
| Metrics from the incident store: time to detect and time to respond, shown in a `/stats` command or a dashboard | Managers ask for these numbers |
| ~~A heartbeat alert: a scheduled search that fires when a host stops sending~~ **Done**: a cron heartbeat on the victim and a Splunk search that fires after 15 silent minutes, proven by stopping Filebeat for 15 minutes and getting card #105 ([detections.md](detections.md), section 4). The console shows it live as a floating pulse widget ([web-console.md](web-console.md)) | A stalled Filebeat or Logstash looks the same as a quiet host, and the alert action does not retry, so silent pipeline failures go unnoticed |

## Phase 3: automation and reporting

| Idea | Why it matters |
|---|---|
| Automatic first response: on a high-severity alert, the bot runs `/hunt` and `/enrich` and attaches the results to the incident before an analyst opens it | This is the "automation" in the project name |
| A Splunk dashboard: alerts over time, top hosts, open versus closed incidents. **Alerts over time by attack type, next to raw log activity, is done** as the console's Timeline tab ([web-console.md](web-console.md)); top hosts and open versus closed are still open | Quick to build and good for screenshots |
| `/report`: a markdown summary of an incident (alert, actions, who did what, outcome) | Mirrors the post-incident reports real teams write |
| Forward the bot's and the console's audit logs to Splunk (`index=soc_audit`) as one tamper-resistant copy (the console's Audit page already merges both through the bot API) | Analysts see every action in one place |
| Show only the buttons that fit each alert type (a heartbeat card should not offer Isolate) | Fewer wrong clicks |
| Match source IPs and file hashes against a free threat-intel feed | Raises severity automatically on a hit |

## Phase 4: larger extensions (only if the rest is done)

- A Windows victim with Sysmon, since most enterprise attacks target Windows.
- Network telemetry with Suricata or Zeek on the host-only network, to see the command-and-control traffic.
- A runbook per alert type: what an analyst checks and when to isolate.
- Running the bot as a service, with database backups, token rotation and TLS between Splunk and the bot.

## Known gaps to close along the way

Listed in [security-review.md](security-review.md), under "Still open". The bot has not yet run against a live Splunk or a real isolation, and the auditd rule covers 64-bit `execve` only.
