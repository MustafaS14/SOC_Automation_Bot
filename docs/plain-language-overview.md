# The project in plain language

This page explains what the project does and what has been built so far, without technical jargon. The other documents go into the details; this one is for anyone who wants the big picture.

## The idea in one minute

Imagine a shop with a burglar alarm, a camera system and a security guard.

- The **cameras and door sensors** write down everything that happens.
- A **control room** collects all those notes in one place, so nobody has to walk around reading them.
- When something suspicious is spotted, the control room **rings the guard's phone**.
- The guard decides what to do: look closer, call it a false alarm, or lock a door.

This project builds exactly that, but for computers. It is called a **SOC** (Security Operations Centre): a team and a set of tools whose job is to notice when someone is attacking a computer, and to react quickly.

Everything runs on one laptop, using **virtual computers** (computers simulated inside a program). Nothing touches the real internet or a real company, so it is safe to practise attacks on it.

## The cast

| In the project | What it is | The shop comparison |
|---|---|---|
| **Attacker** (`soc-attacker`) | A virtual computer running a tool called Caldera that plays the role of a burglar and performs realistic, harmless break-in steps | A friendly actor who pretends to be a burglar to test the alarm |
| **Victim** (`soc-victim`) | A virtual computer that gets "attacked" and keeps a diary of everything it does | The shop |
| **auditd** | A built-in Linux program that writes down every command run on the victim | The cameras |
| **Filebeat** | A small courier on the victim that takes the diary pages and sends them off | A courier carrying the camera tapes to the control room |
| **Logstash** | A sorting office that reads each page, throws away the junk, labels the rest and passes it on | The person who sorts the tapes and discards the boring ones |
| **Splunk** | A very fast searchable archive where all the notes end up, and which can raise alerts | The control room's screens and filing cabinet |
| **Discord bot** | A chat assistant that receives the alerts and lets the analyst react from a chat app | The guard's phone |
| **Analyst** | The human in charge: you | The guard |

The three virtual computers are called `soc-attacker`, `soc-victim` and `soc-siem` (the control room). SIEM stands for "Security Information and Event Management": a system that collects and searches security notes.

## The journey of one event

1. The actor (Caldera) makes the victim run a command, for example one that asks "who am I logged in as?" (`whoami`).
2. **auditd** writes a line in its diary: who ran what, and when.
3. **Filebeat** picks up the new line and sends it over the lab network.
4. **Logstash** receives it, checks it is worth keeping, stamps it with the correct time and a label ("this is an audit note"), and forwards it.
5. **Splunk** stores it. A few seconds after the command was typed, it can be found by searching.
6. *(Next step)* A rule in Splunk notices that this command looks like an attacker exploring the machine, and sends an alert to the Discord bot.

Steps 1 to 5 are working and tested. Step 6 is what is being built next.

## What has been done so far

- **Three virtual computers built and connected** on a private network that is cut off from the real world.
- **The attacker tool works.** The first practice attack (called "Discovery", where the attacker looks around to see what machine it is on) was run and its traces were recorded.
- **A Discord bot was written and reviewed.** It can receive alerts, keep a list of incidents, search Splunk and, with the analyst's permission, cut a machine off from the network. It has automatic tests but has not yet run against the real Splunk.
- **The control room (Splunk) was installed** in a container (a sealed box holding a program and everything it needs).
- **The pipeline was connected end to end.** Notes from the victim now flow through the courier and the sorting office into Splunk.
- **The noise was cut.** At the first attempt more than 135,000 notes arrived in a few hours, mostly meaningless background chatter. After tuning, only the notes that matter are kept (a couple of hundred for the same period). This is important: an analyst who sees too many alerts stops noticing the real ones.
- **The result was checked.** Four test commands were typed on the victim; they appeared in Splunk with the right time, a few seconds later. The clocks on both machines agree.

## What had to be solved along the way (short version)

- **The control room kept freezing.** The virtual machine was too weak for the amount of work Splunk does when it starts. Giving it more processor power fixed it.
- **Too much junk arrived.** The fix was to record only what real people do in login sessions, and to throw away repeated pieces of each note.
- **A leftover backup file confused the sorting office.** It read the backup as if it were an instruction and labelled everything twice. Lesson: never leave spare copies in a folder that a program reads everything from.
- **Everything looked "late" at first.** After a restart, the courier re-sent old pages, so some notes arrived minutes after they were written. Fresh events arrive within seconds.

The full list is in [troubleshooting.md](troubleshooting.md).

## What comes next

1. Run the practice attack again and see exactly what it leaves in Splunk.
2. Write the **first detection**: a Splunk rule that recognises "an attacker is looking around" and labels it with its code in the MITRE ATT&CK catalogue (a public list of how attackers behave, where each technique has an ID such as T1087 for "account discovery").
3. Make Splunk **send an alert to the Discord bot**, and let the bot show it with buttons: acknowledge, investigate, isolate.
4. Test the isolation button on a snapshot (a saved copy of the victim that can be restored in a minute).
5. Later: let an AI assistant read the alerts and write short summaries for the analyst. It will only be allowed to read, never to act.

## Small glossary

| Word | Meaning |
|---|---|
| **VM (virtual machine)** | A computer simulated inside another computer |
| **Snapshot** | A saved copy of a VM at a moment in time, to go back to if something breaks |
| **Log** | A written record of what happened on a computer |
| **Alert** | A message saying "this looks suspicious" |
| **Detection** | A rule that decides what counts as suspicious |
| **False positive** | An alert about something harmless |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, used to label detections |
| **Container (Docker)** | A sealed box holding one program and everything it needs, so it runs the same everywhere |
| **Index (in Splunk)** | A labelled drawer in the archive |
| **HEC** | Splunk's front door for receiving events over the network |

For the technical details, continue with [architecture.md](architecture.md) and [lab-build-log.md](lab-build-log.md).
