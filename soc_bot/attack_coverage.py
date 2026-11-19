"""What the lab's detections cover in MITRE ATT&CK, in one place.

The console's coverage page and the ATT&CK Navigator export both read this list. Keep it honest: "tested" means a
real Caldera run produced an alert, "built" means the rule is written and saved but has not yet fired on a real
test, "planned" is a gap we know about and have not built yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

TESTED = "tested"
BUILT = "built"
PLANNED = "planned"
STATUSES = (TESTED, BUILT, PLANNED)
STATUS_LABELS = {TESTED: "Tested", BUILT: "Built, not yet proven", PLANNED: "Planned"}
STATUS_COLORS = {TESTED: "#8fc1b5", BUILT: "#e2c75f", PLANNED: "#ff8a00"}

# Order the tactics the way ATT&CK lists them.
TACTICS = ("Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery")

RULE_MASQUERADE = "Masquerading process: ./splunkd from home directory"
RULE_DISCOVERY = "Discovery burst: several reconnaissance commands in ten minutes"
RULE_HISTORY = "Shell history cleared or switched off"
RULE_USER = "New local user account created"
RULE_SUDO = "Risky sudo use: root shell, wrong password or not allowed"
RULE_BRUTE = "SSH brute force: many failed logins from one address"
RULE_CRON = "Cron job added or changed"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    status: str
    rules: tuple[str, ...] = ()
    note: str = ""


TECHNIQUES: tuple[Technique, ...] = (
    Technique("T1036.005", "Match Legitimate Resource Name or Location", "Defense Evasion", TESTED,
              (RULE_MASQUERADE,), "A Caldera agent named splunkd, started from a home directory."),
    Technique("T1070.003", "Clear Command History", "Defense Evasion", TESTED, (RULE_HISTORY,),
              "Run by Caldera: switches shell history off (card #49 on 19 November)."),
    Technique("T1033", "System Owner/User Discovery", "Discovery", TESTED, (RULE_DISCOVERY,), "whoami, id"),
    Technique("T1057", "Process Discovery", "Discovery", TESTED, (RULE_DISCOVERY,), "ps"),
    Technique("T1082", "System Information Discovery", "Discovery", TESTED, (RULE_DISCOVERY,), "uname, hostname"),
    Technique("T1087.001", "Account Discovery: Local Account", "Discovery", TESTED, (RULE_DISCOVERY,),
              "Reading /etc/passwd"),
    Technique("T1016", "System Network Configuration Discovery", "Discovery", TESTED, (RULE_DISCOVERY,),
              "ip, ifconfig, netstat, ss"),
    Technique("T1110", "Brute Force", "Credential Access", TESTED, (RULE_BRUTE,),
              "Five or more failed SSH logins from one address in ten minutes. Fired from a hand-run loop; the Caldera step still needs a re-run."),
    Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence", TESTED, (RULE_CRON,),
              "A write to a cron file. Fired from a hand test (card #59); needs the cron_change auditd rule on the victim."),
    Technique("T1136.001", "Create Account: Local Account", "Persistence", TESTED, (RULE_USER,),
              "Run by Caldera: useradd of a test account (cards #52 and #58)."),
    Technique("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation",
              TESTED, (RULE_SUDO,), "Run by Caldera: a root shell through sudo (cards #53 and #56)."),
)


def by_tactic() -> list[tuple[str, list[Technique]]]:
    """Techniques grouped by tactic, in ATT&CK order, tested ones first within each group."""
    groups = []
    for tactic in TACTICS:
        rows = [t for t in TECHNIQUES if t.tactic == tactic]
        rows.sort(key=lambda t: (STATUSES.index(t.status), t.id))
        if rows:
            groups.append((tactic, rows))
    return groups


def counts() -> dict[str, int]:
    return {status: sum(1 for t in TECHNIQUES if t.status == status) for status in STATUSES}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def navigator_layer() -> dict[str, Any]:
    """An ATT&CK Navigator layer (open it at https://mitre-attack.github.io/attack-navigator/)."""
    return {
        "name": "SOC lab detection coverage",
        "versions": {"attack": "18", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques the SOC lab's Splunk detections cover (tested or built) or still lack (planned).",
        "techniques": [
            {
                "techniqueID": t.id,
                "color": STATUS_COLORS[t.status],
                "comment": f"{STATUS_LABELS[t.status]}. " + (", ".join(t.rules) or "No rule yet."),
                "enabled": True,
            }
            for t in TECHNIQUES
        ],
        "legendItems": [{"label": STATUS_LABELS[s], "color": STATUS_COLORS[s]} for s in STATUSES],
    }
