"""The coverage list must match the detections it claims, so it cannot drift into marketing."""

from pathlib import Path

from soc_bot.attack_coverage import (
    PLANNED, STATUSES, TACTICS, TECHNIQUES, TESTED, by_tactic, counts, navigator_layer, technique_url,
)
from soc_bot.models import TECHNIQUE_RE

CONF = (Path(__file__).resolve().parent.parent / "infra" / "siem" / "splunk" / "savedsearches.conf").read_text()


def test_every_entry_is_well_formed_and_unique():
    ids = [t.id for t in TECHNIQUES]
    assert len(ids) == len(set(ids))
    for t in TECHNIQUES:
        assert TECHNIQUE_RE.match(t.id), t.id
        assert t.status in STATUSES and t.tactic in TACTICS and t.name


def test_tested_techniques_name_real_rules_and_appear_in_them():
    for t in TECHNIQUES:
        if t.status == TESTED:
            assert t.rules, f"{t.id} is marked tested but has no rule"
            for rule in t.rules:
                assert f"[{rule}]" in CONF, f"{t.id}: rule {rule!r} is not in savedsearches.conf"
            assert t.id in CONF, f"{t.id} is marked tested but no saved search mentions it"


def test_planned_techniques_have_no_rule_yet():
    assert all(not t.rules for t in TECHNIQUES if t.status == PLANNED)


def test_grouping_totals_and_links():
    assert sum(len(rows) for _, rows in by_tactic()) == len(TECHNIQUES)
    assert sum(counts().values()) == len(TECHNIQUES)
    assert technique_url("T1036.005") == "https://attack.mitre.org/techniques/T1036/005/"
    assert technique_url("T1110") == "https://attack.mitre.org/techniques/T1110/"


def test_navigator_layer_lists_every_technique():
    layer = navigator_layer()
    assert layer["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in layer["techniques"]} == {t.id for t in TECHNIQUES}
