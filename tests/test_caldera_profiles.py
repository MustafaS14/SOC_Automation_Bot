"""The Caldera attack profiles must stay in step with the coverage list they exercise."""

import re
from pathlib import Path

import pytest

from soc_bot.attack_coverage import BUILT, TECHNIQUES, TESTED

ROOT = Path(__file__).resolve().parent.parent / "attack-scenarios" / "caldera"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _abilities() -> dict[str, str]:
    return {p.stem: p.read_text() for p in sorted((ROOT / "abilities").glob("*.yml"))}


def _field(text: str, name: str) -> str:
    return re.search(rf"^\s*(?:- )?{name}: (.+)$", text, re.M).group(1).strip()


def test_every_ability_is_well_formed_and_named_after_its_file():
    abilities = _abilities()
    assert len(abilities) >= 6
    for ident, text in abilities.items():
        assert UUID.match(ident), ident
        assert _field(text, "id") == ident
        assert "platform: linux" in text and "command: |" in text
        assert "\r" not in text, "Caldera files must use Unix line endings"


def test_abilities_cover_the_built_and_tested_attack_techniques_they_claim():
    known = {t.id for t in TECHNIQUES if t.status in (TESTED, BUILT)}
    claimed = {_field(text, "technique_id") for text in _abilities().values()}
    assert claimed <= known, claimed - known
    # One ability for each technique that is not plain discovery.
    assert {"T1053.003", "T1136.001", "T1548.003", "T1110", "T1070.003"} <= claimed


def test_the_adversary_lists_only_abilities_that_exist_once_each():
    adversary = next((ROOT / "adversaries").glob("*.yml")).read_text()
    order = re.findall(r"^- ([0-9a-f-]{36})$", adversary, re.M)
    assert order and len(order) == len(set(order))
    assert set(order) == set(_abilities())
    assert _field(adversary, "adversary_id") in str(next((ROOT / "adversaries").glob("*.yml")))


def test_ability_commands_would_trip_the_rules_they_target():
    text = {_field(t, "technique_id"): t for t in _abilities().values()}
    assert "crontab" in text["T1053.003"]
    assert "useradd" in text["T1136.001"]
    assert re.search(r"sudo /bin/sh", text["T1548.003"])
    assert "Failed password" not in text["T1110"] and "fakeuser" in text["T1110"] and "127.0.0.1" in text["T1110"]
    assert re.search(r"unset HISTFILE", text["T1070.003"])


def test_install_script_has_unix_line_endings():
    assert b"\r" not in (ROOT / "install.sh").read_bytes()


def test_every_file_is_valid_yaml_with_the_fields_caldera_reads():
    yaml = pytest.importorskip("yaml")
    for ident, text in _abilities().items():
        (ability,) = yaml.safe_load(text)
        assert ability["id"] == ident and ability["name"] and ability["technique_id"] and ability["technique_name"]
        (executor,) = ability["executors"]
        assert executor["platform"] == "linux" and executor["name"] == "sh" and executor["command"].strip()
    adversary = yaml.safe_load(next((ROOT / "adversaries").glob("*.yml")).read_text())
    assert adversary["name"] and adversary["atomic_ordering"] and adversary["adversary_id"]
