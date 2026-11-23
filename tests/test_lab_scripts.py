"""The lab start/stop scripts must at least parse, use LF endings and stay safe to re-run."""

import shutil
import subprocess
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parent.parent / "scripts" / "lab"
SCRIPTS = sorted(LAB.glob("*.sh"))


def test_expected_scripts_exist():
    names = {p.name for p in SCRIPTS}
    assert {"start-siem.sh", "start-victim.sh", "start-attacker.sh",
            "stop-siem.sh", "stop-attacker.sh", "stop-victim.sh", "lib.sh"} <= names
    assert (LAB / "start-tunnels.ps1").exists()


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_uses_lf_endings(script):
    assert b"\r" not in script.read_bytes(), f"{script.name} has CRLF line endings"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_parses(script):
    result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_victim_script_keeps_one_agent_and_never_hard_codes_secrets():
    text = (LAB / "start-victim.sh").read_text()
    assert "pgrep -x splunkd" in text          # counts agents before starting another
    for banned in ("password=", "TOKEN=", "API_SECRET="):
        assert banned not in text


def test_agent_runs_on_the_victim_not_the_attacker():
    # The agent must run where auditd and Filebeat watch it. Starting it on soc-attacker
    # produced no alerts, so the attacker script must never start one.
    assert "./splunkd" not in (LAB / "start-attacker.sh").read_text()
    assert "./splunkd" in (LAB / "start-victim.sh").read_text()


def test_attacker_script_recovers_from_unreadable_caldera_state():
    assert "--fresh" in (LAB / "start-attacker.sh").read_text()


def test_victim_script_checks_the_cron_rules():
    assert "cron_change" in (LAB / "start-victim.sh").read_text()
