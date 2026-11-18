"""The heartbeat alert needs both halves: the cron line on the victim and the search in Splunk."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRON = (ROOT / "infra" / "heartbeat" / "soc-heartbeat.cron").read_bytes()
CONF = (ROOT / "infra" / "siem" / "splunk" / "savedsearches.conf").read_text()
NAME = "[Heartbeat: no pipeline heartbeat from a host for 15 minutes]"


def test_cron_file_is_valid_for_cron_d():
    assert b"\r" not in CRON, "cron ignores files with Windows line endings"
    lines = [x for x in CRON.decode().splitlines() if x and not x.startswith("#")]
    assert len(lines) == 1
    minute, hour, dom, month, dow, user, *cmd = lines[0].split()
    assert (minute, hour, dom, month, dow, user) == ("*/5", "*", "*", "*", "*", "root")
    assert "soc-heartbeat" in " ".join(cmd) and "auth" in " ".join(cmd)


def test_search_looks_for_the_same_marker_the_cron_line_writes():
    section = CONF.split(NAME, 1)[1].split("\n[", 1)[0]
    assert '"soc-heartbeat: alive"' in section
    assert "action.soc_bot_webhook = 1" in section
    assert "dispatch.earliest_time = -24h" in section
    assert "silent_min>=15" in section
    for column in ("host", "severity", "description"):
        assert column in section.split("| table", 1)[1]
