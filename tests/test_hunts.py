import pytest

from soc_bot import hunts
from soc_bot.validators import ValidationError


def test_host_hunt_fills_validated_target():
    spl, earliest = hunts.build("host_commands", "1h", "SOC-Victim")
    assert 'host="soc-victim"' in spl and earliest == "-1h"


def test_ip_hunt_normalises_ip():
    spl, _ = hunts.build("ip_activity", "24h", " 192.168.56.30 ")
    assert '"192.168.56.30"' in spl


def test_targetless_hunt_ignores_target():
    spl, _ = hunts.build("ssh_failures", "15m", None)
    assert "Failed password" in spl


@pytest.mark.parametrize("target", ['x" | delete', "a b", "host`", "", None])
def test_host_hunt_rejects_spl_injection(target):
    with pytest.raises(ValidationError):
        hunts.build("host_commands", "1h", target)


@pytest.mark.parametrize("name,window", [("nope", "1h"), ("ssh_failures", "-1h | delete"), ("ssh_failures", "30d")])
def test_unknown_template_or_window(name, window):
    with pytest.raises(ValidationError):
        hunts.build(name, window, None)
