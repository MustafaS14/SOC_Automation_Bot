import pytest

from soc_bot.validators import (
    ValidationError,
    is_protected_host,
    is_public_ip,
    parse_hostname,
    parse_incident_ref,
    parse_ip,
)


def test_incident_ref_number():
    assert parse_incident_ref("1042") == 1042
    assert parse_incident_ref("#7") == 7


@pytest.mark.parametrize(
    "value",
    ["0", "abc", "1 or 1=1", "' or ''='", "../../x", "\u00b2", "\u0663", "1" * 30,
     "0b3f8a9e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"],
)
def test_incident_ref_rejects_garbage(value):
    with pytest.raises(ValidationError):
        parse_incident_ref(value)


@pytest.mark.parametrize("parse", [parse_incident_ref, parse_ip, parse_hostname])
def test_errors_do_not_echo_markdown_breaking_characters(parse):
    with pytest.raises(ValidationError) as exc:
        parse("a`**b|\n@everyone`")
    message = str(exc.value)
    assert message.count("`") == 2 and "**" not in message and "\n" not in message and "@" not in message


def test_ip_parsing():
    assert is_public_ip(parse_ip("185.220.101.4"))
    assert not is_public_ip(parse_ip("10.0.0.1"))
    assert not is_public_ip(parse_ip("127.0.0.1"))
    with pytest.raises(ValidationError):
        parse_ip("999.1.1.1")


@pytest.mark.parametrize("value", ["WS-FIN-017", "srv-web-02.corp.contoso.com"])
def test_hostname_ok(value):
    assert parse_hostname(value) == value.lower()


@pytest.mark.parametrize("value", ["host'", "a b", "-bad", "x' or 1 eq 1 or 'a", ""])
def test_hostname_rejects_injection(value):
    with pytest.raises(ValidationError):
        parse_hostname(value)


def test_protected_hosts():
    denylist = ("dc*", "adfs*")
    assert is_protected_host("dc01", denylist)
    assert is_protected_host("dc01.corp.contoso.com", denylist)
    assert not is_protected_host("ws-fin-017", denylist)
