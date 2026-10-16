import asyncio
from types import SimpleNamespace

import asyncssh
import pytest

from soc_bot.clients import APIError, NotFoundError, SshResponseClient
from soc_bot.clients import ssh_response

INVENTORY = {"soc-victim": "192.168.56.20", "srv1.corp.local": "10.0.0.5"}


def make_client(hosts=None, known_hosts=""):
    return SshResponseClient(
        hosts=hosts or INVENTORY, user="responder", key_path="id_bot", known_hosts=known_hosts
    )


class FakeSsh:
    """Stands in for asyncssh.connect: an object usable as `async with connect(...) as conn`."""

    def __init__(self, result=None, connect_error=None, run_error=None):
        self.result = result or SimpleNamespace(exit_status=0, stdout="isolated\n", stderr="")
        self.connect_error = connect_error
        self.run_error = run_error
        self.connects: list[tuple[str, dict]] = []
        self.commands: list[str] = []

    def __call__(self, address, **kwargs):
        self.connects.append((address, kwargs))
        return self

    async def __aenter__(self):
        if self.connect_error:
            raise self.connect_error
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, command, check=False):
        self.commands.append(command)
        if self.run_error:
            raise self.run_error
        return self.result


@pytest.fixture
def fake(monkeypatch):
    fake = FakeSsh()
    monkeypatch.setattr(ssh_response.asyncssh, "connect", fake)
    return fake


def test_exact_and_case_insensitive_match():
    client = make_client()
    assert client.resolve("SOC-Victim") == ("soc-victim", "192.168.56.20")
    assert client.resolve("srv1.corp.local") == ("srv1.corp.local", "10.0.0.5")


def test_short_name_resolves_to_unique_inventory_fqdn():
    assert make_client().resolve("srv1") == ("srv1.corp.local", "10.0.0.5")


@pytest.mark.parametrize("typed", ["dc01.evil.com", "soc-victim.evil.com", "srv1.evil.com", "srv1.corp.local.evil.com"])
def test_fqdn_with_foreign_domain_never_maps_to_an_inventory_host(typed):
    with pytest.raises(NotFoundError):
        make_client().resolve(typed)


def test_unknown_host_and_ambiguous_short_name():
    with pytest.raises(NotFoundError):
        make_client().resolve("dc01")
    ambiguous = make_client({"web.a.local": "10.0.0.1", "web.b.local": "10.0.0.2"})
    with pytest.raises(APIError) as exc:
        ambiguous.resolve("web")
    assert exc.value.status == 409 and "web.a.local" in exc.value.message


async def test_isolate_runs_only_the_fixed_command(fake):
    result = await make_client().isolate("srv1")

    assert fake.commands == ["sudo -n /usr/local/sbin/soc-isolate"]
    address, kwargs = fake.connects[0]
    assert address == "10.0.0.5"
    assert kwargs["username"] == "responder" and kwargs["client_keys"] == ["id_bot"]
    assert (result.host, result.action, result.output) == ("srv1.corp.local", "isolate", "isolated")


async def test_unisolate_command(fake):
    await make_client().unisolate("soc-victim")
    assert fake.commands == ["sudo -n /usr/local/sbin/soc-unisolate"]


async def test_host_key_checking_is_never_disabled(fake):
    await make_client().isolate("soc-victim")
    assert "known_hosts" not in fake.connects[0][1]  # None would turn verification off

    await make_client(known_hosts="C:/known_hosts").isolate("soc-victim")
    assert fake.connects[1][1]["known_hosts"] == "C:/known_hosts"


@pytest.mark.parametrize("typed", ["soc-victim; rm -rf /", "$(id)", "dc01.evil.com", "unknown"])
async def test_unlisted_or_hostile_names_never_open_a_connection(fake, typed):
    with pytest.raises(NotFoundError):
        await make_client().isolate(typed)
    assert fake.connects == [] and fake.commands == []


async def test_nonzero_exit_is_reported_with_script_output(monkeypatch):
    fake = FakeSsh(result=SimpleNamespace(exit_status=3, stdout="", stderr="ufw: not found\n"))
    monkeypatch.setattr(ssh_response.asyncssh, "connect", fake)
    with pytest.raises(APIError) as exc:
        await make_client().isolate("soc-victim")
    assert exc.value.status == 500 and "exited 3" in exc.value.message and "ufw: not found" in exc.value.message


@pytest.mark.parametrize(
    "kwargs",
    [
        {"connect_error": OSError("connection refused")},
        {"connect_error": asyncssh.PermissionDenied("no key")},
        {"run_error": asyncio.TimeoutError()},
    ],
)
async def test_connection_problems_map_to_502(monkeypatch, kwargs):
    monkeypatch.setattr(ssh_response.asyncssh, "connect", FakeSsh(**kwargs))
    with pytest.raises(APIError) as exc:
        await make_client().isolate("soc-victim")
    assert exc.value.status == 502
