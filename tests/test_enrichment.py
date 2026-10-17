import httpx
import pytest

from soc_bot.clients import EnrichmentClient
from soc_bot.validators import ValidationError

PUBLIC_IP = "185.220.101.4"
ABUSE_OK = {"data": {"abuseConfidenceScore": 5, "totalReports": 2, "countryCode": "DE", "isp": "ISP"}}
VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60},
                                 "as_owner": "AS", "country": "DE"}}}


class Router:
    """MockTransport handler: one response (or exception) per upstream, and a log of calls made."""

    def __init__(self, abuse=None, vt=None):
        self.abuse = abuse if abuse is not None else httpx.Response(200, json=ABUSE_OK)
        self.vt = vt if vt is not None else httpx.Response(200, json=VT_OK)
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request):
        self.calls.append(request.url.host)
        outcome = self.abuse if request.url.host == "api.abuseipdb.com" else self.vt
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_client(router, abuse_key="a", vt_key="v"):
    http = httpx.AsyncClient(transport=httpx.MockTransport(router))
    return EnrichmentClient(http=http, abuseipdb_key=abuse_key, virustotal_key=vt_key)


async def test_both_sources_ok_gives_no_errors():
    report = await make_client(Router()).enrich_ip(PUBLIC_IP)
    assert report.errors == []
    assert (report.abuse_score, report.vt_malicious, report.country) == (5, 0, "DE")
    assert report.verdict == "Clean"


async def test_abuseipdb_http_error_is_recorded_and_verdict_is_incomplete():
    report = await make_client(Router(abuse=httpx.Response(500))).enrich_ip(PUBLIC_IP)
    assert report.errors == ["AbuseIPDB: HTTPStatusError"]
    assert report.vt_malicious == 0 and report.abuse_score is None
    assert report.verdict == "Incomplete"


async def test_virustotal_timeout_is_recorded_and_verdict_is_incomplete():
    report = await make_client(Router(vt=httpx.ReadTimeout("slow"))).enrich_ip(PUBLIC_IP)
    assert report.errors == ["VirusTotal: ReadTimeout"]
    assert report.abuse_score == 5
    assert report.verdict == "Incomplete"


async def test_a_failed_lookup_does_not_hide_a_malicious_finding_from_the_other_source():
    router = Router(abuse=httpx.Response(200, json={"data": {"abuseConfidenceScore": 100}}),
                    vt=httpx.ConnectError("down"))
    report = await make_client(router).enrich_ip(PUBLIC_IP)
    assert report.errors == ["VirusTotal: ConnectError"] and report.verdict == "Malicious"


async def test_both_sources_failing_is_incomplete_not_unknown_or_clean():
    router = Router(abuse=httpx.ConnectError("down"), vt=httpx.Response(429))
    report = await make_client(router).enrich_ip(PUBLIC_IP)
    assert sorted(report.errors) == ["AbuseIPDB: ConnectError", "VirusTotal: HTTPStatusError"]
    assert report.verdict == "Incomplete"


async def test_invalid_json_body_is_recorded_as_an_error():
    report = await make_client(Router(vt=httpx.Response(200, text="<html>not json"))).enrich_ip(PUBLIC_IP)
    assert len(report.errors) == 1 and report.errors[0].startswith("VirusTotal:")
    assert report.verdict == "Incomplete"


@pytest.mark.parametrize("body", [[], "text", None, 5, {"data": None}, {"data": []}, {"data": {"attributes": None}}])
async def test_unexpected_json_shapes_are_errors_not_crashes(body):
    router = Router(abuse=httpx.Response(200, json=body), vt=httpx.Response(200, json=body))
    report = await make_client(router).enrich_ip(PUBLIC_IP)
    assert report.verdict in {"Incomplete", "Unknown"}
    assert report.verdict != "Clean"


async def test_no_keys_configured_makes_no_calls_and_says_so():
    router = Router()
    report = await make_client(router, abuse_key=None, vt_key=None).enrich_ip(PUBLIC_IP)
    assert router.calls == []
    assert report.errors == ["No threat-intel API keys configured"]
    assert report.verdict == "Incomplete"


async def test_a_source_without_a_key_is_skipped_without_counting_as_a_failure():
    router = Router()
    report = await make_client(router, vt_key=None).enrich_ip(PUBLIC_IP)
    assert router.calls == ["api.abuseipdb.com"] and report.errors == []


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.56.20", "127.0.0.1"])
async def test_private_addresses_are_never_sent_upstream(ip):
    router = Router()
    report = await make_client(router).enrich_ip(ip)
    assert router.calls == [] and report.errors == [] and report.verdict == "Internal"


async def test_invalid_ip_is_rejected_before_any_call():
    router = Router()
    with pytest.raises(ValidationError):
        await make_client(router).enrich_ip("not-an-ip")
    assert router.calls == []
