import httpx
import pytest

from soc_bot.clients import APIError, HecClient, NotFoundError, SplunkClient, SshResponseClient
from soc_bot.models import IpReport


def make_splunk(handler):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return SplunkClient(http=http, base_url="https://splunk:8089/", token="tok")


async def test_search_posts_form_and_parses_ndjson():
    seen = {}

    def handler(request: httpx.Request):
        seen["path"] = request.url.path
        seen["auth"] = request.headers["Authorization"]
        seen["form"] = dict(httpx.QueryParams(request.content.decode()))
        body = '{"preview":false,"result":{"host":"soc-victim"}}\n{"lastrow":true}\nnot json\n'
        return httpx.Response(200, text=body)

    rows = await make_splunk(handler).search("search index=linux | head 1", earliest="-15m")

    assert seen["path"] == "/services/search/jobs/export"
    assert seen["auth"] == "Bearer tok"
    assert seen["form"]["earliest_time"] == "-15m" and seen["form"]["output_mode"] == "json"
    assert rows == [{"host": "soc-victim"}]


async def test_splunk_error_text_is_surfaced():
    client = make_splunk(
        lambda r: httpx.Response(400, json={"messages": [{"type": "FATAL", "text": "Unknown search command 'foo'."}]})
    )
    with pytest.raises(APIError) as exc:
        await client.search("search | foo")
    assert exc.value.status == 400 and "Unknown search command" in exc.value.message


async def test_splunk_unreachable_maps_to_api_error():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(APIError) as exc:
        await make_splunk(handler).search("search *")
    assert exc.value.status == 502


async def test_splunk_404_is_not_found():
    with pytest.raises(NotFoundError):
        await make_splunk(lambda r: httpx.Response(404, json={})).search("search *")


async def test_hec_sends_event_and_swallows_failures():
    seen = {}

    def handler(request: httpx.Request):
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"text": "Success", "code": 0})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await HecClient(http=http, url="https://splunk:8088/services/collector/event", token="hec").send({"a": 1})
    assert seen["auth"] == "Splunk hec"
    assert '"index":"soc_audit"' in seen["body"].replace(" ", "")

    failing = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"text": "Invalid token"})))
    await HecClient(http=failing, url="https://x", token="bad").send({"a": 1})  # must not raise


def test_ssh_inventory_is_an_allowlist():
    client = SshResponseClient(hosts={"soc-victim": "192.168.56.20"}, user="responder", key_path="k")
    assert client.resolve("SOC-VICTIM.lab.local") == "192.168.56.20"
    with pytest.raises(NotFoundError):
        client.resolve("dc01")


def test_verdict_is_incomplete_when_a_lookup_failed():
    report = IpReport(ip="8.8.8.8", is_public=True, abuse_score=0, errors=["VirusTotal: ReadTimeout"])
    assert report.verdict == "Incomplete"
    report.errors.clear()
    assert report.verdict == "Clean"


def test_verdict_levels():
    assert IpReport(ip="10.0.0.1", is_public=False).verdict == "Internal"
    assert IpReport(ip="1.1.1.1", is_public=True).verdict == "Unknown"
    assert IpReport(ip="1.1.1.1", is_public=True, abuse_score=75).verdict == "Malicious"
    assert IpReport(ip="1.1.1.1", is_public=True, vt_malicious=5).verdict == "Malicious"
    assert IpReport(ip="1.1.1.1", is_public=True, abuse_score=25).verdict == "Suspicious"
    assert IpReport(ip="1.1.1.1", is_public=True, vt_malicious=0, vt_suspicious=2).verdict == "Suspicious"
    # Real findings still win over a failed second lookup.
    assert IpReport(ip="1.1.1.1", is_public=True, abuse_score=90, errors=["x"]).verdict == "Malicious"
