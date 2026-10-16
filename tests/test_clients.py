import httpx
import pytest

from soc_bot.clients import APIError, HecClient, NotFoundError, SplunkClient


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


@pytest.mark.parametrize(
    "body",
    [["a", "list"], "just a string", {"messages": "not a list"}, {"messages": [{"text": 5}, "x", None]},
     {"error": ["nested", "list"]}, {"error": {"message": None}}, None],
)
async def test_unexpected_error_shapes_do_not_crash(body):
    client = make_splunk(lambda r: httpx.Response(500, json=body))
    with pytest.raises(APIError) as exc:
        await client.search("search *")
    assert exc.value.status == 500


async def test_error_messages_are_truncated_to_300_chars():
    long = "x" * 1000
    for response in (httpx.Response(400, text=long), httpx.Response(400, json={"error": {"message": long}}),
                     httpx.Response(400, json={"messages": [{"text": long}]})):
        with pytest.raises(APIError) as exc:
            await make_splunk(lambda r, resp=response: resp).search("search *")
        assert len(exc.value.message) == 300


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
