from __future__ import annotations

import httpx


class APIError(RuntimeError):
    def __init__(self, service: str, status: int, message: str):
        super().__init__(f"{service} API error {status}: {message}")
        self.service = service
        self.status = status
        self.message = message


class NotFoundError(APIError):
    pass


class NotConfiguredError(RuntimeError):
    pass


def _error_message(resp: httpx.Response) -> str | None:
    try:
        body = resp.json()
    except ValueError:
        return resp.text
    if not isinstance(body, dict):
        return str(body)
    # Splunk REST: {"messages": [{"type": "FATAL", "text": "..."}]}
    messages = body.get("messages")
    if isinstance(messages, list):
        texts = [str(m["text"]) for m in messages if isinstance(m, dict) and m.get("text")]
        if texts:
            return "; ".join(texts)
    # HEC: {"text": "Invalid token", "code": 4}
    err = body.get("error", body)
    if isinstance(err, dict):
        value = err.get("message") or err.get("text")
        return str(value) if value else None
    return str(err)


def raise_for_status(service: str, resp: httpx.Response) -> None:
    if resp.status_code < 400:
        return
    cls = NotFoundError if resp.status_code == 404 else APIError
    message = (_error_message(resp) or resp.reason_phrase)[:300]
    raise cls(service, resp.status_code, message)
