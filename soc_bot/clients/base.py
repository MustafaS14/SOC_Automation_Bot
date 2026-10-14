from __future__ import annotations

from typing import Any, Protocol

import httpx


class APIError(RuntimeError):
    def __init__(self, service: str, status: int, message: str):
        super().__init__(f"{service} API error {status}: {message}")
        self.service = service
        self.status = status
        self.message = message


class NotFoundError(APIError):
    pass


class AsyncTokenCredential(Protocol):
    async def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...


async def bearer_headers(credential: AsyncTokenCredential, scope: str) -> dict[str, str]:
    token = await credential.get_token(scope)
    return {"Authorization": f"Bearer {token.token}", "Content-Type": "application/json"}


def raise_for_status(service: str, resp: httpx.Response) -> None:
    if resp.status_code < 400:
        return
    try:
        body = resp.json()
        err = body.get("error", body)
        message = err.get("message") if isinstance(err, dict) else str(err)
    except ValueError:
        message = resp.text[:300]
    cls = NotFoundError if resp.status_code == 404 else APIError
    raise cls(service, resp.status_code, message or resp.reason_phrase)
