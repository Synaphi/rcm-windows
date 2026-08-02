from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


def _method(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("HTTP method must be a string")
    normalized = value.strip().upper()
    if not normalized or not normalized.isascii() or not normalized.isalpha():
        raise ValueError("HTTP method must contain ASCII letters only")
    return normalized


def _route(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("fake HTTP routes must be absolute route paths")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("//"):
        raise ValueError("fake HTTP transport rejects hosts and ports")
    if parsed.fragment:
        raise ValueError("fake HTTP routes must not contain fragments")
    return value


@dataclass(frozen=True, slots=True)
class FakeHttpResponse:
    status: int
    json_data: Any = None
    headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("status must be an HTTP status integer")

    def clone(self) -> FakeHttpResponse:
        return FakeHttpResponse(
            self.status,
            deepcopy(self.json_data),
            tuple(self.headers),
        )

    def snapshot(self) -> dict[str, object]:
        return {
            "status": self.status,
            "json_data": deepcopy(self.json_data),
            "headers": [list(header) for header in self.headers],
        }


class FakeHttpTransport:
    def __init__(self) -> None:
        self._responses: dict[tuple[str, str], FakeHttpResponse] = {}
        self._requests: list[dict[str, object]] = []

    def register(
        self,
        method: str,
        route: str,
        response: FakeHttpResponse,
    ) -> None:
        key = (_method(method), _route(route))
        if key in self._responses:
            raise ValueError("fake HTTP response already registered")
        self._responses[key] = response.clone()

    def request(
        self,
        method: str,
        route: str,
        *,
        json_data: Any = None,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> FakeHttpResponse:
        key = (_method(method), _route(route))
        self._requests.append(
            {
                "method": key[0],
                "route": key[1],
                "json_data": deepcopy(json_data),
                "headers": [list(header) for header in headers],
            }
        )
        try:
            return self._responses[key].clone()
        except KeyError as exc:
            raise LookupError("unregistered fake HTTP request") from exc

    def clear(self) -> None:
        self._responses.clear()
        self._requests.clear()

    def snapshot(self) -> dict[str, object]:
        responses = []
        for method, route in sorted(self._responses):
            responses.append(
                {
                    "method": method,
                    "route": route,
                    "response": self._responses[(method, route)].snapshot(),
                }
            )
        return {
            "responses": responses,
            "requests": deepcopy(self._requests),
        }

    def resource_count(self) -> int:
        return len(self._responses)
