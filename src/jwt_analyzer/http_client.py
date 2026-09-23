"""Bounded HTTP fetch for documents the user explicitly names.

JWKS and OIDC discovery call this only after the operator passes a URL.
Redirects stay on HTTP(S), credentials in the URL are rejected, and the
body is capped so a remote document cannot grow without limit.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlsplit

from jwt_analyzer.exceptions import RemoteFetchError

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BYTES = 1_048_576
_USER_AGENT = "jwt-analyzer"

Fetcher = Callable[[str], bytes]


def validate_remote_url(url: str) -> None:
    """Reject URLs that are not plain HTTP(S) locations."""
    if not isinstance(url, str) or not url.strip():
        raise RemoteFetchError("Remote URL is empty", code="INVALID_URL")
    if any(char.isspace() for char in url):
        raise RemoteFetchError("Remote URL contains whitespace", code="INVALID_URL")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"https", "http"}:
        raise RemoteFetchError(
            f"Remote URL scheme is not allowed: {parts.scheme or '-'}",
            code="UNSUPPORTED_SCHEME",
        )
    if not parts.hostname:
        raise RemoteFetchError("Remote URL has no host", code="INVALID_URL")
    if parts.username or parts.password:
        raise RemoteFetchError("Remote URL must not contain credentials", code="URL_CREDENTIALS")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a few HTTP(S) redirects and refuse every other target."""

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        validate_remote_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_remote(
    url: str,
    *,
    fetcher: Optional[Fetcher] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    """Load a document from ``url``.

    ``fetcher`` replaces the network call in tests. It still has to return
    bytes, and the result is held to ``max_bytes``.
    """
    validate_remote_url(url)
    _check_limits(timeout, max_bytes)
    if fetcher is not None:
        try:
            data = fetcher(url)
        except RemoteFetchError:
            raise
        except Exception as exc:
            raise RemoteFetchError(
                f"Could not fetch {url}: {exc}",
                code="URL_ERROR",
            ) from exc
        if not isinstance(data, (bytes, bytearray)):
            raise RemoteFetchError("Fetcher must return bytes", code="INVALID_FETCHER")
        body = bytes(data)
        if len(body) > max_bytes:
            raise RemoteFetchError("Remote document exceeds the size limit", code="TOO_LARGE")
        return body
    return fetch_url(url, timeout=timeout, max_bytes=max_bytes)


def fetch_url(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    """GET ``url`` with a timeout and a response-size cap."""
    validate_remote_url(url)
    _check_limits(timeout, max_bytes)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        method="GET",
    )
    opener = urllib.request.build_opener(SafeRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            validate_remote_url(final_url)
            length = response.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > max_bytes:
                raise RemoteFetchError("Remote document exceeds the size limit", code="TOO_LARGE")
            return _read_limited(response, max_bytes)
    except RemoteFetchError:
        raise
    except urllib.error.HTTPError as exc:
        raise RemoteFetchError(f"HTTP {exc.code} while fetching {url}", code="HTTP_ERROR") from exc
    except urllib.error.URLError as exc:
        raise RemoteFetchError(f"Could not fetch {url}: {exc.reason}", code="URL_ERROR") from exc
    except TimeoutError as exc:
        raise RemoteFetchError(f"Timed out fetching {url}", code="TIMEOUT") from exc


def _check_limits(timeout: float, max_bytes: int) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise RemoteFetchError("timeout must be a positive number", code="INVALID_LIMIT")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise RemoteFetchError("max_bytes must be a positive integer", code="INVALID_LIMIT")


def _read_limited(response: object, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = response.read(8192)  # type: ignore[attr-defined]
        if not block:
            break
        total += len(block)
        if total > max_bytes:
            raise RemoteFetchError("Remote document exceeds the size limit", code="TOO_LARGE")
        chunks.append(block)
    return b"".join(chunks)
