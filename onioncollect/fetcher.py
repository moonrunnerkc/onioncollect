import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urljoin

import httpx
from httpx_socks import AsyncProxyTransport
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError, parse_proxy_url

from onioncollect import lifecycle, onion, safety
from onioncollect.config import Settings, load_credential
from onioncollect.source_config import AUTH_ALLOWLIST, SourceConfig
from onioncollect.sources import SourceTable
from onioncollect.tor_pool import TorInstance

REDIRECT_CODES = {301, 302, 303, 307, 308}
TEXT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
REFUSALS = {"not_approved", "not_source_host", "excluded", "bad_path", "auth_refused", "credential_unreadable"}
CLIENT_CACHE_SIZE = 32
CONNECT_TIMEOUT = 20.0
COMPRESSED = {"gzip", "x-gzip", "deflate"}
GZIP_OR_ZLIB = 32 + zlib.MAX_WBITS


@dataclass
class FetchResult:
    source_id: str
    path: str
    host: str | None = None
    url: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    error: str | None = None
    redirect_to: str | None = None
    elapsed: float = 0.0
    truncated: bool = False


class AuthRefused(Exception):
    """A login for a source not on AUTH_ALLOWLIST. Raised before any client or request exists."""


class Sessions:
    """Section 15: the session cookie of each allowlisted source with a run under way, in memory only. One is
    shared by every fetcher of a crawl, so one login serves the run. Only Fetcher's auth step fills or reads it;
    everything else can only end sessions."""

    def __init__(self):
        self._cookies: dict[str, tuple[str, str]] = {}

    def holds(self, source_id: str) -> bool:
        return source_id in self._cookies

    def end(self, source_id: str) -> None:
        self._cookies.pop(source_id, None)

    def end_all(self) -> None:
        self._cookies.clear()


class Fetcher:
    """Fetches a path of an approved source. There is no way in here for a bare URL."""

    def __init__(self, settings: Settings, tor: TorInstance, sources: SourceTable,
                 configs: Mapping[str, SourceConfig], allowed_states: frozenset[str], sessions: Sessions | None = None):
        self.settings = settings
        self.sessions = sessions or Sessions()
        self.tor = tor
        self.sources = sources
        self.configs = configs
        self.allowed_states = allowed_states
        self.exclusions = settings.exclusions
        self.max_body_bytes = settings.max_body_bytes
        self.timeout = httpx.Timeout(settings.request_timeout, connect=CONNECT_TIMEOUT)
        self.headers = {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        self._clients: OrderedDict[str, httpx.AsyncClient] = OrderedDict()

    async def _client_for(self, host: str) -> httpx.AsyncClient:
        client = self._clients.pop(host, None)
        if client is None:
            proxy_type, proxy_host, proxy_port, _, _ = parse_proxy_url(self.tor.socks_url())
            # torrc has IsolateSOCKSAuth, so Tor builds a separate circuit per distinct SOCKS username.
            # Using the target host as the username means no two onion sites ever share a circuit.
            # The password is a placeholder: Tor ignores it, but SOCKS5 auth requires one.
            transport = AsyncProxyTransport(
                proxy_type=proxy_type, proxy_host=proxy_host, proxy_port=proxy_port,
                username=host, password="x", rdns=True, http2=False, trust_env=False,
            )
            client = httpx.AsyncClient(
                transport=transport, headers=self.headers, http2=False,
                follow_redirects=False, trust_env=False, timeout=self.timeout,
            )
        self._clients[host] = client
        while len(self._clients) > CLIENT_CACHE_SIZE:
            _, evicted = self._clients.popitem(last=False)
            await evicted.aclose()
        return client

    async def fetch(self, source_id: str, path: str) -> FetchResult:
        return await self._send(FetchResult(source_id=source_id, path=path), self._get)

    async def _send(self, result: FetchResult, request) -> FetchResult:
        started = time.monotonic()
        try:
            url = await self.resolve(result)
            if url is not None:
                await request(result, url)
        except (httpx.TimeoutException, ProxyTimeoutError):
            result.error = "timeout"
        except (httpx.ProxyError, ProxyError, ProxyConnectionError):
            result.error = "tor_unreachable"
        except AuthRefused:
            raise
        except Exception as exc:
            result.error = f"other:{type(exc).__name__}"
        result.elapsed = time.monotonic() - started
        if result.error not in REFUSALS:
            self.tor.record(result.status is not None)
        return result

    async def resolve(self, result: FetchResult) -> str | None:
        # Every check runs before a client or a circuit exists. A refusal here never reaches Tor.
        source = await self.sources.resolve(result.source_id)
        config = self.configs.get(result.source_id)
        if source is None or config is None or source.state not in self.allowed_states:
            result.error = "not_approved"
            return None
        host = source.active_host
        if host not in source.hosts or host not in config.hosts or not onion.is_v3_onion(host):
            result.error = "not_source_host"
            return None
        if safety.is_excluded(host, self.exclusions):
            result.error = "excluded"
            return None
        url = onion.normalize(f"{config.scheme}://{host}{result.path}") if result.path.startswith("/") else None
        if url is None or onion.host_of(url) != host or onion.path_of(url) != result.path:
            result.error = "bad_path"
            return None
        result.host, result.url = host, url
        return url

    async def _get(self, result: FetchResult, url: str) -> None:
        client = await self._client_for(result.host)
        try:
            async with client.stream("GET", url, headers=self._session_for(result)) as response:
                result.status = response.status_code
                result.headers = dict(response.headers)
                if response.status_code in REDIRECT_CODES:
                    # Recorded, never followed. The crawler decides where the target belongs.
                    result.redirect_to = onion.normalize(urljoin(url, response.headers.get("location", "")))
                    result.error = "redirect"
                    return
                if not response.headers.get("content-type", "").lower().startswith(TEXT_TYPES):
                    result.error = "not_text"
                    return
                result.body, result.truncated = await self._read_capped(response)
        finally:
            client.cookies.clear()

    async def _read_capped(self, response: httpx.Response) -> tuple[bytes, bool]:
        # Inflate by hand: httpx inflates each raw read whole, and 64 KiB of gzip'd zeros is 67 MB before
        # any cap could see it. max_length stops zlib at one byte past the cap, the byte that proves
        # truncation; input it has not inflated yet waits in unconsumed_tail.
        encoding = response.headers.get("content-encoding", "").strip().lower()
        inflater = zlib.decompressobj(GZIP_OR_ZLIB) if encoding in COMPRESSED else None
        body = bytearray()
        async for raw in response.aiter_raw():
            while raw:
                room = self.max_body_bytes + 1 - len(body)
                if inflater is None:
                    body += raw[:room]
                    raw = b""
                else:
                    body += inflater.decompress(raw, room)
                    raw = inflater.unconsumed_tail
                if len(body) > self.max_body_bytes:
                    return bytes(body[: self.max_body_bytes]), True
        if inflater is not None:
            body += inflater.flush()
        return bytes(body[: self.max_body_bytes]), len(body) > self.max_body_bytes

    async def close(self) -> None:
        self.sessions.end_all()
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    # Section 15's auth step: the three methods below are the only code that sends a request body, reads a
    # cookie or holds a session. Each tests AUTH_ALLOWLIST before anything else, and AuthContainmentTest
    # fails the build if any of that appears outside them.

    async def log_in(self, source_id: str) -> FetchResult:
        """One POST of the login form to the allowlisted source's active host, while it is live or degraded,
        through every check a GET passes. The redirect it answers with is recorded, never followed."""
        if source_id not in AUTH_ALLOWLIST:
            raise AuthRefused(f"{source_id} is not on the auth allowlist")
        config = self.configs.get(source_id)
        source = await self.sources.resolve(source_id)
        result = FetchResult(source_id=source_id, path=config.auth.login_path if config and config.auth else "/")
        if config is None or config.auth is None or source is None or source.state not in lifecycle.COLLECTING:
            result.error = "auth_refused"
            return result
        return await self._send(result, self._post_form)

    async def _post_form(self, result: FetchResult, url: str) -> None:
        if result.source_id not in AUTH_ALLOWLIST:
            raise AuthRefused(f"{result.source_id} is not on the auth allowlist")
        auth = self.configs[result.source_id].auth
        try:
            credential = load_credential(self.settings, result.source_id, auth.credential_ref)
        except (OSError, ValueError):
            result.error = "credential_unreadable"
            return
        form = {auth.username_field: credential.username, auth.password_field: credential.password}
        client = await self._client_for(result.host)
        try:
            # The response body is never read; only its status, its redirect and its session cookie matter.
            async with client.stream("POST", url, data=form) as response:
                result.status = response.status_code
                if response.status_code in REDIRECT_CODES:
                    result.redirect_to = onion.normalize(urljoin(url, response.headers.get("location", "")))
                    result.error = "redirect"
                cookie = "; ".join(f"{name}={value}" for name, value in response.cookies.items())
                if cookie:
                    self.sessions._cookies[result.source_id] = (result.host, cookie)
        finally:
            client.cookies.clear()

    def _session_for(self, result: FetchResult) -> dict[str, str]:
        if result.source_id not in AUTH_ALLOWLIST:
            return {}
        host, cookie = self.sessions._cookies.get(result.source_id, (None, None))
        return {"Cookie": cookie} if host == result.host else {}
