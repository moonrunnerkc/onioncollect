import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx
from httpx_socks import AsyncProxyTransport
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError, parse_proxy_url

from onioncrawl import onion, safety
from onioncrawl.config import Settings
from onioncrawl.tor_pool import TorInstance

REDIRECT_CODES = {301, 302, 303, 307, 308}
TEXT_TYPES = ("text/html", "application/xhtml", "text/plain")
MAX_HOPS = 3
CLIENT_CACHE_SIZE = 32
CONNECT_TIMEOUT = 20.0
COMPRESSED = {"gzip", "x-gzip", "deflate"}
GZIP_OR_ZLIB = 32 + zlib.MAX_WBITS


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    error: str | None = None
    elapsed: float = 0.0
    truncated: bool = False


class Fetcher:
    def __init__(self, settings: Settings, tor: TorInstance, exclusions: set[str]):
        self.tor = tor
        self.exclusions = exclusions
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

    async def fetch(self, url: str) -> FetchResult:
        started = time.monotonic()
        result = FetchResult(url=url, final_url=url)
        try:
            await self._follow(result)
        except (httpx.TimeoutException, ProxyTimeoutError):
            result.error = "timeout"
        except (httpx.ProxyError, ProxyError, ProxyConnectionError):
            result.error = "tor_unreachable"
        except Exception as exc:
            result.error = f"other:{type(exc).__name__}"
        result.elapsed = time.monotonic() - started
        if result.error != "not_onion":
            self.tor.record(result.status is not None)
        return result

    async def _follow(self, result: FetchResult) -> None:
        current = result.url
        for _ in range(MAX_HOPS + 1):
            host = onion.host_of(current)
            if not onion.is_v3_onion(host):
                result.error = "not_onion"
                return
            client = await self._client_for(host)
            try:
                async with client.stream("GET", current) as response:
                    result.final_url = current
                    result.status = response.status_code
                    result.headers = dict(response.headers)
                    if response.status_code in REDIRECT_CODES:
                        target = onion.normalize(urljoin(current, response.headers.get("location", "")))
                        if target is None:
                            result.error = "redirect_offsite"
                            return
                        if safety.is_excluded(onion.host_of(target), self.exclusions):
                            result.error = "redirect_excluded"
                            return
                        current = target
                        continue
                    if not response.headers.get("content-type", "").lower().startswith(TEXT_TYPES):
                        result.error = "not_text"
                        return
                    result.body, result.truncated = await self._read_capped(response)
                    return
            finally:
                client.cookies.clear()
        result.error = "other:TooManyRedirects"

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
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
