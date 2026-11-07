import gzip
import os
import tracemalloc
import unittest
import zlib
from unittest import mock

import httpx
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError

from onioncrawl import fetcher as fetcher_module
from onioncrawl.fetcher import Fetcher
from tests.fixtures import throwaway_settings
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT, build_address

HTML = {"content-type": "text/html; charset=utf-8"}


class FakeTor:
    def __init__(self):
        self.outcomes = []

    def socks_url(self):
        return "socks5://127.0.0.1:10051"

    def record(self, ok):
        self.outcomes.append(ok)


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.consumed = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk


class FetcherTestCase(unittest.IsolatedAsyncioTestCase):
    """Runs the real Fetcher with AsyncProxyTransport replaced by a recorder around a MockTransport."""

    def setUp(self):
        self.requests: list[httpx.Request] = []
        self.served_by: list[tuple[str, str]] = []
        self.transport_kwargs: list[dict] = []
        self.routes = {}
        self.tor = FakeTor()
        self.exclusions = {TORPROJECT}
        self.fetcher = Fetcher(throwaway_settings(max_body_bytes=1000), self.tor, self.exclusions)
        patcher = mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=self.make_transport)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        await self.fetcher.close()

    def make_transport(self, **kwargs):
        self.transport_kwargs.append(kwargs)

        async def handle_as(request):
            self.served_by.append((kwargs["username"], request.url.host))
            return await self.handle(request)

        return httpx.MockTransport(handle_as)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get(str(request.url))
        if route is None:
            raise AssertionError(f"unexpected request to {request.url}")
        if isinstance(route, BaseException):
            raise route
        return route()

    def route(self, url, status=200, headers=HTML, body=b"<html></html>", stream=None):
        # Always a stream, as from the network: Response(content=...) reads itself eagerly and refuses aiter_raw.
        self.routes[url] = lambda: httpx.Response(status, headers=headers, stream=stream or TrackingStream([body]))


class RedirectTrapTest(FetcherTestCase):
    """Leak test 4 from section 15: a redirect off the onion network is never followed."""

    async def test_redirect_to_clearnet_sends_no_second_request(self):
        start = f"http://{AHMIA}/"
        self.route(start, status=302, headers={"location": "https://example.com/"})
        result = await self.fetcher.fetch(start)
        self.assertEqual(result.error, "redirect_offsite")
        self.assertEqual([str(r.url) for r in self.requests], [start])
        self.assertEqual(len(self.transport_kwargs), 1)
        self.assertIsNone(result.body)

    async def test_every_redirect_code_and_offsite_form_is_trapped(self):
        offsite = [
            "https://example.com/",
            "//example.com/next",
            "http://1.1.1.1/",
            "http://expyuzz4wqqyqhjn.onion/",
            f"ftp://{AHMIA}/file",
            f"http://{AHMIA}.example.com/",
            f"http://{AHMIA}@example.com/",
        ]
        for code in (301, 302, 303, 307, 308):
            for location in offsite:
                self.requests.clear()
                start = f"http://{AHMIA}/r{code}"
                self.route(start, status=code, headers={"location": location})
                result = await self.fetcher.fetch(start)
                self.assertEqual(result.error, "redirect_offsite", (code, location))
                self.assertEqual(len(self.requests), 1, (code, location))

    async def test_redirect_to_another_onion_uses_a_new_circuit(self):
        start, target = f"http://{AHMIA}/old", f"http://{DUCKDUCKGO}/new"
        self.route(start, status=301, headers={"location": target})
        self.route(target)
        result = await self.fetcher.fetch(start)
        self.assertIsNone(result.error)
        self.assertEqual(result.final_url, target)
        self.assertEqual([kw["username"] for kw in self.transport_kwargs], [AHMIA, DUCKDUCKGO])

    async def test_redirect_onto_an_excluded_host_is_never_followed(self):
        start = f"http://{AHMIA}/moved"
        self.route(start, status=302, headers={"location": f"http://{TORPROJECT.upper()}/landing"})
        result = await self.fetcher.fetch(start)
        self.assertEqual((result.error, result.status, result.body), ("redirect_excluded", 302, None))
        self.assertEqual(self.served_by, [(AHMIA, AHMIA)])
        self.assertEqual(len(self.transport_kwargs), 1)

    async def test_redirect_check_sees_hosts_excluded_after_the_fetcher_was_built(self):
        start = f"http://{AHMIA}/moved"
        self.route(start, status=301, headers={"location": f"http://{DUCKDUCKGO}/"})
        self.exclusions.add(DUCKDUCKGO)
        result = await self.fetcher.fetch(start)
        self.assertEqual(result.error, "redirect_excluded")
        self.assertEqual(len(self.requests), 1)

    async def test_relative_redirect_is_normalized(self):
        start = f"http://{AHMIA}/a/b"
        self.route(start, status=302, headers={"location": "../c#frag"})
        self.route(f"http://{AHMIA}/c")
        result = await self.fetcher.fetch(start)
        self.assertEqual(result.final_url, f"http://{AHMIA}/c")

    async def test_redirect_chain_stops_after_three_hops(self):
        hops = [f"http://{AHMIA}/{n}" for n in range(6)]
        for here, there in zip(hops, hops[1:]):
            self.route(here, status=302, headers={"location": there})
        result = await self.fetcher.fetch(hops[0])
        self.assertEqual(result.error, "other:TooManyRedirects")
        self.assertEqual(len(self.requests), 4)


class GateTest(FetcherTestCase):
    async def test_clearnet_url_rejected_before_any_client_exists(self):
        for url in ("http://example.com/", "https://1.1.1.1/", f"http://{AHMIA[1:]}/"):
            result = await self.fetcher.fetch(url)
            self.assertEqual(result.error, "not_onion")
        self.assertEqual(self.requests, [])
        self.assertEqual(self.transport_kwargs, [])
        self.assertEqual(self.tor.outcomes, [])

    async def test_non_text_body_never_read(self):
        url = f"http://{AHMIA}/image"
        stream = TrackingStream([b"\x89PNG" * 100])
        self.route(url, headers={"content-type": "image/png"}, stream=stream)
        result = await self.fetcher.fetch(url)
        self.assertEqual(result.error, "not_text")
        self.assertIsNone(result.body)
        self.assertEqual(stream.consumed, 0)

    async def test_missing_content_type_is_not_text(self):
        url = f"http://{AHMIA}/blob"
        self.route(url, headers={})
        self.assertEqual((await self.fetcher.fetch(url)).error, "not_text")

    async def test_allowed_content_types(self):
        for kind in ("text/html", "TEXT/HTML; charset=latin-1", "application/xhtml+xml", "text/plain"):
            url = f"http://{AHMIA}/{len(kind)}"
            self.route(url, headers={"content-type": kind}, body=b"ok")
            result = await self.fetcher.fetch(url)
            self.assertIsNone(result.error, kind)
            self.assertEqual(result.body, b"ok")

    async def test_body_capped_while_streaming(self):
        url = f"http://{AHMIA}/big"
        stream = TrackingStream([b"x" * 400] * 10)
        self.route(url, stream=stream)
        result = await self.fetcher.fetch(url)
        self.assertEqual(len(result.body), 1000)
        self.assertTrue(result.truncated)
        self.assertEqual(stream.consumed, 3)

    async def test_body_under_cap_not_truncated(self):
        url = f"http://{AHMIA}/small"
        self.route(url, body=b"y" * 1000)
        result = await self.fetcher.fetch(url)
        self.assertEqual(len(result.body), 1000)
        self.assertFalse(result.truncated)


class CompressedBodyTest(FetcherTestCase):
    """The 2 MB cap counts decompressed bytes, and a gzip bomb is never inflated past it."""

    GZIP = HTML | {"content-encoding": "gzip"}

    async def test_gzip_body_that_expands_past_the_cap_stops_at_the_cap(self):
        url = f"http://{AHMIA}/bomb"
        bomb = gzip.compress(b"<p>" + b"a" * 5_000_000)
        raw = [bomb[i:i + 1024] for i in range(0, len(bomb), 1024)]
        stream = TrackingStream(raw)
        self.route(url, headers=self.GZIP, stream=stream)
        result = await self.fetcher.fetch(url)
        self.assertIsNone(result.error)
        self.assertEqual(result.body, b"<p>" + b"a" * 997)
        self.assertTrue(result.truncated)
        self.assertEqual(stream.consumed, 1)
        self.assertGreater(len(raw), 1)

    async def test_one_raw_read_of_a_bomb_is_never_inflated_past_the_cap(self):
        url = f"http://{AHMIA}/bomb"
        bomb = gzip.compress(b"\0" * 50_000_000)
        self.route(url, headers=self.GZIP, body=bomb)
        tracemalloc.start()
        try:
            result = await self.fetcher.fetch(url)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual((len(result.body), result.truncated), (1000, True))
        self.assertLess(peak, 5_000_000)

    async def test_small_gzip_and_deflate_bodies_are_decoded_whole(self):
        page = b"<html><p>hello</p></html>"
        for encoding, compressed in (("gzip", gzip.compress(page)), ("deflate", zlib.compress(page))):
            with self.subTest(encoding=encoding):
                url = f"http://{AHMIA}/{encoding}"
                self.route(url, headers=HTML | {"content-encoding": encoding}, body=compressed)
                result = await self.fetcher.fetch(url)
                self.assertEqual((result.body, result.truncated), (page, False))

    async def test_body_exactly_at_the_cap_is_not_truncated(self):
        url = f"http://{AHMIA}/exact"
        self.route(url, headers=self.GZIP, body=gzip.compress(b"x" * 1000))
        result = await self.fetcher.fetch(url)
        self.assertEqual((len(result.body), result.truncated), (1000, False))


class AnonymityControlsTest(FetcherTestCase):
    async def test_transport_and_client_settings(self):
        url = f"http://{AHMIA}/"
        self.route(url)
        await self.fetcher.fetch(url)
        kwargs = self.transport_kwargs[0]
        self.assertEqual(kwargs["username"], AHMIA)
        self.assertTrue(kwargs["password"])
        self.assertIs(kwargs["rdns"], True)
        self.assertIs(kwargs["http2"], False)
        self.assertIs(kwargs["trust_env"], False)
        self.assertEqual((kwargs["proxy_host"], kwargs["proxy_port"]), ("127.0.0.1", 10051))
        client = self.fetcher._clients[AHMIA]
        self.assertFalse(client.follow_redirects)
        self.assertFalse(client.trust_env)
        self.assertEqual(client.timeout, httpx.Timeout(45.0, connect=20.0))

    async def test_socks_username_is_the_target_host_on_every_request(self):
        hosts = [AHMIA, DUCKDUCKGO, TORPROJECT]
        for host in hosts:
            self.route(f"http://{host}/")
            self.route(f"http://{host}/page")
            await self.fetcher.fetch(f"http://{host}/")
            await self.fetcher.fetch(f"http://{host}/page")
        self.assertEqual(len(self.served_by), 6)
        for username, host in self.served_by:
            self.assertEqual(username, host)

    async def test_exact_tor_browser_headers(self):
        url = f"http://{AHMIA}/"
        self.route(url)
        await self.fetcher.fetch(url)
        sent = {k.lower(): v for k, v in self.requests[0].headers.items()}
        self.assertEqual(set(sent), {
            "host", "user-agent", "accept", "accept-language", "accept-encoding", "connection",
            "upgrade-insecure-requests",
        })
        self.assertIn("Firefox/153.0", sent["user-agent"])
        self.assertNotIn("python", sent["user-agent"].lower())

    async def test_no_referer_or_cookie_carried_across_requests(self):
        first, second = f"http://{AHMIA}/login", f"http://{AHMIA}/next"
        self.route(first, status=302, headers={"location": "/next", "set-cookie": "sid=abc; Path=/"})
        self.route(second, headers={**HTML, "set-cookie": "track=1; Path=/"})
        await self.fetcher.fetch(first)
        await self.fetcher.fetch(second)
        for request in self.requests:
            self.assertNotIn("referer", request.headers)
            self.assertNotIn("cookie", request.headers)
        self.assertEqual(len(self.fetcher._clients[AHMIA].cookies), 0)

    async def test_cookies_cleared_even_when_body_read_fails(self):
        url = f"http://{AHMIA}/broken"

        class BrokenStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"partial"
                raise httpx.ReadError("connection reset")

        self.route(url, headers={**HTML, "set-cookie": "sid=abc; Path=/"}, stream=BrokenStream())
        result = await self.fetcher.fetch(url)
        self.assertEqual(result.error, "other:ReadError")
        self.assertEqual(len(self.fetcher._clients[AHMIA].cookies), 0)

    async def test_proxy_environment_is_ignored(self):
        url = f"http://{AHMIA}/"
        self.route(url)
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://10.9.9.9:3128", "ALL_PROXY": "socks5://10.9.9.9:1080"}):
            result = await self.fetcher.fetch(url)
        self.assertIsNone(result.error)
        self.assertEqual(len(self.requests), 1)

    async def test_client_cache_evicts_and_closes_oldest(self):
        hosts = [build_address(bytes([n]) * 32, 3) for n in range(fetcher_module.CLIENT_CACHE_SIZE + 1)]
        for host in hosts:
            self.route(f"http://{host}/")
        first_client = None
        for host in hosts:
            await self.fetcher.fetch(f"http://{host}/")
            first_client = first_client or self.fetcher._clients[hosts[0]]
        self.assertEqual(len(self.fetcher._clients), fetcher_module.CLIENT_CACHE_SIZE)
        self.assertNotIn(hosts[0], self.fetcher._clients)
        self.assertTrue(first_client.is_closed)


class ErrorMappingTest(FetcherTestCase):
    async def test_errors_map_to_crawler_strings(self):
        url = f"http://{AHMIA}/"
        cases = [
            (httpx.ConnectTimeout("slow"), "timeout"),
            (httpx.ReadTimeout("slow"), "timeout"),
            (ProxyTimeoutError("socks slow"), "timeout"),
            (ProxyError("Host unreachable", 0x04), "tor_unreachable"),
            (ProxyError("Onion service descriptor can not be found", 0xF0), "tor_unreachable"),
            (ProxyConnectionError("SOCKS port closed"), "tor_unreachable"),
            (httpx.ProxyError("refused"), "tor_unreachable"),
            (httpx.RemoteProtocolError("garbage"), "other:RemoteProtocolError"),
        ]
        for exc, expected in cases:
            self.routes[url] = exc
            result = await self.fetcher.fetch(url)
            self.assertEqual(result.error, expected, type(exc).__name__)
            self.assertIsNone(result.status)
        self.assertEqual(self.tor.outcomes, [False] * len(cases))

    async def test_any_status_counts_as_a_live_host(self):
        url = f"http://{AHMIA}/missing"
        self.route(url, status=404, body=b"not here")
        result = await self.fetcher.fetch(url)
        self.assertEqual(result.status, 404)
        self.assertEqual(self.tor.outcomes, [True])
        self.assertGreater(result.elapsed, 0)


if __name__ == "__main__":
    unittest.main()
