import gzip
import os
import tracemalloc
import unittest
import zlib
from unittest import mock

import httpx
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError

from onioncollect import fetcher as fetcher_module
from tests.fixtures import NEWS
from tests.test_fetcher import HTML, FetcherTestCase, TrackingStream
from tests.test_onion import AHMIA, DUCKDUCKGO, build_address


class CompressedBodyTest(FetcherTestCase):
    """The 2 MB cap counts decompressed bytes, and a gzip bomb is never inflated past it."""

    GZIP = HTML | {"content-encoding": "gzip"}

    async def test_gzip_body_that_expands_past_the_cap_stops_at_the_cap(self):
        bomb = gzip.compress(b"<p>" + b"a" * 5_000_000)
        raw = [bomb[i:i + 1024] for i in range(0, len(bomb), 1024)]
        stream = TrackingStream(raw)
        self.route("/bomb", headers=self.GZIP, stream=stream)
        result = await self.fetcher.fetch("news", "/bomb")
        self.assertIsNone(result.error)
        self.assertEqual(result.body, b"<p>" + b"a" * 997)
        self.assertTrue(result.truncated)
        self.assertEqual(stream.consumed, 1)
        self.assertGreater(len(raw), 1)

    async def test_one_raw_read_of_a_bomb_is_never_inflated_past_the_cap(self):
        self.route("/bomb", headers=self.GZIP, body=gzip.compress(b"\0" * 50_000_000))
        tracemalloc.start()
        try:
            result = await self.fetcher.fetch("news", "/bomb")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual((len(result.body), result.truncated), (1000, True))
        self.assertLess(peak, 5_000_000)

    async def test_small_gzip_and_deflate_bodies_are_decoded_whole(self):
        page = b"<html><p>hello</p></html>"
        for encoding, compressed in (("gzip", gzip.compress(page)), ("deflate", zlib.compress(page))):
            with self.subTest(encoding=encoding):
                self.route(f"/{encoding}", headers=HTML | {"content-encoding": encoding}, body=compressed)
                result = await self.fetcher.fetch("news", f"/{encoding}")
                self.assertEqual((result.body, result.truncated), (page, False))

    async def test_body_exactly_at_the_cap_is_not_truncated(self):
        self.route("/exact", headers=self.GZIP, body=gzip.compress(b"x" * 1000))
        result = await self.fetcher.fetch("news", "/exact")
        self.assertEqual((len(result.body), result.truncated), (1000, False))


class AnonymityControlsTest(FetcherTestCase):
    async def test_transport_and_client_settings(self):
        self.route("/")
        await self.fetcher.fetch("news", "/")
        kwargs = self.transport_kwargs[0]
        self.assertEqual(kwargs["username"], NEWS)
        self.assertTrue(kwargs["password"])
        self.assertIs(kwargs["rdns"], True)
        self.assertIs(kwargs["http2"], False)
        self.assertIs(kwargs["trust_env"], False)
        self.assertEqual((kwargs["proxy_host"], kwargs["proxy_port"]), ("127.0.0.1", 10051))
        client = self.fetcher._clients[NEWS]
        self.assertFalse(client.follow_redirects)
        self.assertFalse(client.trust_env)
        self.assertEqual(client.timeout, httpx.Timeout(45.0, connect=20.0))

    async def test_socks_username_is_the_target_host_on_every_request(self):
        await self.add_live("ahmia", AHMIA)
        await self.add_live("ddg", DUCKDUCKGO)
        for source_id, host in (("news", NEWS), ("ahmia", AHMIA), ("ddg", DUCKDUCKGO)):
            for path in ("/", "/page"):
                self.route(path, host=host)
                await self.fetcher.fetch(source_id, path)
        self.assertEqual(len(self.served_by), 6)
        self.assertEqual({host for _, host in self.served_by}, {NEWS, AHMIA, DUCKDUCKGO})
        for username, host in self.served_by:
            self.assertEqual(username, host)

    async def test_exact_tor_browser_headers(self):
        self.route("/")
        await self.fetcher.fetch("news", "/")
        sent = {k.lower(): v for k, v in self.requests[0].headers.items()}
        self.assertEqual(set(sent), {
            "host", "user-agent", "accept", "accept-language", "accept-encoding", "connection",
            "upgrade-insecure-requests",
        })
        self.assertIn("Firefox/153.0", sent["user-agent"])
        self.assertNotIn("python", sent["user-agent"].lower())

    async def test_only_get_is_ever_sent(self):
        self.route("/")
        self.route("/r", status=303, headers={"location": "/"})
        await self.fetcher.fetch("news", "/")
        await self.fetcher.fetch("news", "/r")
        self.assertEqual({request.method for request in self.requests}, {"GET"})
        self.assertTrue(all(request.content == b"" for request in self.requests))

    async def test_no_referer_or_cookie_carried_across_requests(self):
        self.route("/login", status=302, headers={"location": "/next", "set-cookie": "sid=abc; Path=/"})
        self.route("/next", headers={**HTML, "set-cookie": "track=1; Path=/"})
        await self.fetcher.fetch("news", "/login")
        await self.fetcher.fetch("news", "/next")
        for request in self.requests:
            self.assertNotIn("referer", request.headers)
            self.assertNotIn("cookie", request.headers)
        self.assertEqual(len(self.fetcher._clients[NEWS].cookies), 0)

    async def test_cookies_cleared_even_when_body_read_fails(self):
        class BrokenStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"partial"
                raise httpx.ReadError("connection reset")

        self.route("/broken", headers={**HTML, "set-cookie": "sid=abc; Path=/"}, stream=BrokenStream())
        result = await self.fetcher.fetch("news", "/broken")
        self.assertEqual(result.error, "other:ReadError")
        self.assertEqual(len(self.fetcher._clients[NEWS].cookies), 0)

    async def test_proxy_environment_is_ignored(self):
        self.route("/")
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://10.9.9.9:3128", "ALL_PROXY": "socks5://10.9.9.9:1080"}):
            result = await self.fetcher.fetch("news", "/")
        self.assertIsNone(result.error)
        self.assertEqual(len(self.requests), 1)

    async def test_client_cache_evicts_and_closes_oldest(self):
        hosts = [build_address(bytes([n]) * 32, 3) for n in range(fetcher_module.CLIENT_CACHE_SIZE + 1)]
        for n, host in enumerate(hosts):
            await self.add_live(f"source-{n}", host)
            self.route("/", host=host)
        first_client = None
        for n, host in enumerate(hosts):
            await self.fetcher.fetch(f"source-{n}", "/")
            first_client = first_client or self.fetcher._clients[hosts[0]]
        self.assertEqual(len(self.fetcher._clients), fetcher_module.CLIENT_CACHE_SIZE)
        self.assertNotIn(hosts[0], self.fetcher._clients)
        self.assertTrue(first_client.is_closed)


class ErrorMappingTest(FetcherTestCase):
    async def test_errors_map_to_crawler_strings(self):
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
            self.routes[f"http://{NEWS}/"] = exc
            result = await self.fetcher.fetch("news", "/")
            self.assertEqual(result.error, expected, type(exc).__name__)
            self.assertIsNone(result.status)
        self.assertEqual(self.tor.outcomes, [False] * len(cases))

    async def test_any_status_counts_as_a_live_host(self):
        self.route("/missing", status=404, body=b"not here")
        result = await self.fetcher.fetch("news", "/missing")
        self.assertEqual(result.status, 404)
        self.assertEqual(self.tor.outcomes, [True])
        self.assertGreater(result.elapsed, 0)


if __name__ == "__main__":
    unittest.main()
