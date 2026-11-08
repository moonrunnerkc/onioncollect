import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

from onioncollect import fetcher as fetcher_module
from onioncollect import lifecycle, source_config
from onioncollect.db import open_collect
from onioncollect.fetcher import Fetcher
from onioncollect.sources import SourceTable
from tests.fixtures import (CANDIDATE, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, make_live, news_config,
                            throwaway_settings)
from tests.test_onion import AHMIA

HTML = {"content-type": "text/html; charset=utf-8"}


def config_for(source_id: str, host: str):
    return source_config.parse(NEWS_CONFIG.replace('"news"', f'"{source_id}"').replace(NEWS, host), source_id)


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
    """The real Fetcher on a real source table, with AsyncProxyTransport replaced by a recorder around a MockTransport."""

    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = await open_collect(Path(self.dir.name) / "collect.db")
        self.table = SourceTable(self.db)
        await make_live(self.table)
        self.configs = {"news": news_config()}
        self.requests: list[httpx.Request] = []
        self.served_by: list[tuple[str, str]] = []
        self.transport_kwargs: list[dict] = []
        self.routes = {}
        self.tor = FakeTor()
        self.fetcher = self.build()
        patcher = mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=self.make_transport)
        patcher.start()
        self.addCleanup(patcher.stop)

    def build(self, allowed=lifecycle.COLLECTING, **settings) -> Fetcher:
        return Fetcher(throwaway_settings(max_body_bytes=1000, **settings), self.tor, self.table, self.configs, allowed)

    async def asyncTearDown(self):
        await self.fetcher.close()
        await self.db.close()
        self.dir.cleanup()

    async def add_live(self, source_id: str, host: str) -> None:
        await make_live(self.table, source_id, host)
        self.configs[source_id] = config_for(source_id, host)

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

    def route(self, path, status=200, headers=HTML, body=b"<html></html>", stream=None, host=NEWS):
        # Always a stream, as from the network: Response(content=...) reads itself eagerly and refuses aiter_raw.
        self.routes[f"http://{host}{path}"] = lambda: httpx.Response(
            status, headers=headers, stream=stream or TrackingStream([body])
        )

    def assert_no_client(self):
        self.assertEqual((self.requests, self.transport_kwargs, self.tor.outcomes), ([], [], []))


class RedirectTrapTest(FetcherTestCase):
    """Leak test 4: a redirect is recorded and never followed, whatever it points at."""

    async def test_redirect_to_clearnet_sends_no_second_request(self):
        self.route("/", status=302, headers={"location": "https://example.com/"})
        result = await self.fetcher.fetch("news", "/")
        self.assertEqual((result.error, result.redirect_to, result.status, result.body), ("redirect", None, 302, None))
        self.assertEqual([str(r.url) for r in self.requests], [f"http://{NEWS}/"])
        self.assertEqual(len(self.transport_kwargs), 1)

    async def test_every_redirect_code_and_offsite_form_is_trapped(self):
        offsite = [
            "https://example.com/", "//example.com/next", "http://1.1.1.1/", "http://expyuzz4wqqyqhjn.onion/",
            f"ftp://{AHMIA}/file", f"http://{AHMIA}.example.com/", f"http://{AHMIA}@example.com/",
        ]
        for code in (301, 302, 303, 307, 308):
            for location in offsite:
                with self.subTest(code=code, location=location):
                    self.requests.clear()
                    self.route(f"/r{code}", status=code, headers={"location": location})
                    result = await self.fetcher.fetch("news", f"/r{code}")
                    self.assertEqual((result.error, result.redirect_to), ("redirect", None))
                    self.assertEqual(len(self.requests), 1)

    async def test_redirect_to_another_onion_is_recorded_not_followed(self):
        self.route("/moved", status=301, headers={"location": f"http://{OFF_SOURCE.upper()}/market"})
        result = await self.fetcher.fetch("news", "/moved")
        self.assertEqual((result.error, result.redirect_to), ("redirect", f"http://{OFF_SOURCE}/market"))
        self.assertEqual(self.served_by, [(NEWS, NEWS)])
        self.assertEqual(len(self.transport_kwargs), 1)

    async def test_redirect_on_the_same_host_is_normalized_and_not_followed(self):
        self.route("/a/b", status=302, headers={"location": "../c#frag"})
        self.route("/c")
        result = await self.fetcher.fetch("news", "/a/b")
        self.assertEqual((result.error, result.redirect_to), ("redirect", f"http://{NEWS}/c"))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.tor.outcomes, [True])


class RefusalTest(FetcherTestCase):
    """Every refusal happens before a client, a circuit or a Tor outcome exists."""

    async def assert_refused(self, source_id: str, error: str, path: str = "/", fetcher: Fetcher | None = None):
        result = await (fetcher or self.fetcher).fetch(source_id, path)
        self.assertEqual((result.error, result.status, result.body, result.url), (error, None, None, None))
        self.assert_no_client()

    async def test_unknown_source_and_a_candidate_host_as_id(self):
        await self.table.add_candidates({CANDIDATE}, "news")
        for source_id in ("ghost", CANDIDATE, NEWS):
            with self.subTest(source_id=source_id):
                await self.assert_refused(source_id, "not_approved")

    async def test_approved_source_only_under_test(self):
        await self.table.approve(NEWS_MIRROR, "pending", "journalism-publishing", "n", "t", frozenset())
        self.configs["pending"] = config_for("pending", NEWS_MIRROR)
        await self.assert_refused("pending", "not_approved")
        self.route("/", host=NEWS_MIRROR)
        under_test = self.build(allowed=lifecycle.UNDER_TEST)
        try:
            self.assertIsNone((await under_test.fetch("pending", "/")).error)
            self.assertEqual((await under_test.fetch("news", "/")).error, "not_approved")
        finally:
            await under_test.close()

    async def test_disabled_and_degraded(self):
        await self.table.change_state("news", lifecycle.DEGRADED)
        self.route("/")
        self.assertIsNone((await self.fetcher.fetch("news", "/")).error)
        self.requests.clear()
        self.transport_kwargs.clear()
        self.tor.outcomes.clear()
        await self.table.change_state("news", lifecycle.DISABLED, "gone")
        await self.assert_refused("news", "not_approved")

    async def test_live_source_without_a_loaded_config(self):
        del self.configs["news"]
        await self.assert_refused("news", "not_approved")

    async def test_active_host_must_be_in_the_config_and_the_member_set(self):
        self.configs["news"] = config_for("news", NEWS_MIRROR)
        await self.assert_refused("news", "not_source_host")
        self.configs["news"] = news_config()
        await self.db.conn.execute("UPDATE sources SET active_host = ?", (OFF_SOURCE,))
        await self.db.conn.commit()
        self.configs["news"] = config_for("news", OFF_SOURCE)
        await self.assert_refused("news", "not_source_host")

    async def test_excluded_host(self):
        await self.assert_refused("news", "excluded", fetcher=self.build(exclusions=frozenset({NEWS})))

    async def test_bad_paths(self):
        for path in ("http://x", f"http://{NEWS}/", "relative", "", "?q=1", ":8080/x", "/#frag"):
            with self.subTest(path=path):
                await self.assert_refused("news", "bad_path", path)

    async def test_odd_paths_never_leave_the_source_host(self):
        for path in ("//evil.com/", "/@evil.com", f"//{OFF_SOURCE}/x"):
            self.route(path)
        for path in ("//evil.com/", "/@evil.com", f"//{OFF_SOURCE}/x"):
            await self.fetcher.fetch("news", path)
        self.assertEqual({host for _, host in self.served_by}, {NEWS})


class BodyTest(FetcherTestCase):
    async def test_non_text_body_never_read(self):
        stream = TrackingStream([b"\x89PNG" * 100])
        self.route("/image", headers={"content-type": "image/png"}, stream=stream)
        result = await self.fetcher.fetch("news", "/image")
        self.assertEqual((result.error, result.body, stream.consumed), ("not_text", None, 0))

    async def test_missing_content_type_is_not_text(self):
        self.route("/blob", headers={})
        self.assertEqual((await self.fetcher.fetch("news", "/blob")).error, "not_text")

    async def test_allowed_content_types(self):
        for kind in ("text/html", "TEXT/HTML; charset=latin-1", "application/xhtml+xml", "text/plain"):
            self.route(f"/{len(kind)}", headers={"content-type": kind}, body=b"ok")
            result = await self.fetcher.fetch("news", f"/{len(kind)}")
            self.assertEqual((result.error, result.body), (None, b"ok"), kind)

    async def test_xml_and_bare_xhtml_prefixes_are_not_text(self):
        for kind in ("application/xml", "application/xhtml", "application/octet-stream"):
            self.route("/x", headers={"content-type": kind})
            self.assertEqual((await self.fetcher.fetch("news", "/x")).error, "not_text", kind)

    async def test_body_capped_while_streaming(self):
        stream = TrackingStream([b"x" * 400] * 10)
        self.route("/big", stream=stream)
        result = await self.fetcher.fetch("news", "/big")
        self.assertEqual((len(result.body), result.truncated, stream.consumed), (1000, True, 3))

    async def test_body_under_cap_not_truncated(self):
        self.route("/small", body=b"y" * 1000)
        result = await self.fetcher.fetch("news", "/small")
        self.assertEqual((len(result.body), result.truncated), (1000, False))

    async def test_result_names_the_source_host_and_url(self):
        self.route("/a?b=1")
        result = await self.fetcher.fetch("news", "/a?b=1")
        self.assertEqual((result.source_id, result.path, result.host, result.url),
                         ("news", "/a?b=1", NEWS, f"http://{NEWS}/a?b=1"))


if __name__ == "__main__":
    unittest.main()
