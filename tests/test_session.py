"""Section 15 end to end: a crawler run of the self-hosted onion through the real Fetcher, its network replaced by
a stand-in for testonion/app.py. Section 17 test 5's behaviour half; AuthContainmentTest is the code half."""
import json
import logging
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

import httpx

from onioncollect import fetcher as fetcher_module
from onioncollect import health, lifecycle, pages
from onioncollect.crawler import Crawler
from onioncollect.fetcher import Fetcher
from onioncollect.redact import Redacted
from tests.fixtures import (OFF_SOURCE, TESTONION, TESTONION_CONFIG, TESTONION_PASSWORD, TESTONION_USER, make_live,
                            throwaway_settings, write_credential)
from tests.test_fetcher import HTML, FakeTor, TrackingStream

TOKEN = "s3ss10n"
# The member pages echo the credential, on a line of its own, as a careless app might: the gate's job.
ECHOED = f"\n{TESTONION_USER}:{TESTONION_PASSWORD}\n"


def page(*notes: tuple[str, str], signed_in: bool = False) -> bytes:
    articles = "".join(f"<article class='note'><h2><a href='{href}'>{title}</a></h2></article>" for href, title in notes)
    marker = "<p id='signed-in'>Signed in</p>" if signed_in else ""
    return f"<html><body>{marker}{articles}</body></html>".encode()


class TestOnionStandIn:
    """How testonion/app.py answers, as a MockTransport handler."""

    def __init__(self, landing: str = "/members/"):
        self.landing = landing
        self.issued = TOKEN
        self.posts: list[dict] = []
        self.member_gets: list[str | None] = []
        self.public = page(("/notices/1", "Maintenance window on Sunday"))
        self.members = page(("/members/notes/1", ECHOED), ("/members/notes/2", "Rotate the relay keys"), signed_in=True)

    def answer(self, status: int, body: bytes = b"", **headers) -> httpx.Response:
        return httpx.Response(status, headers=HTML | headers, stream=TrackingStream([body]))

    async def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            form = parse_qs(request.content.decode())
            self.posts.append(form)
            if form == {"username": [TESTONION_USER], "password": [TESTONION_PASSWORD]}:
                return self.answer(303, location=self.landing, **{"set-cookie": f"sid={self.issued}; Path=/; HttpOnly"})
            return self.answer(200, b"<form method='post'><input name='username'></form>")
        if path.startswith("/members/"):
            self.member_gets.append(request.headers.get("cookie"))
            if request.headers.get("cookie") != f"sid={TOKEN}":
                return self.answer(303, location="/login")
            return self.answer(200, self.members if path == "/members/" else
                               f"<html><body><div class='body'>{ECHOED}</div></body></html>".encode())
        return self.answer(200, self.public if path == "/" else b"<html><body><div class='body'>notice</div></body></html>")


class SessionRunTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        for name in ("configs", "data"):
            (root / name).mkdir()
        (root / "configs" / "testonion.toml").write_text(TESTONION_CONFIG)
        self.settings = throwaway_settings(data_dir=root / "data", configs_dir=root / "configs",
                                           credentials_dir=root / "etc", tor_instances=((10051, 11051),),
                                           max_retries=1, jitter_seconds=(0.0, 0.0))
        write_credential(self.settings)
        self.crawler = Crawler(self.settings)
        await self.crawler.open()
        await make_live(self.crawler.sources, "testonion", TESTONION, "self-hosted")
        self.app = TestOnionStandIn()
        patcher = mock.patch.object(fetcher_module, "AsyncProxyTransport",
                                    side_effect=lambda **kwargs: httpx.MockTransport(self.app.handle))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tor = FakeTor()
        self.fetcher = Fetcher(self.settings, self.tor, self.crawler.sources, self.crawler.configs,
                               lifecycle.COLLECTING, sessions=self.crawler.logins.sessions)

    async def asyncTearDown(self):
        await self.fetcher.close()
        await self.crawler.close()
        self.tmp.cleanup()

    async def crawl(self) -> list[str]:
        """One scheduler pass, then pages until nothing is claimable; every log line of it, from every logger."""
        with self.assertLogs(level=logging.DEBUG) as logs:
            await self.crawler.start_due_runs()
            while tasks := await self.crawler.frontier.claim(1):
                await self.crawler.handle(tasks[0], self.fetcher)
        return logs.output

    def data_on_disk(self) -> bytes:
        return b"".join(path.read_bytes() for path in self.settings.data_dir.rglob("*") if path.is_file())

    def assert_credential_absent(self, logs: list[str]) -> None:
        on_disk, logged = self.data_on_disk(), "\n".join(logs)
        for value in (TESTONION_USER, TESTONION_PASSWORD):
            self.assertNotIn(value.encode(), on_disk, value)
            self.assertNotIn(value, logged, value)

    async def errors(self) -> list[str]:
        return [row["error"] for row in await self.crawler.collect.rows("SELECT error FROM page_metrics ORDER BY rowid")]


class SessionRunTest(SessionRunTestCase):
    async def test_one_login_serves_the_whole_run_and_ends_with_it(self):
        await self.crawl()
        self.assertEqual(len(self.app.posts), 1)
        self.assertEqual(self.app.member_gets, [f"sid={TOKEN}"] * 4, "landing check, listing and both notes")
        self.assertEqual(await self.errors(), [None] * 5)
        self.assertFalse(self.crawler.logins.sessions.holds("testonion"))
        self.assertEqual(self.crawler.logins.outcomes, {})
        titles = {json.loads(row["fields"])["title"] for row in await self.crawler.records.db.rows("SELECT fields FROM records")}
        self.assertIn("Rotate the relay keys", titles)

    async def test_the_credential_is_nowhere_under_the_data_dir_or_in_any_log(self):
        logs = await self.crawl()
        self.assert_credential_absent(logs)
        self.assertIn("INFO:onioncollect.session:testonion session started", logs)
        (kind, priority), = {(item["kind"], item["priority"]) for item in await self.crawler.health.queue()}
        self.assertEqual((kind, priority), (health.REDACTION, health.REDACTION_PRIORITY))
        stored = (await self.crawler.records.db.rows("SELECT fields FROM records"))
        self.assertTrue(any("[user_password]" in row["fields"] for row in stored), stored)

    async def test_with_the_redaction_gate_broken_the_storage_refusal_keeps_it_off_disk(self):
        def untouched(text, salt):
            return Redacted(text, {}, (), 0)

        broken = types.SimpleNamespace(redact=untouched,
                                       redact_fields=lambda fields, salt: (dict(fields), Redacted("", {}, (), 0)))
        with mock.patch.object(pages, "redact", broken):
            logs = await self.crawl()
        self.assert_credential_absent(logs)
        self.assertIn("WARNING:onioncollect.crawler:testonion write refused: a secret survived redaction", logs)
        details = {item["detail"] for item in await self.crawler.health.queue()}
        self.assertIn("write refused: a secret survived", details)

    async def test_wrong_credentials_fail_the_run_after_one_post(self):
        write_credential(self.settings, f"username={TESTONION_USER}\npassword=not-the-password\n")
        logs = await self.crawl()
        self.assertEqual(len(self.app.posts), 1)
        self.assertEqual(self.app.member_gets, [])
        self.assertEqual(await self.errors(), ["auth_rejected", "auth_rejected"])
        self.assertIn("WARNING:onioncollect.session:testonion session not started: auth_rejected", logs)
        self.assertFalse(self.crawler.logins.sessions.holds("testonion"))
        self.assertEqual(self.crawler.logins.outcomes, {}, "the next run tries again")

    async def test_a_landing_that_bounces_back_to_the_login_is_not_a_session(self):
        self.app.issued = "already-expired"
        await self.crawl()
        self.assertEqual(self.app.member_gets, ["sid=already-expired"])
        self.assertEqual(await self.errors(), ["auth_rejected", "auth_rejected"])

    async def test_a_login_redirect_off_the_source_is_recorded_and_not_followed(self):
        self.app.landing = f"http://{OFF_SOURCE}/members/"
        await self.crawl()
        self.assertEqual(self.app.member_gets, [])
        self.assertEqual([row["host"] for row in await self.crawler.sources.hosts(lifecycle.CANDIDATE)], [OFF_SOURCE])
        self.assertEqual(await self.errors(), ["auth_rejected", "auth_rejected"])

    async def test_a_landing_page_tripping_the_safety_check_disables_the_source(self):
        self.app.members = page(("/members/notes/1", "forbiddenterm"), signed_in=True)
        await self.crawl()
        source = await self.crawler.sources.get("testonion")
        self.assertEqual((source["state"], source["reason"]), (lifecycle.DISABLED, "safety: child_exploitation"))
        self.assertEqual(await self.crawler.records.counts(), {"records": 0, "snapshots": 0})

    async def test_a_source_without_form_session_never_posts(self):
        (self.settings.configs_dir / "testonion.toml").write_text(
            TESTONION_CONFIG.split("[auth]")[0] + '[auth]\ntype = "none"\n')
        await self.crawl()
        self.assertEqual(self.app.posts, [])
        self.assertEqual(self.app.member_gets, [None])

    async def test_the_session_is_gone_after_a_worker_crash(self):
        self.crawler.tor_pool.assign = lambda worker_id: self.tor
        await self.crawler.start_due_runs()
        with mock.patch.object(self.crawler, "store", side_effect=RuntimeError("disk gone")), \
                self.assertLogs("onioncollect.crawler", logging.ERROR):
            await self.crawler.worker(0)
        self.assertEqual(len(self.app.posts), 1)
        self.assertTrue(self.crawler.stopping.is_set())
        self.assertFalse(self.crawler.logins.sessions.holds("testonion"))
        self.assertEqual(self.crawler.logins.sessions._cookies, {})


if __name__ == "__main__":
    unittest.main()
