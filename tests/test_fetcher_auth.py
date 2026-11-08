import dataclasses
import logging
import tempfile
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

import httpx

from onioncollect import lifecycle
from onioncollect.config import config_path
from onioncollect.fetcher import AuthRefused, Fetcher, FetchResult
from tests.fixtures import (CANDIDATE, NEWS, TESTONION, TESTONION_CONFIG, TESTONION_PASSWORD, TESTONION_USER,
                            make_live, news_config, testonion_config, throwaway_settings, write_credential)
from tests.test_fetcher import HTML, FetcherTestCase, TrackingStream

SIGNED_IN = HTML | {"set-cookie": "sid=s3ss10n; Path=/; HttpOnly"}


class AuthStepTestCase(FetcherTestCase):
    async def asyncSetUp(self):
        self.secrets = tempfile.TemporaryDirectory()
        root = Path(self.secrets.name)
        self.settings = throwaway_settings(max_body_bytes=1000, credentials_dir=root / "etc",
                                           configs_dir=root / "configs")
        self.settings.configs_dir.mkdir()
        config_path(self.settings.configs_dir, "testonion").write_text(TESTONION_CONFIG)
        write_credential(self.settings)
        await super().asyncSetUp()
        await make_live(self.table, "testonion", TESTONION, "self-hosted")
        self.configs["testonion"] = testonion_config()

    async def asyncTearDown(self):
        await super().asyncTearDown()
        self.secrets.cleanup()

    def build(self, allowed=lifecycle.COLLECTING, **settings) -> Fetcher:
        return Fetcher(dataclasses.replace(self.settings, **settings) if settings else self.settings, self.tor,
                       self.table, self.configs, allowed)

    def login_answers(self, status=303, headers=SIGNED_IN | {"location": "/members/"}):
        self.routes[f"http://{TESTONION}/login"] = lambda: httpx.Response(status, headers=headers,
                                                                          stream=TrackingStream([b"never read"]))

    def jars_empty(self) -> bool:
        return all(not client.cookies for client in self.fetcher._clients.values())


class LogInTest(AuthStepTestCase):
    async def test_one_post_of_the_form_to_the_active_host_redirect_recorded_jar_cleared(self):
        self.login_answers()
        result = await self.fetcher.log_in("testonion")
        (request,) = self.requests
        self.assertEqual((request.method, str(request.url)), ("POST", f"http://{TESTONION}/login"))
        self.assertEqual(parse_qs(request.content.decode()), {"username": [TESTONION_USER],
                                                              "password": [TESTONION_PASSWORD]})
        self.assertEqual(self.served_by, [(TESTONION, TESTONION)], "the SOCKS username is the host, as for a GET")
        self.assertEqual((result.status, result.error, result.redirect_to),
                         (303, "redirect", f"http://{TESTONION}/members/"))
        self.assertIsNone(result.body)
        self.assertTrue(self.fetcher.sessions.holds("testonion"))
        self.assertTrue(self.jars_empty(), "the session lives in Sessions, never in a client's jar")

    async def test_later_gets_carry_the_session_to_that_host_and_no_other(self):
        self.login_answers()
        await self.fetcher.log_in("testonion")
        self.route("/members/", host=TESTONION)
        self.route("/articles/")
        await self.fetcher.fetch("testonion", "/members/")
        await self.fetcher.fetch("news", "/articles/")
        member, news = self.requests[1:]
        self.assertEqual(member.headers.get("cookie"), "sid=s3ss10n")
        self.assertNotIn("cookie", news.headers)
        self.assertTrue(self.jars_empty())

    async def test_a_session_for_another_host_of_the_source_is_not_sent(self):
        self.login_answers()
        await self.fetcher.log_in("testonion")
        self.fetcher.sessions._cookies["testonion"] = (CANDIDATE, "sid=s3ss10n")
        self.route("/members/", host=TESTONION)
        await self.fetcher.fetch("testonion", "/members/")
        self.assertNotIn("cookie", self.requests[-1].headers)

    async def test_any_other_source_id_raises_before_a_request_is_built(self):
        # news carries a form-session config here, as if the loader had been bypassed: the fetcher's own check holds.
        self.configs["news"] = dataclasses.replace(news_config(), auth=testonion_config().auth)
        with mock.patch.object(Fetcher, "_client_for", side_effect=AssertionError("client built")), \
                mock.patch("onioncollect.fetcher.load_credential", side_effect=AssertionError("credential read")):
            for source_id in ("news", "testonion2", "TESTONION", "", CANDIDATE):
                with self.assertRaises(AuthRefused, msg=source_id):
                    await self.fetcher.log_in(source_id)
                with self.assertRaises(AuthRefused, msg=source_id):
                    await self.fetcher._post_form(FetchResult(source_id, "/login", host=NEWS), f"http://{NEWS}/login")
        self.assert_no_client()

    async def test_an_allowlisted_source_not_live_or_degraded_is_refused(self):
        await self.table.change_state("testonion", lifecycle.DEGRADED)
        self.login_answers()
        self.assertEqual((await self.fetcher.log_in("testonion")).error, "redirect", "degraded still collects")
        self.requests.clear()
        self.transport_kwargs.clear()
        self.tor.outcomes.clear()
        await self.table.change_state("testonion", lifecycle.DISABLED, "operator pulled it")
        self.assertEqual((await self.fetcher.log_in("testonion")).error, "auth_refused")
        await self.table.change_state("testonion", lifecycle.APPROVED)
        for allowed in (lifecycle.COLLECTING, lifecycle.UNDER_TEST):
            self.assertEqual((await self.build(allowed).log_in("testonion")).error, "auth_refused", allowed)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.tor.outcomes, [])

    async def test_a_live_source_through_a_golive_fetcher_is_refused_by_its_states(self):
        self.assertEqual((await self.build(lifecycle.UNDER_TEST).log_in("testonion")).error, "not_approved")
        self.assert_no_client()

    async def test_a_config_without_form_session_is_refused(self):
        self.configs["testonion"] = dataclasses.replace(testonion_config(), auth=None)
        self.assertEqual((await self.fetcher.log_in("testonion")).error, "auth_refused")
        self.assert_no_client()

    async def test_an_unreadable_credential_file_sends_nothing(self):
        (self.settings.credentials_dir / "testonion.env").chmod(0o644)
        self.assertEqual((await self.fetcher.log_in("testonion")).error, "credential_unreadable")
        self.assert_no_client()

    async def test_a_failed_post_leaves_no_session_and_an_empty_jar(self):
        self.routes[f"http://{TESTONION}/login"] = httpx.ReadTimeout("x")
        self.assertEqual((await self.fetcher.log_in("testonion")).error, "timeout")
        self.assertFalse(self.fetcher.sessions.holds("testonion"))
        self.assertTrue(self.jars_empty())

    async def test_closing_ends_every_session(self):
        self.login_answers()
        await self.fetcher.log_in("testonion")
        await self.fetcher.close()
        self.assertFalse(self.fetcher.sessions.holds("testonion"))

    async def test_the_credential_reaches_no_log_and_no_result(self):
        self.login_answers()
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("onioncollect").debug("marker")
            result = await self.fetcher.log_in("testonion")
        for text in ("\n".join(logs.output), repr(result), repr(self.fetcher.sessions.__dict__)):
            self.assertNotIn(TESTONION_PASSWORD, text)
            self.assertNotIn(TESTONION_USER, text)
