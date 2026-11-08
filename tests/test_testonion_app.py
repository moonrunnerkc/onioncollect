"""testonion/app.py against the two configs shipped beside it, on a loopback port: the self-hosted onion answers
the way section 15's auth step and the extractor expect, and never shows what a client sent."""
import http.client
import importlib.util
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from selectolax.lexbor import LexborHTMLParser

from onioncollect import extractor, source_config
from tests.fixtures import TESTONION, TESTONION_PASSWORD, TESTONION_USER

APP_DIR = Path(__file__).resolve().parent.parent / "testonion"


def load_app():
    spec = importlib.util.spec_from_file_location("testonion_app", APP_DIR / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shipped_config(name: str) -> source_config.SourceConfig:
    return source_config.parse((APP_DIR / name).read_text().replace("HOSTNAME", TESTONION), "testonion")


class TestOnionAppTest(unittest.TestCase):
    def setUp(self):
        self.app = load_app()
        self.tmp = tempfile.TemporaryDirectory()
        credentials = Path(self.tmp.name) / "credentials"
        credentials.write_text(f"username={TESTONION_USER}\npassword={TESTONION_PASSWORD}\n")
        credentials.chmod(0o600)
        self.app.Handler.credentials = self.app.read_credentials(credentials)
        self.app.Handler.sessions = self.app.Sessions()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.app.Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method: str, path: str, body: str | None = None, cookie: str | None = None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
        if cookie:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        answer = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return answer

    def log_in(self, username=TESTONION_USER, password=TESTONION_PASSWORD):
        return self.request("POST", "/login", urlencode({"username": username, "password": password}))

    def extract(self, body: bytes, path: str, config: source_config.SourceConfig) -> extractor.Extraction:
        return extractor.listing(LexborHTMLParser(body.decode()), f"http://{TESTONION}{path}", config)

    def test_the_public_landing_meets_the_stage_one_config(self):
        config = shipped_config("config-public.toml")
        self.assertIsNone(config.auth)
        status, _, body = self.request("GET", "/")
        found = self.extract(body, "/", config)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(found.items - found.incomplete, config.min_items_per_page)
        self.assertTrue(found.follows and all(map(config.path_for, found.follows)), "every note is on the source")
        status, _, notice = self.request("GET", config.path_for(found.records[0]["url"]))
        self.assertEqual(status, 200)
        self.assertIsNotNone(LexborHTMLParser(notice.decode()).css_first("div.body"))

    def test_the_login_answers_as_the_auth_step_expects(self):
        config = shipped_config("config-session.toml")
        status, headers, _ = self.log_in()
        self.assertEqual((status, headers["Location"]), (303, "/members/"))
        self.assertEqual(config.path_for(f"http://{TESTONION}{headers['Location']}"), "/members/")
        cookie = headers["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        status, _, members = self.request("GET", "/members/", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIsNotNone(LexborHTMLParser(members.decode()).css_first(config.auth.success_selector))
        found = self.extract(members, "/members/", config)
        self.assertGreaterEqual(found.items - found.incomplete, config.min_items_per_page)
        status, _, note = self.request("GET", config.path_for(found.records[0]["url"]), cookie=cookie)
        self.assertEqual(status, 200)
        for body in (members, note):
            self.assertNotIn(TESTONION_USER.encode(), body)
            self.assertNotIn(TESTONION_PASSWORD.encode(), body)

    def test_members_pages_without_a_session_bounce_to_the_login(self):
        for cookie in (None, "sid=forged"):
            status, headers, _ = self.request("GET", "/members/notes/1", cookie=cookie)
            self.assertEqual((status, headers["Location"]), (303, "/login"))

    def test_a_wrong_password_signs_nobody_in_and_echoes_nothing(self):
        status, headers, body = self.log_in(password="Wrong-Guess-77")
        self.assertEqual(status, 200)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(b"Wrong-Guess-77", body)
        self.assertNotIn(TESTONION_USER.encode(), body)

    def test_failed_sign_ins_are_throttled(self):
        for _ in range(self.app.MAX_FAILURES):
            self.log_in(password="Wrong-Guess-77")
        self.assertEqual(self.log_in()[0], 429)

    def test_a_credentials_file_readable_by_others_stops_the_app(self):
        path = Path(self.tmp.name) / "loose"
        path.write_text("username=a\npassword=b\n")
        path.chmod(0o644)
        with self.assertRaises(SystemExit):
            self.app.read_credentials(path)


if __name__ == "__main__":
    unittest.main()
