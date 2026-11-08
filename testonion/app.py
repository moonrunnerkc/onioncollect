"""Section 15's self-hosted onion: the one site onioncollect may log in to, because the operator owns it.

Standard library only, so nothing to pin beyond Debian 13's Python 3.13. Listens on 127.0.0.1:8080 behind the
onion service in torrc and nowhere else. A public landing page lets it be triaged and go live like any source;
the member pages need a session from one POST to /login. Every page is synthetic, and no page ever shows a
credential, a session token, or anything a client sent.
"""
import hmac
import html
import logging
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ADDRESS = ("127.0.0.1", 8080)
CREDENTIALS = Path("/etc/testonion/credentials")
SESSION_TTL = 3600
MAX_SESSIONS = 64
MAX_FORM_BYTES = 4096
FAILURE_WINDOW, MAX_FAILURES = 600, 5
COOKIE = "sid"

NOTICES = {
    1: ("Maintenance window on Sunday", "The service is down for package updates between 02:00 and 03:00 UTC."),
    2: ("New onion address key", "The service key was rotated; the address on this page is the only one in use."),
    3: ("Reading list updated", "Three new notes on onion service operation are in the members' area."),
}
NOTES = {
    1: ("Relay maintenance log", "Restarted the Tor daemon after the package update. Circuits rebuilt in 40 s."),
    2: ("Rotate the relay keys", "Key rotation is due at the end of the quarter. Back up the old keys offline first."),
    3: ("Uptime review", "Two short outages this month, both during planned maintenance."),
}

log = logging.getLogger("testonion")


def read_credentials(path: Path) -> tuple[str, str]:
    if path.stat().st_mode & 0o077:
        sys.exit(f"{path} must be mode 600")
    values = dict(line.partition("=")[::2] for line in path.read_text().splitlines() if line.strip())
    if set(values) != {"username", "password"} or not all(values.values()):
        sys.exit(f"{path}: one username= line and one password= line")
    return values["username"], values["password"]


def page(title: str, body: str, signed_in: bool = False) -> bytes:
    marker = '<p id="signed-in">Signed in</p>' if signed_in else '<p><a href="/login">Members</a></p>'
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title></head>"
            f"<body><h1>{html.escape(title)}</h1>{marker}{body}</body></html>").encode()


def listing(items: dict[int, tuple[str, str]], prefix: str) -> str:
    return "".join(f"<article class='note'><h2><a href='{prefix}{n}'>{html.escape(title)}</a></h2></article>"
                   for n, (title, _) in items.items())


def detail(items: dict[int, tuple[str, str]], path: str, prefix: str) -> tuple[str, str] | None:
    number = path.removeprefix(prefix)
    return items.get(int(number)) if number.isdigit() else None


class Sessions:
    """In memory only: a restart signs everyone out. One lock, since the server answers on a thread per request."""

    def __init__(self):
        self.lock = threading.Lock()
        self.expiry: dict[str, float] = {}
        self.failures: list[float] = []

    def start(self) -> str:
        with self.lock:
            now = time.monotonic()
            self.expiry = {token: until for token, until in self.expiry.items() if until > now}
            while len(self.expiry) >= MAX_SESSIONS:
                self.expiry.pop(min(self.expiry, key=self.expiry.get))
            token = secrets.token_urlsafe(32)
            self.expiry[token] = now + SESSION_TTL
            return token

    def valid(self, token: str | None) -> bool:
        with self.lock:
            return token is not None and self.expiry.get(token, 0) > time.monotonic()

    def failed(self) -> None:
        with self.lock:
            self.failures.append(time.monotonic())

    def throttled(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.failures = [at for at in self.failures if now - at < FAILURE_WINDOW]
            return len(self.failures) >= MAX_FAILURES


class Handler(BaseHTTPRequestHandler):
    server_version = "testonion"
    sys_version = ""
    credentials: tuple[str, str]
    sessions: Sessions

    def log_message(self, format, *args):
        # The method and the status only: no path, no query, never a form.
        pass

    def log_request(self, code="-", size="-"):
        log.info("%s %s", self.command, code)

    def send(self, status: int, body: bytes = b"", **headers) -> None:
        self.send_response(status)
        for name, value in {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
                            "Content-Length": str(len(body)), **headers}.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def session(self) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return None

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self.send(200, page("Operator notices", listing(NOTICES, "/notices/")))
        if path.startswith("/notices/") and (found := detail(NOTICES, path, "/notices/")):
            return self.send(200, page(found[0], f"<div class='body'>{html.escape(found[1])}</div>"))
        if path == "/login":
            return self.send(200, page("Members", "<form method='post' action='/login'>"
                                                  "<input name='username'><input name='password' type='password'>"
                                                  "<button>Sign in</button></form>"))
        if path.startswith("/members/"):
            if not self.sessions.valid(self.session()):
                return self.send(303, Location="/login")
            if path == "/members/":
                return self.send(200, page("Members' notes", listing(NOTES, "/members/notes/"), signed_in=True))
            if found := detail(NOTES, path, "/members/notes/"):
                return self.send(200, page(found[0], f"<div class='body'>{html.escape(found[1])}</div>",
                                           signed_in=True))
        self.send(404, page("Not found", ""))

    def do_POST(self):
        if self.path != "/login":
            return self.send(404, page("Not found", ""))
        if self.sessions.throttled():
            return self.send(429, page("Members", "<p>Too many failed sign-ins. Try again later.</p>"))
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_FORM_BYTES:
            return self.send(413, page("Members", ""))
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        given = form.get("username", [""])[0], form.get("password", [""])[0]
        # Both compared every time, in constant time, so a wrong username takes as long as a wrong password.
        matches = [hmac.compare_digest(sent.encode(), held.encode()) for sent, held in zip(given, self.credentials)]
        if all(matches):
            token = self.sessions.start()
            return self.send(303, Location="/members/",
                             Set_Cookie=f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict")
        self.sessions.failed()
        self.send(200, page("Members", "<p>Sign-in failed.</p>"))

    def do_HEAD(self):
        self.send(405)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    Handler.credentials = read_credentials(Path(sys.argv[1]) if len(sys.argv) > 1 else CREDENTIALS)
    Handler.sessions = Sessions()
    server = ThreadingHTTPServer(ADDRESS, Handler)
    log.info("listening on %s:%d", *ADDRESS)
    server.serve_forever()


if __name__ == "__main__":
    main()
