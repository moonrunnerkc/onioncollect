import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from onioncollect import golive, lifecycle, safety, source_config
from onioncollect.config import Settings
from onioncollect.sources import SourceTable
from tests.test_onion import TORPROJECT, build_address

# Throwaway patterns and generated hosts. The operator's safety files and real configs never enter the repo.
NEWS = build_address(bytes([0xEE] * 32), 3)
NEWS_MIRROR = build_address(bytes([0xCC] * 32), 3)
OFF_SOURCE = build_address(bytes([0xDD] * 32), 3)
CANDIDATE = build_address(bytes([0xBB] * 32), 3)
DECLINED = build_address(bytes([0xAA] * 32), 3)
TESTONION = build_address(bytes([0x77] * 32), 3)
EXCLUDED = TORPROJECT
PATTERNS = safety.parse_patterns("child_exploitation \\bforbiddenterm\\b\n")
SALT = b"test-salt-" + b"x" * 30

NEWS_CONFIG = f'''
id = "news"
hosts = ["{NEWS}"]
category = "journalism-publishing"
cadence = "6h"
seeds = ["/articles/"]

[pagination]
next = "a.next"
max_pages = 3

[listing]
item = "article"

[listing.fields]
title = "h2 a"
url = "h2 a@href"
published = "time@datetime"

[detail]
follow = "url"

[detail.fields]
body = "div.body"

[expect]
min_items_per_page = 2
required_fields = ["title", "url"]

[auth]
type = "none"
'''


# Section 15's self-hosted onion. Synthetic credentials: neither value may ever be found under a data dir.
TESTONION_USER, TESTONION_PASSWORD = "tester-q7v", "Synth-Login-9xQ!"
TESTONION_CONFIG = f'''
id = "testonion"
hosts = ["{TESTONION}"]
category = "self-hosted"
cadence = "6h"
seeds = ["/", "/members/"]

[listing]
item = "article.note"

[listing.fields]
title = "h2 a"
url = "h2 a@href"

[detail]
follow = "url"

[detail.fields]
body = "div.body"

[expect]
min_items_per_page = 1
required_fields = ["title", "url"]

[auth]
type = "form-session"
login_path = "/login"
username_field = "username"
password_field = "password"
success_selector = "#signed-in"
credential_ref = "testonion"
'''


def testonion_config(text: str = TESTONION_CONFIG):
    return source_config.parse(text, "testonion")


def write_credential(settings: Settings, text: str | None = None, mode: int = 0o600) -> Path:
    """The secrets file credential_ref names, as the operator writes it in the guest."""
    settings.credentials_dir.mkdir(parents=True, exist_ok=True)
    path = settings.credentials_dir / "testonion.env"
    path.write_text(text if text is not None else f"username={TESTONION_USER}\npassword={TESTONION_PASSWORD}\n")
    path.chmod(mode)
    return path


def news_config(text: str = NEWS_CONFIG):
    return source_config.parse(text, "news")


def listing_page(*titles: str, next_href: str | None = None, extra: str = "") -> bytes:
    articles = "".join(
        f"<article><h2><a href='/articles/{n}'>{title}</a></h2><time datetime='2026-11-0{n % 9 + 1}'>x</time></article>"
        for n, title in enumerate(titles, 1)
    )
    pager = f"<a class='next' href='{next_href}'>older</a>" if next_href else ""
    return f"<html><body><h1>News</h1>{articles}{pager}{extra}</body></html>".encode()


def detail_page(body: str) -> bytes:
    return f"<html><body><h1>Story</h1><div class='body'>{body}</div></body></html>".encode()


def throwaway_settings(**overrides) -> Settings:
    defaults = {"control_password": "x", "exclusions": frozenset({EXCLUDED}), "safety_patterns": PATTERNS,
                "redaction_salt": SALT}
    return Settings(**defaults | overrides)


async def make_live(table: SourceTable, source_id: str = "news", host: str = NEWS,
                    category: str = "journalism-publishing") -> None:
    await table.approve(host, source_id, category, "public newsroom mirror", "tester", frozenset({EXCLUDED}))
    await table.change_state(source_id, lifecycle.LIVE)


def headlines(edition: str, count: int = 5) -> tuple[str, ...]:
    """Front-page titles long enough to fingerprint. Two editions share no words, only the template."""
    return tuple(f"{edition} story {n} " + " ".join(f"{edition}{n}w{k}" for k in range(12)) for n in range(1, count + 1))


def leak_result_owned_by_root(test) -> None:
    """Check 3 wants root to own the result file; a test's file is owned by whoever runs the suite."""
    patcher = mock.patch.object(golive, "ROOT", os.geteuid())
    patcher.start()
    test.addCleanup(patcher.stop)


DEPLOY = "2026-11-08T09:00:00Z 5eedf00d"


def write_leak_result(path: Path, age: timedelta = timedelta(hours=1), failed: tuple[str, ...] = (),
                      tests: tuple[str, ...] = golive.LEAK_TESTS, mode: int = 0o644, seen: str | None = DEPLOY) -> Path:
    """A result file as `make leak-test` writes it, after the deploy whose stamp `make deploy` left beside it."""
    stamp = path.with_name(golive.DEPLOY_STAMP)
    stamp.write_text(DEPLOY + "\n")
    stamp.chmod(0o644)
    result = {"run_at": (datetime.now(UTC) - age).isoformat(), "run_by": "tester",
              "tests": [{"name": name, "passed": name not in failed} for name in tests]}
    if seen is not None:
        result["deploy_stamp"] = seen
    path.write_text(json.dumps(result))
    path.chmod(mode)
    return path
