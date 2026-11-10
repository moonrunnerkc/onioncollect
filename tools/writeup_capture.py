"""make writeup-capture, as the analyst in the guest (onioncollect-capture.service): the write-up's evidence in one
bundle under OUT/<UTC time>/. Every file comes from a read-only command or query; the crawl log contributes only
its Tor instance lines, and nothing else from the data dir goes in raw. Before anything is written, every file is
stripped of the testonion address, any section 15 credential value (read from the *.env files in --credentials,
as log_audit does), every IP address and the login name of every account with a home under /home but the two
role accounts, then checked again: if anything survived, nothing is written."""
import argparse
import ipaddress
import json
import pwd
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP))

from onioncollect.config import Settings  # noqa: E402
from tests.live.log_audit import credentials  # noqa: E402

TESTONION = "testonion"
TOR_LINE = re.compile(r" onioncollect\.tor_pool: tor \d+: (rotated circuits|success |no circuit after )")
IP_CANDIDATE = re.compile(r"(?<![\w.:])[0-9A-Fa-f.:]*[.:][0-9A-Fa-f.:]+(?![\w.:])")
HIDDEN = {"testonion": "[testonion address]", "credential": "[credential]", "user": "[user]", "ip": "[ip]"}
# The accounts whose names are roles, the same on every deployment. Any other login name says who the operator is.
ROLES = frozenset({"crawler", "analyst"})


def login_names() -> set[str]:
    return {entry.pw_name for entry in pwd.getpwall() if entry.pw_dir.startswith("/home/")} - ROLES


def user_pattern(users: set[str]) -> re.Pattern | None:
    """A login name as a whole word, so a name that is also part of a longer word leaves that word alone."""
    names = "|".join(re.escape(name) for name in sorted(users, key=len, reverse=True) if name)
    return re.compile(rf"(?<![\w-])(?:{names})(?![\w-])") if names else None


def is_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def ip_spans(text: str) -> list[str]:
    """IPv4 and IPv6 addresses, validated, so a time like 12:30:45 or a version like 3.13 is left alone."""
    return [candidate for candidate in IP_CANDIDATE.findall(text) if is_ip(candidate)]


def needles(hosts: set[str], secrets: set[str]) -> dict[str, set[str]]:
    labels = {host.removesuffix(".onion") for host in hosts}
    return {"testonion": {needle for needle in hosts | labels if needle}, "credential": {s for s in secrets if s}}


def strip(texts: dict[str, str], hosts: set[str], secrets: set[str],
          users: set[str]) -> tuple[dict[str, str], dict[str, int]]:
    counts = dict.fromkeys(HIDDEN, 0)
    found = needles(hosts, secrets)
    named = user_pattern(users)
    stripped = {}
    for name, text in texts.items():
        for kind in ("credential", "testonion"):
            for needle in sorted(found[kind], key=len, reverse=True):
                counts[kind] += text.count(needle)
                text = text.replace(needle, HIDDEN[kind])
        if named:
            text, hits = named.subn(HIDDEN["user"], text)
            counts["user"] += hits
        counts["ip"] += len(ip_spans(text))
        stripped[name] = IP_CANDIDATE.sub(lambda m: HIDDEN["ip"] if is_ip(m.group(0)) else m.group(0), text)
    return stripped, counts


def survivors(texts: dict[str, str], hosts: set[str], secrets: set[str], users: set[str]) -> list[str]:
    found = needles(hosts, secrets)
    named = user_pattern(users)
    return ([f"{name}: {kind}" for name, text in texts.items() for kind in ("testonion", "credential")
             if any(needle in text for needle in found[kind])]
            + [f"{name}: user" for name, text in texts.items() if named and named.search(text)]
            + [f"{name}: ip" for name, text in texts.items() if ip_spans(text)])


def write_bundle(out: Path, texts: dict[str, str], hosts: set[str], secrets: set[str], users: set[str]) -> Path:
    stripped, counts = strip(texts, hosts, secrets, users)
    left = survivors(stripped, hosts, secrets, users)
    if left:
        raise SystemExit(f"writeup-capture: nothing written, still present after stripping: {', '.join(left)}")
    target = out / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target.mkdir(mode=0o700, parents=True)
    for name, text in stripped.items():
        (target / name).write_text(text)
        (target / name).chmod(0o600)
    manifest = [f"{name}  {len(text.splitlines())} lines" for name, text in sorted(stripped.items())]
    replaced = ", ".join(f"{HIDDEN[kind]} x{count}" for kind, count in counts.items())
    (target / "MANIFEST.txt").write_text("\n".join([f"captured {datetime.now(UTC):%Y-%m-%d %H:%M} UTC",
                                                    f"replaced: {replaced}", *manifest]) + "\n")
    return target


def cli(settings_path: Path, *args: str) -> str:
    done = subprocess.run([sys.executable, "-s", "-E", "-m", "onioncollect", "--settings", str(settings_path), *args],
                          cwd=APP, capture_output=True, text=True)
    return done.stdout + (f"\n[command exited {done.returncode}: {done.stderr.strip()}]\n" if done.returncode else "")


def rows(db_path: Path, sql: str, params=()) -> list[sqlite3.Row]:
    db = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        return db.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        db.close()


def gather(settings_path: Path, settings: Settings, credentials_dir: Path) -> dict[str, str]:
    collect = settings.data_dir / "collect.db"
    texts = {"sources-export.jsonl": cli(settings_path, "sources", "export"),
             "triage-list.txt": cli(settings_path, "triage", "list"),
             "health-queue.txt": cli(settings_path, "health"),
             "health-log.txt": cli(settings_path, "health", "log")}
    for row in rows(collect, "SELECT id FROM sources ORDER BY id"):
        texts[f"health-runs-{row['id']}.txt"] = cli(settings_path, "health", "runs", row["id"], "--limit", "200")
        reports = rows(collect, "SELECT run_at, passed, lines FROM golive_reports WHERE source_id = ? ORDER BY id",
                       (row["id"],))
        if reports:
            texts[f"golive-{row['id']}.txt"] = "\n".join(
                f"golive {row['id']} at {report['run_at'][:16]}: {'passed' if report['passed'] else 'failed'}\n"
                + "\n".join(f"{'PASS' if ok else 'FAIL'}  {line}" for ok, line in json.loads(report["lines"]))
                for report in reports) + "\n"
    try:
        texts["leak-test.json"] = settings.leak_test_result.read_text()
    except OSError as exc:
        texts["leak-test.json"] = f"[not readable: {type(exc).__name__}]\n"
    logs = sorted(settings.log_dir.glob("crawl.log*"), reverse=True)
    texts["tor-lines.txt"] = "".join(line for path in logs for line in path.read_text().splitlines(keepends=True)
                                     if TOR_LINE.search(line))
    audit = subprocess.run([sys.executable, "-s", "-E", str(APP / "tests/live/log_audit.py"), "--data",
                            str(settings.data_dir), "--credentials", str(credentials_dir),
                            str(settings.log_dir / "crawl.log"), str(Path.home() / "ui.log")],
                           cwd=APP, capture_output=True, text=True)
    texts["log-audit.txt"] = audit.stdout + f"exit {audit.returncode}\n"
    return texts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="the write-up's evidence, stripped, in one bundle")
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, default=Path("/etc/onioncollect"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    settings = Settings.load(args.settings, reader=True)
    hosts = {row["host"] for row in rows(settings.data_dir / "collect.db",
                                         "SELECT host FROM hosts WHERE source_id = ?", (TESTONION,))}
    target = write_bundle(args.out, gather(args.settings, settings, args.credentials), hosts,
                          credentials(args.credentials), login_names())
    print(f"writeup-capture: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
