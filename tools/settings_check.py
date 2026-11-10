"""make deploy's preflight, run by deploy/install.sh as each user against the files installed in the guest. With
--crawl, the settings load as `crawl run` loads them: salt, control password, safety patterns, exclusions and the
Tor ports. Without it, as the analyst's commands load them: the exclusions. A refusal exits non-zero, so the deploy
stops before a unit restarts, rather than on the next crawl tick. Prints counts, never a host or a pattern."""
import argparse
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP))

from onioncollect import onion  # noqa: E402
from onioncollect.config import Settings  # noqa: E402


def summary(path: Path, crawl: bool) -> str:
    settings = Settings.load(path, crawl=crawl)
    hosts = settings.exclusions
    line = f"{len(hosts)} excluded hosts, every one a v3 onion: {all(onion.is_v3_onion(host) for host in hosts)}"
    if crawl:
        line += f"; {len(settings.safety_patterns)} safety patterns; Tor ports answering"
    return line


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="settings_check")
    parser.add_argument("settings", type=Path)
    parser.add_argument("--crawl", action="store_true", help="load as the crawler's crawl run does")
    args = parser.parse_args(argv)
    try:
        print(f"settings check: {args.settings} loads: {summary(args.settings, args.crawl)}")
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"settings check: {args.settings} refused: {exc}") from None


if __name__ == "__main__":
    main()
