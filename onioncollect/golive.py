import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from onioncollect import config_text, lifecycle, matching, onion
from onioncollect.config import Settings, config_path
from onioncollect.db import LISTING
from onioncollect.fetcher import Fetcher
from onioncollect.pages import inspect
from onioncollect.session import Logins
from onioncollect.source_config import ConfigError, SourceConfig
from onioncollect.sources import PinnedHost, RefusedChange, Source
from onioncollect.tor_pool import TorInstance
from onioncollect.writer_client import WriteRefused, Writer

REACHABILITY_INSTANCES = 2
LEAK_TEST_MAX_AGE = timedelta(hours=36)
DEPLOY_STAMP = "deploy-stamp"
LEAK_TESTS = ("clearnet-block", "dns-block", "packet-capture", "redirect-trap")
ROOT = 0


@dataclass
class Report:
    lines: list[tuple[bool, str]] = field(default_factory=list)

    def check(self, ok: bool, line: str) -> bool:
        self.lines.append((ok, line))
        return ok

    @property
    def passed(self) -> bool:
        return all(ok for ok, _ in self.lines)

    @property
    def failure(self) -> str:
        return next((line for ok, line in self.lines if not ok), "")


def root_written(path: Path) -> str | None:
    """Why a file root is meant to have written is not to be trusted, or None."""
    status = path.stat()
    if status.st_uid != ROOT:
        return f"{path} is not owned by root, so make deploy or make leak-test did not write it"
    if status.st_mode & 0o022:
        return f"{path} is writable by someone other than its owner"
    return None


def leak_tests(path: Path, now: datetime) -> tuple[bool, str]:
    """Check 3, and the gate in front of every crawl. The result file `make leak-test` writes as root, read only if
    root owns it and nobody else can write it, from a run after the current deploy (the stamp `make deploy`
    writes beside it, also as root) and no older than LEAK_TEST_MAX_AGE."""
    stamp_path = path.with_name(DEPLOY_STAMP)
    try:
        if why := root_written(path) or root_written(stamp_path):
            return False, f"leak tests: {why}"
        result = json.loads(path.read_text())
        deploy = stamp_path.read_text().strip()
        run_at = datetime.fromisoformat(result["run_at"])
        outcomes = {test["name"]: test["passed"] for test in result["tests"]}
        run_by, seen = str(result["run_by"]), result.get("deploy_stamp")
        age = now - run_at
    except FileNotFoundError as exc:
        return False, f"leak tests: no {exc.filename}; run make deploy, which ends with make leak-test"
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return False, f"leak tests: {path} is not a leak test result ({type(exc).__name__})"
    if seen != deploy:
        return False, f"leak tests: the last run predates the current deploy ({deploy}); run make leak-test"
    if age > LEAK_TEST_MAX_AGE:
        return False, (f"leak tests: last run {run_at:%Y-%m-%d %H:%M}, more than"
                       f" {LEAK_TEST_MAX_AGE.total_seconds() / 3600:.0f} h ago")
    if age < timedelta(0):
        return False, f"leak tests: run at {run_at:%Y-%m-%d %H:%M}, which is in the future"
    failed = [name for name in LEAK_TESTS if outcomes.get(name) is not True]
    if failed:
        return False, f"leak tests: {', '.join(failed)} did not pass in the run at {run_at:%Y-%m-%d %H:%M}"
    return True, f"leak tests: all {len(LEAK_TESTS)} passed {age.total_seconds() / 3600:.0f} h ago, run by {run_by}"


async def go_live(source_id: str, config: SourceConfig, settings: Settings, writer: Writer,
                  instances: list[TorInstance], confirm_new_source: bool = False, mirror_of: str | None = None) -> Report:
    """Section 14. Any failed check leaves the source approved; only a clean pass flips it to live, and a
    pass that confirms the source as a mirror folds it into that source instead."""
    report = Report()
    source = await writer.resolve(source_id)
    row = await writer.get(source_id)
    if not report.check(source is not None and source.state == lifecycle.APPROVED,
                        f"state is approved (found {source.state if source else 'no source'})"):
        return report
    if config.auth is not None:
        # Section 15's login runs only for a collecting source, so a form-session source goes live on its public
        # pages first, with auth.type none, and its config moves to form-session once it is live.
        report.check(False, "auth: form-session; go live with auth.type none on the public pages first")
        return report
    if not (hosts_check(report, config, source)
            and report.check(config.category == source.category and source.category in lifecycle.CATEGORIES
                             and bool(row["note"].strip()), f"policy: {source.category}, reviewer note on file")
            and report.check(*leak_tests(settings.leak_test_result, datetime.now(UTC)))):
        return report
    fetchers = [Fetcher(settings, tor, writer, {source_id: config}, lifecycle.UNDER_TEST) for tor in instances]
    sampled = await reach_and_sample(source_id, config, settings, writer, fetchers, report)
    if not sampled:
        return report
    matched = await writer.source_matches(source_id)
    if mirror_of is not None:
        await fold(source, mirror_of, dict(matched).get(mirror_of), settings, writer, report)
        return report
    named = ", ".join(f"{other} ({matching.describe(near)})" for other, near in matched)
    if not report.check(not matched or confirm_new_source,
                        "mirror: no other source matches" if not matched else
                        f"mirror: matches {named}, confirmed as a new source" if confirm_new_source else
                        f"mirror: matches {named}; rerun with --confirm-new-source or --as-mirror-of {matched[0][0]}"):
        return report
    try:
        # Baselines, the state change to live, and closing any items a reapproved source still carries.
        closed = await writer.went_live(source_id, sampled)
    except WriteRefused:
        report.check(False, "baseline snapshot refused: a secret survived redaction")
        return report
    report.check(True, f"baseline: {len(sampled)} snapshots written, {source_id} is live"
                       + (f"; {closed} open health items closed as fixed" if closed else ""))
    return report


async def recheck(source_id: str, host: str, config: SourceConfig, settings: Settings, writer: Writer,
                  instances: list[TorInstance]) -> Report:
    """Checks 1, 4 and 5 for a source already collecting, against one host of its own set: what the fixed
    and mirror-swapped dispositions must pass. Fetches go through the collecting state and the host set,
    exactly as the crawler's do."""
    report = Report()
    source = await writer.resolve(source_id)
    if not report.check(source is not None and source.state in lifecycle.COLLECTING,
                        f"state is live or degraded (found {source.state if source else 'no source'})"):
        return report
    if not (hosts_check(report, config, source)
            and report.check(host in source.hosts and host in config.hosts,
                             f"host: {host} is in {source_id}'s host set and config")):
        return report
    if config.auth is not None and not report.check(host == source.active_host,
                                                    f"auth: a form-session source logs in on its active host only,"
                                                    f" {source.active_host}"):
        return report
    view, logins = PinnedHost(writer, host), Logins(settings, writer)
    fetchers = [Fetcher(settings, tor, view, {source_id: config}, lifecycle.COLLECTING, sessions=logins.sessions)
                for tor in instances]
    if config.auth is not None:
        error = await logins.start(fetchers[0], source_id, config)
        if not report.check(error is None, "session: signed in, success selector found" if error is None else
                            f"session: not signed in ({error})"):
            for fetcher in fetchers:
                await fetcher.close()
            return report
    await reach_and_sample(source_id, config, settings, writer, fetchers, report)
    return report


def hosts_check(report: Report, config: SourceConfig, source: Source) -> bool:
    # Check 1. The loader already refused any host that is not v3; this adds that each is approved here.
    unapproved = sorted(set(config.hosts) - source.hosts)
    return report.check(not unapproved and all(map(onion.is_v3_onion, config.hosts)),
                        f"hosts: {len(config.hosts)} valid v3, all approved for this source"
                        + (f"; not approved: {', '.join(unapproved)}" if unapproved else ""))


async def reach_and_sample(source_id: str, config: SourceConfig, settings: Settings, writer: Writer,
                           fetchers: list[Fetcher], report: Report) -> list[tuple[str, str]] | None:
    """Checks 4 and 5."""
    try:
        reached = [await fetcher.fetch(source_id, config.seeds[0]) for fetcher in fetchers[:REACHABILITY_INSTANCES]]
        answered = sum(result.status is not None for result in reached)
        errors = ", ".join(sorted({result.error for result in reached if result.error}))
        if not report.check(len(reached) >= REACHABILITY_INSTANCES and answered == len(reached),
                            f"reachability: {answered} of {REACHABILITY_INSTANCES} instances"
                            + (f" ({errors})" if errors else "")):
            return None
        return await sample(source_id, config, settings, writer, fetchers[0], report)
    finally:
        for fetcher in fetchers:
            await fetcher.close()


async def fold(source: Source, mirror_of: str, near: tuple[int, int] | None, settings: Settings, writer: Writer,
               report: Report) -> None:
    if not report.check(near is not None, f"mirror: {source.id} does not match {mirror_of}, so it is not its mirror"):
        return
    # The new config text is proven before anything changes, so a refusal leaves both sources as they were.
    try:
        text = config_text.with_hosts(config_path(settings.configs_dir, mirror_of).read_text(), sorted(source.hosts))
    except (OSError, ConfigError) as exc:
        report.check(False, f"mirror: {mirror_of}'s config: {exc}")
        return
    try:
        # The writer checks the text adds only these hosts, then merges, writes the config and reclusters.
        moved = await writer.fold(source.id, mirror_of, text)
    except RefusedChange as exc:
        report.check(False, f"mirror: {exc}")
        return
    report.check(True, f"mirror: matches {mirror_of} ({matching.describe(near)}); {', '.join(moved)} added to"
                       f" {mirror_of} and its config, which keeps its state; {source.id} is disabled as its mirror")


async def sample(source_id: str, config: SourceConfig, settings: Settings, writer: Writer, fetcher: Fetcher,
                 report: Report) -> list[tuple[str, str]] | None:
    snapshots = []
    for path in config.seeds:
        result = await fetcher.fetch(source_id, path)
        if result.redirect_to and not config.path_for(result.redirect_to):
            await writer.add_redirect_target(source_id, onion.host_of(result.redirect_to))
        if not report.check(result.error is None, f"seed {len(snapshots) + 1}: status {result.status}"
                            + (f", {result.error}" if result.error else "")):
            return None
        found = inspect(result, LISTING, config, settings.safety_patterns, settings.redaction_salt)
        await writer.add_candidates(found.discovered, source_id)
        if found.excluded:
            await writer.disable_for_safety(source_id)
        elif not found.gated and not found.refused:
            await writer.save_fingerprint(result.host, path, True, found.fingerprint)
        complete = found.extraction.items - found.extraction.incomplete
        ok = not (found.excluded or found.gated or found.refused) and complete >= config.min_items_per_page \
            and found.events == 0
        detail = ("tripped the safety check" if found.excluded else "gated" if found.gated else
                  "refused, over the tag cap" if found.refused else
                  f"{complete} complete items of {config.min_items_per_page} expected, hit rate "
                  f"{found.extraction.hit_rate:.2f}, redaction events {found.events}")
        if not report.check(ok, f"seed {len(snapshots) + 1}: {detail}"):
            return None
        snapshots.append((path, found.snapshot))
    return snapshots
