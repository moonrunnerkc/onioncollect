import asyncio
import contextlib
import logging
import random
import signal
from datetime import UTC, datetime, timedelta

from onioncollect import lifecycle, onion, scheduler, wire
from onioncollect.config import Settings, load_config
from onioncollect.db import DETAIL, LISTING, Frontier, PageMetric, Task, open_frontier
from onioncollect.fetcher import Fetcher, FetchResult
from onioncollect.pages import Inspection, inspect
from onioncollect.probes import Prober
from onioncollect.session import Logins
from onioncollect.source_config import ConfigError, SourceConfig
from onioncollect.tor_pool import TorPool
from onioncollect.writer_client import WriteRefused, Writer, WriterError, WriterUnavailable

log = logging.getLogger(__name__)

IDLE_SLEEP = 5.0
SCHEDULE_INTERVAL = 60.0
CONFIG_RETRY = timedelta(hours=1)


class Crawler:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.configs: dict[str, SourceConfig] = {}
        self.config_errors: dict[str, str] = {}
        self.writer = Writer(settings.writer_socket)
        self.tor_pool = TorPool(settings)
        self.stopping = asyncio.Event()
        self.detail_snapshots: set[int] = set()

    async def open(self) -> None:
        self.settings.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.queue = await open_frontier(self.settings.state_dir / "frontier.db")
        self.frontier = Frontier(self.queue, self.settings.per_source_concurrency)
        self.prober = Prober(self.settings, self.writer)
        self.logins = Logins(self.settings, self.writer)
        await self.frontier.release_stale_leases()

    async def close(self) -> None:
        await self.queue.close()

    async def run(self, until_idle: bool = False) -> None:
        await self.open()
        try:
            await self.check_writer()
            await self.check_configs()
            await self.tor_pool.start()
            loop = asyncio.get_running_loop()
            for signum in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(signum, self.stopping.set)
            count = len(self.tor_pool.instances) * self.settings.workers_per_instance
            log.info("crawler: %d workers on %d tor instances", count, len(self.tor_pool.instances))
            probe = lambda: self.prober.probe_due(self.config_for, self.tor_pool.assign)
            if until_idle:
                # The timer's mode: one probe pass and one scheduling pass, then stop once no page is left
                # to fetch. Cadence decides what was due; whatever falls due later waits for the next tick.
                await probe()
                await self.start_due_runs()
                jobs = (self.tor_pool.health_loop(), self.every(IDLE_SLEEP, self.stop_when_idle))
            else:
                jobs = (self.tor_pool.health_loop(), self.every(SCHEDULE_INTERVAL, self.start_due_runs),
                        self.every(SCHEDULE_INTERVAL, probe))
            workers = [asyncio.create_task(self.worker(n)) for n in range(count)]
            background = [asyncio.create_task(job) for job in jobs]
            await self.stopping.wait()
            log.info("crawler: stopping, letting in-flight fetches finish")
            for task in background:
                task.cancel()
            await asyncio.gather(*workers)
        finally:
            self.tor_pool.stop()
            await self.close()
        log.info("crawler: stopped")

    async def every(self, seconds: float, job) -> None:
        while not self.stopping.is_set():
            await job()
            await self.pause(seconds)

    async def check_writer(self) -> None:
        """Before Tor and any client: a crawl that cannot store what it fetches does not start."""
        try:
            await self.writer.ping()
        except (WriterUnavailable, WriterError) as exc:
            raise WriterUnavailable(f"crawl refused, {exc}") from None

    async def check_configs(self) -> None:
        """Every collecting source's config through the loader's full validation before anything starts. A config
        can change between runs with no golive (testonion's switch to form-session is one), so a crawl with any
        config that fails does not start at all. The form-session sources are named, so the switch shows."""
        collecting = await self.writer.collecting()
        broken = [source_id for source_id in collecting if await self.config_for(source_id) is None]
        if broken:
            raise ConfigError(f"configs that fail validation: {', '.join(broken)}")
        sessions = [source_id for source_id in collecting if self.configs[source_id].auth is not None]
        log.info("crawler: form-session sources: %s", ", ".join(sessions) or "none")

    async def stop_when_idle(self) -> None:
        if not await self.frontier.pending(await self.writer.collecting()):
            log.info("crawler: no page left to fetch")
            self.stopping.set()

    async def start_due_runs(self) -> None:
        for source_id in await self.writer.due_sources():
            config = await self.config_for(source_id)
            if config is not None:
                run_id = await self.writer.run_start(source_id)
                await self.frontier.queue_seeds(source_id, run_id, config.seeds)
                log.info("%s run %d started", source_id, run_id)

    async def config_for(self, source_id: str) -> SourceConfig | None:
        try:
            config = load_config(self.settings.configs_dir, source_id)
            source = await self.writer.resolve(source_id)
            if not set(config.hosts) <= source.hosts or config.category != source.category:
                raise ConfigError("hosts or category differ from what was approved")
        except ConfigError as exc:
            if self.config_errors.get(source_id) != str(exc):
                log.error("%s not scheduled: %s", source_id, exc)
            self.config_errors[source_id] = str(exc)
            self.configs.pop(source_id, None)
            return None
        self.config_errors.pop(source_id, None)
        self.configs[source_id] = config
        return config

    async def worker(self, worker_id: int) -> None:
        tor = self.tor_pool.assign(worker_id)
        fetcher = Fetcher(self.settings, tor, self.writer, self.configs, lifecycle.COLLECTING,
                          sessions=self.logins.sessions)
        try:
            while not self.stopping.is_set():
                tasks = await self.frontier.claim(1, await self.writer.collecting())
                if not tasks:
                    await self.pause(IDLE_SLEEP)
                    continue
                await self.handle(tasks[0], fetcher)
                await self.pause(random.uniform(*self.settings.jitter_seconds))
        except Exception as exc:
            # Only the exception's type: its message can carry a path. The claimed lease expires and is retried.
            log.error("worker %d: stopped by %s, shutting down", worker_id, type(exc).__name__)
            self.stopping.set()
        finally:
            await fetcher.close()

    async def pause(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.stopping.wait(), seconds)

    async def handle(self, task: Task, fetcher: Fetcher) -> None:
        config = self.configs.get(task.source_id) or await self.config_for(task.source_id)
        result = await self.logins.fetch(fetcher, task.source_id, task.path, config)
        metric = PageMetric(host=result.host or "", elapsed=result.elapsed, status=result.status, error=result.error)
        if result.error == "redirect" and config is not None:
            await self.handle_redirect(task, result, metric, config)
        elif result.error or config is None:
            await self.handle_failure(task, metric, fetcher)
        else:
            await self.handle_success(task, result, metric, config)
        await self.finish_run(task, config)

    async def handle_success(self, task: Task, result: FetchResult, metric: PageMetric, config: SourceConfig) -> None:
        # Parsing, the body check, extraction and redaction are pure and can take a few hundred milliseconds
        # on a hostile 2 MB body, so they run in a thread; the GIL changes hands between their C calls.
        found = await asyncio.to_thread(
            inspect, result, task.kind, config, self.settings.safety_patterns, self.settings.redaction_salt
        )
        metric.bytes = len(result.body)
        discovered = await self.writer.add_candidates(found.discovered, task.source_id)
        if found.excluded:
            metric.error = "excluded_body"
            await self.writer.disable_for_safety(task.source_id)
            await self.failed(task, metric, task.retries, None)
            log.warning("%s disabled: body tripped %s", task.source_id, found.excluded)
            return
        if found.gated or found.refused:
            metric.error = "gated" if found.gated else "parse_refused"
            await self.handle_failure(task, metric, None)
            return
        extraction = found.extraction
        if task.kind == LISTING:
            metric.items, metric.incomplete = extraction.items, extraction.incomplete
        metric.fields_resolved, metric.fields_declared = extraction.fields_resolved, extraction.fields_declared
        metric.field_hits, metric.field_items = dict(extraction.field_hits), extraction.field_items
        metric.below_expectation = task.kind == LISTING and extraction.items - extraction.incomplete < config.min_items_per_page
        metric.redactions = found.events
        seed = task.kind == LISTING and task.page == 1
        await self.writer.save_fingerprint(result.host, task.path, seed, found.fingerprint)
        if seed:
            # Ahead of storing, so a source whose seed page now matches a sibling's dedupes against it this page.
            await self.writer.mirrors_refresh()
        metric.records_new = await self.store(task, result.host, found)
        listing = [(found.next_page, task.page + 1)] if found.next_page and task.page < config.max_pages else []
        await self.done(task, metric, listing, found.follows)
        log.info(
            "%s %s status=%d bytes=%d items=%d fields=%d/%d new=%d redactions=%d discovered=%d elapsed=%.1fs",
            task.source_id, task.kind, result.status, metric.bytes, extraction.items, extraction.fields_resolved,
            extraction.fields_declared, metric.records_new, found.events, discovered, result.elapsed,
        )
        if found.events:
            # Section 11: secret-shaped text on a live source is a top-priority health item.
            await self.writer.redaction_events(task.source_id, found.events, task.run_id)

    async def store(self, task: Task, host: str, found: Inspection) -> int:
        """Records and the snapshot through the writer, which checks each again and raises the health item for
        any it refuses. Every listing page is snapshotted, and one detail page a run: enough for `config test`."""
        new = 0
        try:
            new = await self.writer.store_records(task, host, found.records)
            if task.kind == LISTING or task.run_id not in self.detail_snapshots:
                if task.kind == DETAIL:
                    self.detail_snapshots.add(task.run_id)
                await self.writer.save_snapshot(task, found.snapshot)
        except WriteRefused as exc:
            log.warning("%s write refused: a secret survived redaction", task.source_id)
            if str(exc) == wire.OVERSIZE:
                await self.writer.store_too_large(task.source_id, task.run_id)
        return new

    async def done(self, task: Task, metric: PageMetric, listing: list[tuple[str, int]], details: list[str]) -> None:
        # Two stores, two steps: a crash between them loses this one page's metrics, never a page.
        await self.frontier.complete(task, metric.status, listing, details)
        await self.writer.page_done(task, metric)

    async def failed(self, task: Task, metric: PageMetric, retries: int, next_due: datetime | None) -> None:
        await self.frontier.fail(task, metric.status, retries, next_due)
        await self.writer.page_done(task, metric)

    async def handle_redirect(self, task: Task, result: FetchResult, metric: PageMetric, config: SourceConfig) -> None:
        target = result.redirect_to
        path = target and config.path_for(target)
        if path:
            listing = [(path, task.page)] if task.kind == LISTING else []
            await self.done(task, metric, listing, [path] if task.kind == DETAIL else [])
        else:
            # Off the source: an onion becomes a candidate for triage, anything else is dropped.
            discovered = await self.writer.add_redirect_target(task.source_id, onion.host_of(target)) if target else 0
            metric.error = "redirect_offsite"
            await self.failed(task, metric, task.retries, None)
            log.info("%s redirect off the source, discovered=%d", task.source_id, discovered)

    async def handle_failure(self, task: Task, metric: PageMetric, fetcher: Fetcher | None) -> None:
        retries = task.retries + scheduler.retry_cost(metric.error)
        due = scheduler.next_due_for_failure(retries, metric.error, self.settings.max_retries, datetime.now(UTC))
        await self.failed(task, metric, retries, due)
        log.info("%s %s error=%s elapsed=%.1fs", task.source_id, task.kind, metric.error, metric.elapsed)
        if fetcher is not None and scheduler.should_rotate(metric.error, fetcher.tor):
            await self.tor_pool.rotate_for(fetcher.tor)

    async def finish_run(self, task: Task, config: SourceConfig | None) -> None:
        # A source whose config broke mid-run still closes the run, or it would never be scheduled again.
        if await self.frontier.open_in_run(task.run_id):
            return
        cadence = config.cadence if config is not None else CONFIG_RETRY
        expect = config and {"min_items": config.min_items_per_page, "required": list(config.required_fields),
                             "category": config.category}
        finished = await self.writer.run_finish(task.run_id, cadence.total_seconds(), expect)
        run = finished["run"]
        if run is None:
            return
        self.detail_snapshots.discard(task.run_id)
        self.logins.end(task.source_id)
        rate = run["fields_resolved"] / run["fields_declared"] if run["fields_declared"] else 0.0
        log.info(
            "%s run %d done pages=%d failures=%d items=%d hit_rate=%.2f below_expectation=%d new=%d redactions=%d",
            task.source_id, task.run_id, run["pages"], run["failures"], run["items"], rate, run["below_expectation"],
            run["records_new"], run["redactions"],
        )
        for kind, priority in finished["findings"]:
            log.info("%s health item %s priority=%d", task.source_id, kind, priority)
