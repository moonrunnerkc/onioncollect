import asyncio
import contextlib
import logging
import random
import signal
from datetime import UTC, datetime

from onioncrawl import onion, parser, safety, scheduler
from onioncrawl.config import Settings
from onioncrawl.db import Frontier, Task
from onioncrawl.fetcher import Fetcher, FetchResult
from onioncrawl.storage import PageStore
from onioncrawl.tor_pool import TorPool

log = logging.getLogger(__name__)

IDLE_SLEEP = 5.0


class Crawler:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.frontier = Frontier(settings)
        self.tor_pool = TorPool(settings)
        self.store = PageStore(settings.data_dir)
        self.stopping = asyncio.Event()
        self.exclusions = safety.load_exclusions(settings.exclusions_file)
        self.patterns = safety.load_patterns(settings.safety_patterns_file)

    async def run(self) -> None:
        await self.frontier.open(self.settings.data_dir / "crawl.db")
        try:
            self.exclusions |= await self.frontier.excluded_hosts()
            await self.tor_pool.start()
            loop = asyncio.get_running_loop()
            for signum in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(signum, self.stopping.set)
            count = len(self.tor_pool.instances) * self.settings.workers_per_instance
            log.info("crawler: %d workers on %d tor instances", count, len(self.tor_pool.instances))
            workers = [asyncio.create_task(self.worker(n)) for n in range(count)]
            health = asyncio.create_task(self.tor_pool.health_loop())
            await self.stopping.wait()
            log.info("crawler: stopping, letting in-flight fetches finish")
            health.cancel()
            await asyncio.gather(*workers)
        finally:
            self.tor_pool.stop()
            await self.frontier.close()
        log.info("crawler: stopped")

    async def worker(self, worker_id: int) -> None:
        fetcher = Fetcher(self.settings, self.tor_pool.assign(worker_id))
        try:
            while not self.stopping.is_set():
                tasks = await self.frontier.claim(1)
                if not tasks:
                    await self.pause(IDLE_SLEEP)
                    continue
                task = tasks[0]
                result = await fetcher.fetch(task.url)
                if result.error:
                    await self.handle_failure(task, result, fetcher)
                else:
                    await self.handle_success(task, result)
                await self.pause(random.uniform(*self.settings.jitter_seconds))
        except Exception as exc:
            # Only the exception's type: its message can carry a URL. The claimed lease expires and is retried.
            log.error("worker %d: stopped by %s, shutting down", worker_id, type(exc).__name__)
            self.stopping.set()
        finally:
            await fetcher.close()

    async def pause(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.stopping.wait(), seconds)

    async def handle_success(self, task: Task, result: FetchResult) -> None:
        info = parser.parse(result.final_url, result.status, result.body, result.headers)
        final_host = onion.host_of(result.final_url)
        # Nothing below may await before store.save: a body that trips the filter on another worker adds
        # its host to self.exclusions synchronously, so this check always sees it.
        if safety.is_excluded(task.host, self.exclusions) or safety.is_excluded(final_host, self.exclusions):
            category = "listed"
        else:
            category = safety.body_triggers_exclusion(result.body.decode("utf-8", errors="replace"), self.patterns)
        if category:
            self.exclusions.add(task.host)
            await self.frontier.exclude(task, info)
            log.warning("%s excluded: %s", task.host, category)
            return
        page_path = None
        if not info.gated:
            self.store.save(info.sha256, result.body)
            page_path = str(self.store.path_for(info.sha256).relative_to(self.settings.data_dir))
        changed = info.sha256 != task.last_hash
        due = scheduler.next_due_for_url(task, info, changed, self.settings, datetime.now(UTC))
        await self.frontier.complete(task, info, due, page_path)
        log.info(
            "%s status=%d bytes=%d links=%d onions=%d changed=%s%s elapsed=%.1fs",
            task.host, result.status, info.size, len(info.links), len(info.text_onions),
            "yes" if changed else "no", " gated" if info.gated else "", result.elapsed,
        )

    async def handle_failure(self, task: Task, result: FetchResult, fetcher: Fetcher) -> None:
        due = scheduler.next_due_for_failure(task, result.error, self.settings, datetime.now(UTC))
        retries = task.retries + scheduler.retry_cost(result.error)
        host_answered = result.status is not None
        await self.frontier.fail(task, retries, due, host_answered)
        log.info("%s error=%s elapsed=%.1fs", task.host, result.error, result.elapsed)
        if scheduler.host_is_dead(await self.frontier.recent_failures(task.host), self.settings):
            await self.frontier.mark_dead(task.host)
            log.info("%s marked dead", task.host)
        if scheduler.should_rotate(result.error, fetcher.tor):
            await self.tor_pool.rotate_for(fetcher.tor)
