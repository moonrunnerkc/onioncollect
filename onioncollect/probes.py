"""Sibling probes: once a day, one GET of the first seed on every host of a collecting source other than its
active one, so `mirrors` and the mirror swap have real last-up times. Up or down only: the body is dropped
unread, and nothing is extracted, fingerprinted or stored."""
import logging
from datetime import UTC, datetime, timedelta
from typing import Awaitable, Callable

from onioncollect import lifecycle
from onioncollect.config import Settings
from onioncollect.fetcher import REFUSALS, Fetcher
from onioncollect.source_config import SourceConfig
from onioncollect.sources import PinnedHost
from onioncollect.tor_pool import TorInstance
from onioncollect.writer_client import Writer

log = logging.getLogger(__name__)

PROBE_INTERVAL = timedelta(days=1)
NEVER = datetime.min.replace(tzinfo=UTC)


class Prober:
    def __init__(self, settings: Settings, writer: Writer, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.settings = settings
        self.writer = writer
        self.clock = clock
        # A probe the fetcher refused leaves no uptime row, so without this it would be due again every pass.
        self.attempted: dict[str, datetime] = {}

    async def probe_due(self, config_for: Callable[[str], Awaitable[SourceConfig | None]],
                        tor_for: Callable[[int], TorInstance]) -> int:
        now = self.clock()
        due = [(source_id, host) for source_id, host in await self.writer.due_probes(PROBE_INTERVAL)
               if now - self.attempted.get(host, NEVER) >= PROBE_INTERVAL]
        for n, (source_id, host) in enumerate(due):
            self.attempted[host] = now
            config = await config_for(source_id)
            if config is not None:
                await self.probe(source_id, host, config, tor_for(n))
        return len(due)

    async def probe(self, source_id: str, host: str, config: SourceConfig, tor: TorInstance) -> bool | None:
        fetcher = Fetcher(self.settings, tor, PinnedHost(self.writer, host), {source_id: config}, lifecycle.COLLECTING)
        try:
            result = await fetcher.fetch(source_id, config.seeds[0])
        finally:
            await fetcher.close()
        if result.error in REFUSALS:
            log.warning("%s sibling probe refused: %s", source_id, result.error)
            return None
        up = result.status is not None
        await self.writer.probe_result(host, up)
        log.info("%s sibling probe status=%s error=%s elapsed=%.1fs", source_id, result.status, result.error,
                 result.elapsed)
        return up
