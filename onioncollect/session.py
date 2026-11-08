"""Section 15, run side. A form-session source logs in once per run, before its first page, and every fetcher
of the crawl shares that session until the run ends. The request itself is Fetcher.log_in's alone."""
import asyncio
import logging
from collections import defaultdict

from onioncollect import onion, scheduler
from onioncollect.config import Settings
from onioncollect.fetcher import Fetcher, FetchResult, Sessions
from onioncollect.pages import signed_in
from onioncollect.source_config import SourceConfig
from onioncollect.writer_client import Writer

log = logging.getLogger(__name__)


class Logins:
    def __init__(self, settings: Settings, writer: Writer):
        self.settings = settings
        self.writer = writer
        self.sessions = Sessions()
        self.locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        # Each source's login outcome for its run under way: None when signed in, else the error every page of
        # the run fails with. One attempt a run, however many pages wait on it.
        self.outcomes: dict[str, str | None] = {}

    async def fetch(self, fetcher: Fetcher, source_id: str, path: str, config: SourceConfig | None) -> FetchResult:
        if config is not None and config.auth is not None:
            error = await self.start(fetcher, source_id, config)
            if error is not None:
                return FetchResult(source_id, path, error=error)
        return await fetcher.fetch(source_id, path)

    async def start(self, fetcher: Fetcher, source_id: str, config: SourceConfig) -> str | None:
        async with self.locks[source_id]:
            if source_id not in self.outcomes:
                self.outcomes[source_id] = error = await self.sign_in(fetcher, source_id, config)
                if error is None:
                    log.info("%s session started", source_id)
                else:
                    log.warning("%s session not started: %s", source_id, error)
            return self.outcomes[source_id]

    def end(self, source_id: str) -> None:
        self.outcomes.pop(source_id, None)
        self.sessions.end(source_id)

    async def sign_in(self, fetcher: Fetcher, source_id: str, config: SourceConfig) -> str | None:
        posted = await fetcher.log_in(source_id)
        if posted.redirect_to is None:
            # A login page shown again, or a redirect off every onion: not signed in.
            return posted.error if posted.error not in (None, "redirect") else "auth_rejected"
        path = config.path_for(posted.redirect_to)
        if path is None:
            await self.writer.add_redirect_target(source_id, onion.host_of(posted.redirect_to))
            return "auth_rejected"
        landed = await fetcher.fetch(source_id, path)
        if landed.error is not None:
            return landed.error if landed.error in scheduler.FLAKY_ERRORS else "auth_rejected"
        excluded, matched = await asyncio.to_thread(signed_in, landed, config.auth.success_selector,
                                                    self.settings.safety_patterns)
        if excluded:
            await self.writer.disable_for_safety(source_id)
            log.warning("%s disabled: body tripped %s", source_id, excluded)
            return "excluded_body"
        return None if matched else "auth_rejected"
