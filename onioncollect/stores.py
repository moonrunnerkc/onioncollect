"""How an analyst command reaches the stores: open the source table and the record store, run one action,
close both. A refused change becomes a clean exit."""
import asyncio
import os
import pwd
from datetime import timedelta

from onioncollect.config import Settings
from onioncollect.db import open_collect
from onioncollect.records import RecordStore
from onioncollect.sources import RefusedChange, SourceTable


def operator() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def record_store(settings: Settings) -> RecordStore:
    return RecordStore(settings.data_dir, timedelta(days=settings.record_retention_days),
                       timedelta(days=settings.snapshot_retention_days))


def with_stores(settings: Settings, action, read_only: bool = False):
    async def run():
        collect = await open_collect(settings.data_dir / "collect.db", read_only)
        store = record_store(settings)
        try:
            await store.open(read_only)
        except BaseException:
            await collect.close()
            raise
        try:
            return await action(SourceTable(collect), store)
        except RefusedChange as exc:
            raise SystemExit(f"onioncollect: not changed, {exc}") from None
        finally:
            await store.close()
            await collect.close()
    return asyncio.run(run())


def with_records(settings: Settings, action, read_only: bool = False):
    return with_stores(settings, lambda table, store: action(store), read_only)


def reading(settings: Settings, action):
    """An analyst read: both stores opened read-only, so the action cannot write even by mistake."""
    try:
        return with_stores(settings, action, read_only=True)
    except FileNotFoundError as exc:
        raise SystemExit(f"onioncollect: no {exc.args[0]} yet; the crawler's first command creates it") from None
