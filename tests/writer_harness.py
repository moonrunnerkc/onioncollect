"""The real writer, in process, for the suite: its server and ops on a short temp socket path, with the test user
as its crawler (the peer check refuses uid 0, so the suite never runs as root), and direct handles on the stores
it owns, for tests to set up and read back."""
import asyncio
import os
import pwd
import shutil
import tempfile
import threading
from pathlib import Path

from onioncollect import lifecycle, writer, writer_ops


class Harness:
    def __init__(self, stores: writer_ops.Stores, server: writer.WriterServer, serving: asyncio.Task, home: str):
        self.stores = stores
        self.server = server
        self.serving = serving
        self.home = home

    @property
    def socket(self) -> Path:
        return self.server.path

    async def stop(self) -> None:
        self.serving.cancel()
        await asyncio.gather(self.serving, return_exceptions=True)
        await self.server.close()
        await self.stores.close()
        shutil.rmtree(self.home, ignore_errors=True)


async def start_writer(data_dir: Path, configs_dir: Path, crawler_uid: int | None = None) -> Harness:
    stores = await writer_ops.Stores.open(data_dir, configs_dir, pwd.getpwuid(os.getuid()).pw_name,
                                          lifecycle.RECORD_RETENTION_DAYS, lifecycle.SNAPSHOT_RETENTION_DAYS)
    # A unix socket path is capped near 104 bytes on macOS, so not under the test's own temp dir.
    home = tempfile.mkdtemp(prefix="w")
    server = writer.WriterServer(stores, Path(home) / "w.sock", os.getuid() if crawler_uid is None else crawler_uid,
                                 os.getgid())
    server.bind()
    return Harness(stores, server, asyncio.create_task(server.serve_forever()), home)


class ThreadedWriter:
    """The same writer on its own event loop in a thread, for tests that drive the synchronous CLI, which runs
    its own asyncio.run."""

    def __init__(self, data_dir: Path, configs_dir: Path, crawler_uid: int | None = None):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.harness = asyncio.run_coroutine_threadsafe(start_writer(data_dir, configs_dir, crawler_uid),
                                                        self.loop).result(10)

    @property
    def socket(self) -> Path:
        return self.harness.socket

    def stop(self) -> None:
        asyncio.run_coroutine_threadsafe(self.harness.stop(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()
