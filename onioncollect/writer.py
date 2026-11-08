"""The write socket. A process running as the analyst owns the stores and serves the crawler's writes over a unix
socket, so the crawler never holds a store file open and the storage layer's secret detector runs under a
different user from the redaction gate. Run by onioncollect-writer.service:

    python -m onioncollect.writer --data-dir DIR --configs-dir DIR [--socket PATH]

Every connection's peer must be the crawler, checked with the kernel's peer credentials before a byte is read.
Each line is one op from writer_ops.OPS, checked field by field against its spec; anything else is answered with
an error and the connection is closed. The log has op names, outcomes, sizes and timings, never a payload."""
import argparse
import asyncio
import grp
import json
import logging
import os
import pwd
import signal
import socket
import struct
import sys
import time
from pathlib import Path

from onioncollect import lifecycle, wire, writer_ops
from onioncollect.records import RefusedWrite
from onioncollect.sources import RefusedChange

SOCKET = Path("/run/onioncollect/writer.sock")
SOCKET_MODE = 0o660
CRAWLER = "crawler"
SOCKET_GROUP = "onioncollect-ipc"
# macOS, where the suite also runs, has LOCAL_PEERCRED at SOL_LOCAL (0) in place of Linux's SO_PEERCRED.
SOL_LOCAL, LOCAL_PEERCRED = 0, 1
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

log = logging.getLogger(__name__)


class BadRequest(Exception):
    def __init__(self, code: str, reason: str, op: str = "-"):
        super().__init__(reason)
        self.code, self.reason, self.op = code, reason, op


def peer_uid(conn: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):
        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid
    # struct xucred: a version, then the uid.
    _, uid = struct.unpack("2I", conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 76)[:8])
    return uid


def admitted(uid: int, crawler_uid: int) -> bool:
    return uid != 0 and uid == crawler_uid


def check(value, spec, where: str) -> None:
    """Raises BadRequest unless `value` has exactly the shape `spec` names. Specs: "str", "int", "float", "bool",
    any of those with "?" for null too; ("list", spec); ("map", spec) with string keys; ("pair", a, b);
    ("one_of", *strings); ("nullable", spec); and a dict, an object with exactly those fields."""
    if isinstance(spec, str):
        if spec.endswith("?"):
            if value is None:
                return
            spec = spec[:-1]
        wanted = {"str": str, "int": int, "float": (int, float), "bool": bool}[spec]
        if isinstance(value, bool) != (spec == "bool") or not isinstance(value, wanted):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected {spec}")
    elif isinstance(spec, dict):
        if not isinstance(value, dict):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected an object")
        if missing := sorted(set(spec) - set(value)):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: missing {', '.join(missing)}")
        if extra := sorted(set(value) - set(spec)):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: unexpected {', '.join(extra)}")
        for name, inner in spec.items():
            check(value[name], inner, f"{where}.{name}")
    elif spec[0] == "nullable":
        if value is not None:
            check(value, spec[1], where)
    elif spec[0] == "one_of":
        if value not in spec[1:]:
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected one of {', '.join(spec[1:])}")
    elif spec[0] == "list":
        if not isinstance(value, list):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected a list")
        for n, item in enumerate(value):
            check(item, spec[1], f"{where}[{n}]")
    elif spec[0] == "map":
        if not isinstance(value, dict):
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected an object")
        for name, item in value.items():
            check(item, spec[1], f"{where}[]")
    elif spec[0] == "pair":
        if not isinstance(value, list) or len(value) != 2:
            raise BadRequest(wire.BAD_REQUEST, f"{where}: expected a pair")
        check(value[0], spec[1], f"{where}[0]")
        check(value[1], spec[2], f"{where}[1]")


def parse(line: bytes) -> tuple[str, dict]:
    """The op name and its fields from one line, every field checked against the op's spec."""
    try:
        request = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BadRequest(wire.NOT_JSON, "not a JSON object") from None
    if not isinstance(request, dict) or not isinstance(request.get("op"), str):
        raise BadRequest(wire.BAD_REQUEST, "a request is an object with an op")
    name = request.pop("op")
    if name not in writer_ops.OPS:
        raise BadRequest(wire.UNKNOWN_OP, "no such op")
    try:
        check(request, writer_ops.OPS[name][0], name)
    except BadRequest as exc:
        raise BadRequest(exc.code, exc.reason, name) from None
    return name, request


class WriterServer:
    def __init__(self, stores: writer_ops.Stores, path: Path, crawler_uid: int, group_gid: int):
        self.stores = stores
        self.path = path
        self.crawler_uid = crawler_uid
        self.group_gid = group_gid
        # One op at a time: each is a few statements, and none interleaves with another's reads and writes.
        self.lock = asyncio.Lock()
        self.listener: socket.socket | None = None
        self.tasks: set[asyncio.Task] = set()

    def bind(self) -> None:
        if self.path.is_socket():
            self.path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        os.chown(self.path, -1, self.group_gid)
        os.chmod(self.path, SOCKET_MODE)
        listener.listen()
        listener.setblocking(False)
        self.listener = listener

    async def serve_forever(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            conn, _ = await loop.sock_accept(self.listener)
            # Before any read: a peer other than the crawler, root included, is closed unanswered.
            uid = peer_uid(conn)
            if not admitted(uid, self.crawler_uid):
                log.warning("writer refused a connection from uid %d", uid)
                conn.close()
                continue
            task = asyncio.create_task(self.serve(conn))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def serve(self, conn: socket.socket) -> None:
        reader, writer = await asyncio.open_unix_connection(sock=conn, limit=wire.LINE_CAP)
        try:
            while True:
                try:
                    line = await reader.readuntil(b"\n")
                except asyncio.IncompleteReadError:
                    break
                except asyncio.LimitOverrunError:
                    line = None
                reply = await self.answer(line)
                writer.write(wire.encode(reply))
                await writer.drain()
                if not reply["ok"] and reply["error"] in wire.CLOSING:
                    break
        except ConnectionError:
            pass
        finally:
            writer.close()

    async def answer(self, line: bytes | None) -> dict:
        """The reply to one line; None is a line past the cap, never read whole."""
        started = time.monotonic()
        name, outcome = "-", "ok"
        try:
            if line is None:
                raise BadRequest(wire.OVERSIZE, f"a line is at most {wire.LINE_CAP} bytes")
            name, request = parse(line)
            async with self.lock:
                reply = wire.answer(await writer_ops.OPS[name][1](self.stores, request))
        except BadRequest as exc:
            name, outcome, reply = exc.op, exc.code, wire.error(exc.code, exc.reason)
        except RefusedWrite as exc:
            # RefusedWrite's reasons are fixed text; none carries any of the payload.
            outcome, reply = wire.REFUSED, wire.error(wire.REFUSED, str(exc))
        except RefusedChange as exc:
            outcome, reply = wire.NOT_CHANGED, wire.error(wire.NOT_CHANGED, str(exc))
        except Exception as exc:
            # Only the type: a message can carry a path or a host.
            outcome, reply = wire.INTERNAL, wire.error(wire.INTERNAL, type(exc).__name__)
        size = wire.LINE_CAP if line is None else len(line)
        log.info("writer op=%s outcome=%s bytes=%d elapsed=%.3fs", name, outcome, size, time.monotonic() - started)
        return reply

    async def close(self) -> None:
        if self.listener is not None:
            self.listener.close()
            self.path.unlink(missing_ok=True)
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


def refusal(uid: int, user: str) -> str | None:
    if uid == 0:
        return "refusing to run as root"
    if user == CRAWLER:
        return "the writer runs as the analyst, never as the crawler it serves"
    return None


async def run(args: argparse.Namespace) -> None:
    stores = await writer_ops.Stores.open(args.data_dir, args.configs_dir, args.crawler_user,
                                          args.record_retention_days, args.snapshot_retention_days)
    server = WriterServer(stores, args.socket, pwd.getpwnam(args.crawler_user).pw_uid,
                          grp.getgrnam(args.socket_group).gr_gid)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopping.set)
    try:
        server.bind()
        log.info("writer listening")
        serving = asyncio.create_task(server.serve_forever())
        await stopping.wait()
        serving.cancel()
    finally:
        await server.close()
        await stores.close()
    log.info("writer stopped")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="onioncollect.writer")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--configs-dir", type=Path, required=True)
    parser.add_argument("--socket", type=Path, default=SOCKET)
    parser.add_argument("--crawler-user", default=CRAWLER)
    parser.add_argument("--socket-group", default=SOCKET_GROUP)
    parser.add_argument("--record-retention-days", type=int, default=lifecycle.RECORD_RETENTION_DAYS)
    parser.add_argument("--snapshot-retention-days", type=int, default=lifecycle.SNAPSHOT_RETENTION_DAYS)
    args = parser.parse_args(argv)
    uid = os.geteuid()
    if why := refusal(uid, pwd.getpwuid(uid).pw_name):
        raise SystemExit(f"onioncollect: {why}")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, stream=sys.stderr)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
