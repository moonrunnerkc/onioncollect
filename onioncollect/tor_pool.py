import asyncio
import logging
import time
from collections import deque

import stem.connection
from stem import Signal, SocketError
from stem.control import Controller

from onioncollect.config import Settings

log = logging.getLogger(__name__)

WINDOW = 50
MIN_SAMPLES = 10
READY_TIMEOUT = 120.0
READY_POLL = 2.0
HEALTH_INTERVAL = 60.0
UNHEALTHY_BELOW = 0.3
ROTATE_COOLDOWN = 30.0
CONTROL_ERRORS = (SocketError, stem.connection.AuthenticationFailure)


class TorInstance:
    def __init__(self, socks_port: int, control_port: int, password: str):
        self.socks_port = socks_port
        self.control_port = control_port
        self._password = password
        self.controller: Controller | None = None
        self.outcomes: deque[bool] = deque(maxlen=WINDOW)
        self.last_rotation: float | None = None

    def connect(self) -> None:
        self.controller = Controller.from_port(address="127.0.0.1", port=self.control_port)
        self.controller.authenticate(password=self._password)

    def is_ready(self) -> bool:
        return self.controller.get_info("status/circuit-established", "0") == "1"

    def open_counts(self) -> tuple[int, int]:
        # Counted only: each status line names the target, and nothing here may print or log it.
        circuits = [line for line in self.controller.get_info("circuit-status", "").splitlines() if " BUILT " in line]
        return len(circuits), len(self.controller.get_info("stream-status", "").splitlines())

    def socks_url(self) -> str:
        return f"socks5://127.0.0.1:{self.socks_port}"

    def record(self, ok: bool) -> None:
        self.outcomes.append(ok)

    def success_rate(self) -> float:
        if len(self.outcomes) < MIN_SAMPLES:
            return 1.0
        return sum(self.outcomes) / len(self.outcomes)

    async def rotate(self) -> None:
        if not self.controller.is_newnym_available():
            await asyncio.sleep(self.controller.get_newnym_wait())
        self.controller.signal(Signal.NEWNYM)
        self.last_rotation = time.monotonic()
        log.info("tor %d: rotated circuits", self.socks_port)

    def close(self) -> None:
        if self.controller is not None:
            self.controller.close()


class TorPool:
    def __init__(self, settings: Settings):
        self.instances = [
            TorInstance(socks, control, settings.control_password) for socks, control in settings.tor_instances
        ]

    async def start(self) -> None:
        for instance in self.instances:
            instance.connect()
        deadline = time.monotonic() + READY_TIMEOUT
        waiting = list(self.instances)
        while waiting:
            waiting = [instance for instance in waiting if not instance.is_ready()]
            if not waiting or time.monotonic() >= deadline:
                break
            await asyncio.sleep(READY_POLL)
        for instance in waiting:
            log.warning("tor %d: no circuit after %.0f s, dropped from pool", instance.socks_port, READY_TIMEOUT)
            instance.close()
            self.instances.remove(instance)
        if not self.instances:
            raise RuntimeError("no Tor instance became ready")

    def assign(self, worker_id: int) -> TorInstance:
        return self.instances[worker_id % len(self.instances)]

    async def health_loop(self) -> None:
        while True:
            await asyncio.sleep(HEALTH_INTERVAL)
            for instance in self.instances:
                since = "never" if instance.last_rotation is None else f"{time.monotonic() - instance.last_rotation:.0f}s ago"
                log.info(
                    "tor %d: success %.2f over %d fetches, last rotation %s",
                    instance.socks_port, instance.success_rate(), len(instance.outcomes), since,
                )
                if instance.success_rate() < UNHEALTHY_BELOW:
                    await instance.rotate()

    async def rotate_for(self, instance: TorInstance) -> None:
        if instance.last_rotation is None or time.monotonic() - instance.last_rotation > ROTATE_COOLDOWN:
            await instance.rotate()

    def stop(self) -> None:
        for instance in self.instances:
            instance.close()
