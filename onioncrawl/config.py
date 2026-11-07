import dataclasses
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

TOR_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"


def port_is_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


@dataclass(frozen=True)
class Settings:
    control_password: str = field(repr=False)
    tor_instances: tuple[tuple[int, int], ...] = tuple((10050 + n, 11050 + n) for n in range(1, 7))
    workers_per_instance: int = 3
    per_host_concurrency: int = 2
    request_timeout: float = 45.0
    max_body_bytes: int = 2_000_000
    max_retries: int = 3
    dead_after_failures: int = 5
    max_depth: int = 6
    jitter_seconds: tuple[float, float] = (1.0, 4.0)
    recrawl_active_hours: int = 24
    recrawl_quiet_hours: int = 168
    retest_dead_hours: int = 168
    data_dir: Path = Path("./data")
    exclusions_file: Path = Path("./exclusions.txt")
    safety_patterns_file: Path = Path("./safety-patterns.txt")
    user_agent: str = TOR_BROWSER_UA

    @classmethod
    def load(cls, path: Path, port_check: Callable[[int], bool] = port_is_listening) -> "Settings":
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        password_file = raw.pop("control_password_file", None)
        if password_file is None:
            raise ValueError(f"{path}: control_password_file is required")
        known = {f.name for f in dataclasses.fields(cls)} - {"control_password"}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"{path}: unknown settings {sorted(unknown)}")
        if "tor_instances" in raw:
            raw["tor_instances"] = tuple((int(socks), int(control)) for socks, control in raw["tor_instances"])
        if "jitter_seconds" in raw:
            low, high = raw["jitter_seconds"]
            raw["jitter_seconds"] = (float(low), float(high))
        for key in ("data_dir", "exclusions_file", "safety_patterns_file"):
            if key in raw:
                raw[key] = Path(raw[key])
        settings = cls(control_password=read_password(Path(password_file)), **raw)
        dead = [port for pair in settings.tor_instances for port in pair if not port_check(port)]
        if dead:
            raise RuntimeError(f"Tor ports not listening on 127.0.0.1: {dead}")
        return settings


def read_password(path: Path) -> str:
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be mode 600")
    password = path.read_text().strip()
    if not password:
        raise ValueError(f"{path} is empty")
    return password
