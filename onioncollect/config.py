import dataclasses
import os
import re
import socket
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from onioncollect import lifecycle, safety, source_config
from onioncollect.source_config import ConfigError, SourceConfig

CRAWL_FILE_KEYS = ("control_password_file", "safety_patterns_file")
FILE_KEYS = (*CRAWL_FILE_KEYS, "redaction_salt_file", "exclusions_file")
SECRET_FIELDS = {"control_password", "exclusions", "safety_patterns", "redaction_salt"}
PATH_FIELDS = ("data_dir", "configs_dir", "state_dir", "log_dir", "writer_socket", "leak_test_result", "credentials_dir")
CREDENTIAL_KEYS = ("username", "password")
MIN_SALT_CHARS = 32
TOR_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"


def port_is_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


@dataclass(frozen=True)
class Settings:
    redaction_salt: bytes = field(repr=False)
    control_password: str | None = field(default=None, repr=False)
    exclusions: frozenset[str] = field(default=frozenset(), repr=False)
    safety_patterns: tuple[re.Pattern, ...] = field(default=(), repr=False)
    tor_instances: tuple[tuple[int, int], ...] = tuple((10050 + n, 11050 + n) for n in range(1, 7))
    workers_per_instance: int = 3
    per_source_concurrency: int = 2
    request_timeout: float = 45.0
    max_body_bytes: int = 2_000_000
    max_retries: int = 3
    jitter_seconds: tuple[float, float] = (1.0, 4.0)
    record_retention_days: int = lifecycle.RECORD_RETENTION_DAYS
    snapshot_retention_days: int = lifecycle.SNAPSHOT_RETENTION_DAYS
    # The analyst's stores. The crawler never opens them: it writes through writer_socket.
    data_dir: Path = Path("./data")
    configs_dir: Path = Path("./configs")
    # The crawler's own: its frontier and run lock (state_dir), and the crawl log, which the analyst reads.
    state_dir: Path = Path("./state")
    log_dir: Path = Path("./log")
    writer_socket: Path = Path("/run/onioncollect/writer.sock")
    # Written by `make leak-test` as root in the guest; golive reads it for check 3.
    leak_test_result: Path = Path("/var/lib/onioncollect/leak-test.json")
    # Section 15's secrets files, one per form-session source, owned by the crawler and mode 600.
    credentials_dir: Path = Path("/etc/onioncollect")
    user_agent: str = TOR_BROWSER_UA

    @classmethod
    def load(cls, path: Path, crawl: bool = False, reader: bool = False,
             port_check: Callable[[int], bool] = port_is_listening) -> "Settings":
        # `crawl` is the crawler user's view: the salt, Tor credentials and the safety patterns are required and
        # the Tor ports must answer. The analyst runs everything else and never holds the salt or the control
        # password. Both load the exclusion list: the fetcher refuses its hosts and triage refuses to approve them.
        # A `reader` opens the stores read-only and reads no file but this one.
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        files = {key: raw.pop(key, None) for key in FILE_KEYS}
        if reader:
            return cls(redaction_salt=b"", **cls.plain(path, raw))
        required = ("exclusions_file", *(("redaction_salt_file", *CRAWL_FILE_KEYS) if crawl else ()))
        missing = [key for key in required if files[key] is None]
        if missing:
            raise ValueError(f"{path}: {', '.join(missing)} required")
        raw = cls.plain(path, raw)
        raw["exclusions"] = read_safety_file(Path(files["exclusions_file"]), safety.parse_exclusions)
        salt = ""
        if crawl:
            salt = read_secret(Path(files["redaction_salt_file"]))
            if len(salt) < MIN_SALT_CHARS:
                raise ValueError(f"{files['redaction_salt_file']}: at least {MIN_SALT_CHARS} characters of salt")
            raw |= {
                "control_password": read_secret(Path(files["control_password_file"])),
                "safety_patterns": read_safety_file(Path(files["safety_patterns_file"]), safety.parse_patterns),
            }
        settings = cls(redaction_salt=salt.encode(), **raw)
        dead = [port for pair in settings.tor_instances for port in pair if crawl and not port_check(port)]
        if dead:
            raise RuntimeError(f"Tor ports not listening on 127.0.0.1: {dead}")
        return settings

    @classmethod
    def plain(cls, path: Path, raw: dict) -> dict:
        """The settings that are values, not secret files, typed."""
        unknown = set(raw) - ({f.name for f in dataclasses.fields(cls)} - SECRET_FIELDS)
        if unknown:
            raise ValueError(f"{path}: unknown settings {sorted(unknown)}")
        if "tor_instances" in raw:
            raw["tor_instances"] = tuple((int(socks), int(control)) for socks, control in raw["tor_instances"])
        if "jitter_seconds" in raw:
            low, high = raw["jitter_seconds"]
            raw["jitter_seconds"] = (float(low), float(high))
        for key in PATH_FIELDS:
            if key in raw:
                raw[key] = Path(raw[key])
        return raw


def read_secret(path: Path) -> str:
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be mode 600")
    secret = path.read_text().strip()
    if not secret:
        raise ValueError(f"{path} is empty")
    return secret


@dataclass(frozen=True)
class Credential:
    username: str = field(repr=False)
    password: str = field(repr=False)


def load_credential(settings: Settings, source_id: str, ref: str) -> Credential:
    """The file a form-session config's credential_ref names: one username= and one password= line, a regular
    file owned by this user and readable by nobody else, outside the configs and the data dir. Errors name the
    file and never a value. A value that also appears in the source's config text is refused as inline."""
    path = settings.credentials_dir / f"{ref}.env"
    for inside in (settings.configs_dir, settings.data_dir):
        if path.resolve().is_relative_to(inside.resolve()):
            raise PermissionError(f"{path} is under {inside}; credentials live outside the configs and the data")
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_mode & 0o077 or status.st_uid != os.geteuid():
        raise PermissionError(f"{path} must be a regular file owned by this user, mode 600")
    pairs = [line.partition("=") for line in path.read_text().splitlines() if line.strip()]
    values = {key.strip(): value for key, _, value in pairs}
    if sorted(key.strip() for key, _, _ in pairs) != sorted(CREDENTIAL_KEYS) or not all(values.values()):
        raise ValueError(f"{path}: one username= line and one password= line, nothing else")
    if any(value in config_path(settings.configs_dir, source_id).read_text() for value in values.values()):
        raise ValueError(f"{config_path(settings.configs_dir, source_id)} holds a credential inline")
    return Credential(**values)


def read_safety_file(path: Path, parse: Callable[[str], frozenset | tuple]) -> frozenset | tuple:
    try:
        parsed = parse(path.read_text())
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None
    if not parsed:
        raise ValueError(f"{path}: no entries, and the crawler never runs unfiltered")
    return parsed



def config_path(directory: Path, source_id: str) -> Path:
    return directory / f"{source_id}.toml"


def write_config(directory: Path, source_id: str, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = config_path(directory, source_id)
    temp = path.with_suffix(".toml.tmp")
    temp.write_text(text)
    # Group-readable whatever the umask: in the guest the configs dir's group is the crawler's, which reads them.
    temp.chmod(0o640)
    os.replace(temp, path)
    return path


def load_config(directory: Path, source_id: str) -> SourceConfig:
    path = config_path(directory, source_id)
    try:
        return source_config.parse(path.read_text(), source_id)
    except FileNotFoundError:
        raise ConfigError(f"{path}: no config file") from None
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from None


def load_configs(directory: Path, source_ids) -> tuple[dict[str, SourceConfig], dict[str, str]]:
    """Each named source's config, or the reason it has none. One bad file never stops the others."""
    configs, errors = {}, {}
    for source_id in source_ids:
        try:
            configs[source_id] = load_config(directory, source_id)
        except ConfigError as exc:
            errors[source_id] = str(exc)
    return configs, errors
