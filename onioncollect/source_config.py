import re
import tomllib
from dataclasses import dataclass
from datetime import timedelta

from selectolax.lexbor import LexborHTMLParser

from onioncollect import detect, lifecycle, onion

SCHEMES = ("http", "https")
CADENCE = re.compile(r"(\d+)([mhd])")
CADENCE_UNITS = {"m": "minutes", "h": "hours", "d": "days"}
MIN_CADENCE = timedelta(minutes=30)
MAX_PAGES = 50
ATTRIBUTE = re.compile(r"[A-Za-z_:][-A-Za-z0-9_:.]*")
FIELD_NAME = re.compile(r"[a-z_][a-z0-9_]{0,31}")
LINK_ATTRIBUTES = ("href", "src")
TOP_KEYS = {"id", "hosts", "category", "cadence", "scheme", "seeds", "pagination", "listing", "detail", "expect", "auth",
            "host_prefix"}
REQUIRED = ("id", "hosts", "category", "cadence", "seeds", "listing", "expect", "auth")
# The one name a source's site may be asked under instead of its bare address. The host set, approval, exclusions
# and circuit isolation never see it.
HOST_PREFIX = "www"
PROBE = LexborHTMLParser("<html><body></body></html>")
# Section 15. The one source that may log in: the self-hosted onion the operator owns. A constant in code, so
# adding to it is a reviewed change; AuthContainmentTest pins its contents.
AUTH_ALLOWLIST = frozenset({"testonion"})
FORM_SESSION_KEYS = {"type", "login_path", "username_field", "password_field", "success_selector", "credential_ref"}
FORM_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
CREDENTIAL_KEY = re.compile(r"user|login|pass|secret|token|cookie|session|credential", re.IGNORECASE)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class FormSession:
    login_path: str
    username_field: str
    password_field: str
    success_selector: str
    # A file name under settings.credentials_dir, never a credential.
    credential_ref: str


@dataclass(frozen=True)
class Selector:
    css: str
    attribute: str | None

    @property
    def is_link(self) -> bool:
        return self.attribute in LINK_ATTRIBUTES


@dataclass(frozen=True)
class SourceConfig:
    id: str
    hosts: tuple[str, ...]
    category: str
    cadence: timedelta
    scheme: str
    seeds: tuple[str, ...]
    next_page: Selector | None
    max_pages: int
    item: str
    fields: dict[str, Selector]
    follow: str | None
    detail_fields: dict[str, Selector]
    min_items_per_page: int
    required_fields: tuple[str, ...]
    auth: FormSession | None = None
    host_prefix: str | None = None

    def path_for(self, url: str) -> str | None:
        """The path of a URL on one of this source's hosts, or None for anything else."""
        normalized = onion.normalize(onion.without_label(url, self.host_prefix, self.hosts))
        if normalized is None or onion.host_of(normalized) not in self.hosts:
            return None
        return onion.path_of(normalized)


def parse(text: str, expected_id: str) -> SourceConfig:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"not valid TOML: {exc}") from None
    only(raw, TOP_KEYS, "")
    missing = [key for key in REQUIRED if key not in raw]
    if missing:
        raise ConfigError(f"missing {', '.join(missing)}")
    if raw["id"] != expected_id:
        raise ConfigError(f"id {raw['id']!r} does not match the file name {expected_id!r}")
    if not lifecycle.SOURCE_ID.fullmatch(raw["id"]):
        raise ConfigError(f"id {raw['id']!r}: lowercase letters, digits and hyphens")
    if raw["category"] not in lifecycle.CATEGORIES:
        raise ConfigError(f"category {raw['category']!r} is not in the source policy")
    hosts = parse_hosts(raw["hosts"])
    scheme = raw.get("scheme", "http")
    if scheme not in SCHEMES:
        raise ConfigError(f"scheme must be one of {', '.join(SCHEMES)}")
    auth = parse_auth(raw["auth"], raw["id"], scheme, hosts)
    prefix = raw.get("host_prefix")
    if "host_prefix" in raw and (prefix != HOST_PREFIX or auth is not None):
        raise ConfigError(f'host_prefix can only be "{HOST_PREFIX}", and never on a form-session source')

    listing = table(raw, "listing", {"item", "fields"})
    if "item" not in listing or "fields" not in listing:
        raise ConfigError("listing needs item and fields")
    item = css(listing["item"], "listing.item")
    fields = parse_fields(listing["fields"], "listing.fields")
    pagination = table(raw, "pagination", {"next", "max_pages"}) if "pagination" in raw else {}
    detail = table(raw, "detail", {"follow", "fields"}) if "detail" in raw else {}
    follow = detail.get("follow")
    if detail and (follow not in fields or not fields[follow].is_link):
        raise ConfigError("detail.follow must name a listing field read from an href or src attribute")
    if detail and "fields" not in detail:
        raise ConfigError("detail needs fields")

    expect = table(raw, "expect", {"min_items_per_page", "required_fields"})
    minimum = expect.get("min_items_per_page")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        raise ConfigError("expect.min_items_per_page must be a whole number of at least 1")
    required = expect.get("required_fields")
    if not isinstance(required, list) or not required or not set(required) <= set(fields):
        raise ConfigError("expect.required_fields must list one or more listing fields")

    return SourceConfig(
        id=raw["id"], hosts=hosts, category=raw["category"], cadence=parse_cadence(raw["cadence"]), scheme=scheme,
        seeds=parse_seeds(raw["seeds"], scheme, hosts), next_page=link_selector(pagination, "next"),
        max_pages=parse_max_pages(pagination), item=item, fields=fields, follow=follow,
        detail_fields=parse_fields(detail["fields"], "detail.fields") if detail else {},
        min_items_per_page=minimum, required_fields=tuple(required), auth=auth, host_prefix=prefix,
    )


def only(raw: dict, allowed: set[str], where: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"unknown keys {sorted(unknown)}{' in ' + where if where else ''}")


def table(raw: dict, key: str, allowed: set[str]) -> dict:
    value = raw[key]
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a table")
    only(value, allowed, key)
    return value


def parse_hosts(value) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("hosts must list at least one host")
    hosts = []
    for host in value:
        if not isinstance(host, str) or not onion.is_v3_onion(host):
            raise ConfigError(f"hosts: {host!r} is not a v3 onion host")
        hosts.append(host.lower())
    return tuple(dict.fromkeys(hosts))


def parse_auth(auth, source_id: str, scheme: str, hosts: tuple[str, ...]) -> FormSession | None:
    if not isinstance(auth, dict):
        raise ConfigError("auth must be a table")
    inline = sorted(key for key in set(auth) - FORM_SESSION_KEYS if CREDENTIAL_KEY.search(key))
    if inline:
        raise ConfigError(f"auth: {inline} look like credentials; they live only in the file credential_ref names")
    if auth.get("type") == "none":
        only(auth, {"type"}, "auth")
        return None
    if auth.get("type") != "form-session":
        raise ConfigError('auth.type must be "none" or "form-session"')
    if source_id not in AUTH_ALLOWLIST:
        raise ConfigError(f"auth.type form-session is for AUTH_ALLOWLIST's self-hosted onion, not {source_id!r}")
    only(auth, FORM_SESSION_KEYS, "auth")
    for key in sorted(FORM_SESSION_KEYS):
        if not isinstance(auth.get(key), str) or detect.find(auth[key]):
            raise ConfigError(f"auth.{key} must be a string, and never a credential")
    fields = auth["username_field"], auth["password_field"]
    if not all(map(FORM_FIELD.fullmatch, fields)) or fields[0] == fields[1]:
        raise ConfigError("auth: username_field and password_field must be two different form field names")
    if not lifecycle.SOURCE_ID.fullmatch(auth["credential_ref"]):
        raise ConfigError("auth.credential_ref must be a file name in the credentials directory, shaped like an id")
    (login_path,) = parse_seeds([auth["login_path"]], scheme, hosts, "auth.login_path")
    return FormSession(login_path, *fields, css(auth["success_selector"], "auth.success_selector"), auth["credential_ref"])


def parse_cadence(value) -> timedelta:
    match = CADENCE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ConfigError("cadence must look like 30m, 6h or 2d")
    cadence = timedelta(**{CADENCE_UNITS[match.group(2)]: int(match.group(1))})
    if cadence < MIN_CADENCE:
        raise ConfigError(f"cadence must be at least {MIN_CADENCE.seconds // 60}m")
    return cadence


def parse_seeds(value, scheme: str, hosts: tuple[str, ...], where: str = "seeds") -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where} must list at least one path")
    seeds = []
    for seed in value:
        if not isinstance(seed, str) or not seed.startswith("/") or seed.startswith("//"):
            raise ConfigError(f"{where}: {seed!r} must be a path starting with /")
        normalized = onion.normalize(f"{scheme}://{hosts[0]}{seed}")
        if normalized is None:
            raise ConfigError(f"{where}: {seed!r} is not a usable path")
        seeds.append(onion.path_of(normalized))
    return tuple(dict.fromkeys(seeds))


def parse_max_pages(pagination: dict) -> int:
    if not pagination:
        return 1
    value = pagination.get("max_pages")
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_PAGES:
        raise ConfigError(f"pagination.max_pages must be between 1 and {MAX_PAGES}")
    return value


def parse_fields(value, where: str) -> dict[str, Selector]:
    if not isinstance(value, dict) or not value:
        raise ConfigError(f"{where} must map at least one field name to a selector")
    fields = {}
    for name, expression in value.items():
        if not FIELD_NAME.fullmatch(name):
            raise ConfigError(f"{where}: field name {name!r} must be lowercase snake_case")
        fields[name] = selector(expression, f"{where}.{name}")
    return fields


def link_selector(pagination: dict, key: str) -> Selector | None:
    if not pagination:
        return None
    if key not in pagination:
        raise ConfigError(f"pagination needs {key}")
    found = selector(pagination[key], f"pagination.{key}")
    return found if found.attribute else Selector(found.css, "href")


def selector(expression, where: str) -> Selector:
    if not isinstance(expression, str):
        raise ConfigError(f"{where} must be a string")
    css_part, at, attribute = expression.rpartition("@") if "@" in expression else (expression, "", "")
    if at and not ATTRIBUTE.fullmatch(attribute):
        raise ConfigError(f"{where}: {attribute!r} is not an attribute name")
    return Selector(css(css_part, where), attribute or None)


def css(expression, where: str) -> str:
    # CSS only. XPath and anything else selectolax cannot compile is refused here, at load.
    if not isinstance(expression, str) or not expression.strip() or expression.lstrip().startswith("/"):
        raise ConfigError(f"{where} must be a CSS selector")
    try:
        PROBE.css(expression)
    except Exception:
        raise ConfigError(f"{where}: {expression!r} is not a CSS selector") from None
    return expression.strip()
