import base64
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

V3_HOST = re.compile(r"[a-z2-7]{56}\.onion")
# The lookbehind keeps a longer base32 run from yielding its last 56 characters as a host.
ONION_IN_TEXT = re.compile(r"(?<![a-z2-7])[a-z2-7]{56}\.onion", re.IGNORECASE)
DEFAULT_PORTS = {"http": 80, "https": 443}


def is_v3_onion(host: str) -> bool:
    # isascii() first: str.lower() maps some non-ASCII letters (the Kelvin sign) onto ASCII ones.
    if not host.isascii():
        return False
    host = host.lower()
    # Requiring the suffix is deliberate: the guide's original snippet accepted a bare 56-char label.
    if not V3_HOST.fullmatch(host):
        return False
    raw = base64.b32decode(host.removesuffix(".onion").upper())
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34]
    expected = hashlib.sha3_256(b".onion checksum" + pubkey + bytes([version])).digest()[:2]
    return version == 3 and checksum == expected


def normalize(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in DEFAULT_PORTS or not is_v3_onion(host):
        return None
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def with_label(url: str, label: str | None) -> str:
    """A normalized URL with label put before its host: how a site that answers only under that name is asked."""
    return url.replace("://", f"://{label}.", 1) if label else url


def without_label(url: str, label: str | None, hosts: tuple[str, ...]) -> str:
    """The URL with label taken off its host, only when what is left is one of hosts. Anything else comes back
    as it was, for normalize to refuse: a label never makes another address, or a deeper name, the source's."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return url
    first, _, rest = (parts.hostname or "").lower().partition(".")
    if not label or first != label or rest not in hosts:
        return url
    return urlunsplit(parts._replace(netloc=rest if port is None else f"{rest}:{port}"))


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def find_onions_in_text(text: str) -> set[str]:
    return {host for host in (m.group().lower() for m in ONION_IN_TEXT.finditer(text)) if is_v3_onion(host)}


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.path or '/'}?{parts.query}" if parts.query else parts.path or "/"
