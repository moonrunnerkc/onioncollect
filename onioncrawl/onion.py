import base64
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

ONION_SUFFIX = re.compile(r"\.onion", re.IGNORECASE)
LABEL_LENGTH = 56
V3_HOST = re.compile(r"[a-z2-7]{56}\.onion")
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


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def find_onions_in_text(text: str) -> set[str]:
    # Look back from each ".onion" instead of trying a 56-character match at every position: on a hostile
    # 2 MB run of letters the regex form costs 56 steps a character in one C call that holds the GIL.
    # Validate before lowercasing, since lower() maps some non-ASCII letters onto ASCII ones.
    labels = {text[max(match.start() - LABEL_LENGTH, 0):match.start()] for match in ONION_SUFFIX.finditer(text)}
    return {f"{label.lower()}.onion" for label in labels if is_v3_onion(f"{label}.onion")}
