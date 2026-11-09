import hashlib
import hmac
import re
from collections import Counter
from dataclasses import dataclass

from onioncollect import detect
from onioncollect.detect import Span

MAX_HASHES = 1_000
# A contact address on a benign page is still redacted, but one alone is not an event. Section 11 names
# bulk email lists, and an event raises a top-priority health item.
BULK_EMAILS = 5


@dataclass(frozen=True)
class Redacted:
    text: str
    counts: dict[str, int]
    hashes: tuple[str, ...]
    events: int


def redact(text: str, salt: bytes) -> Redacted:
    spans = detect.find(text)
    if not spans:
        return Redacted(text, {}, (), 0)
    out, cursor = [], 0
    for span in spans:
        out.append(text[cursor:span.start])
        out.append(f"[{span.kind}]")
        cursor = span.end
    out.append(text[cursor:])
    counts = Counter(span.kind for span in spans)
    # A span cut by an overlap has key_end == start: no whole key, so nothing to hash.
    hashes = sorted({keyed_hash(salt, key_of(span, text)) for span in spans if span.key_end > span.start})[:MAX_HASHES]
    emails = counts.get("email", 0)
    events = len(spans) - (emails if emails < BULK_EMAILS else 0)
    return Redacted("".join(out), dict(counts), tuple(hashes), events)


def redact_fields(fields: dict[str, str], salt: bytes) -> tuple[dict[str, str], Redacted]:
    """Every field through the gate. The summary carries the clean fields' combined counts and hashes."""
    clean, counts, hashes, events = {}, Counter(), set(), 0
    for name, value in fields.items():
        done = redact(value, salt)
        clean[name] = done.text
        counts.update(done.counts)
        hashes.update(done.hashes)
        events += done.events
    return clean, Redacted("", dict(counts), tuple(sorted(hashes)[:MAX_HASHES]), events)


def key_of(span: Span, text: str) -> str:
    # "4111 1111 1111 1111" and "4111-1111-1111-1111" are one card, and must be one hash. A pair's key
    # stops before the separator, so a password is never hashed: a keyed hash of one is a verifier.
    key = text[span.start:span.key_end]
    return re.sub(r"[\s-]", "", key) if span.kind in ("card", "national_id") else key


def keyed_hash(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.casefold().encode(), hashlib.sha256).hexdigest()
