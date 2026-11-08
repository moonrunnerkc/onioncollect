import re
from dataclasses import dataclass

LOCAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
MAX_LOCAL = 64
DOMAIN = re.compile(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])")
DOMAIN_WINDOW = 300
PAIR_SEPARATORS = (":", ";", "|")
PASSWORD = re.compile(r"\S{1,128}")
USER_PAIR = re.compile(r"^([\w.-]{3,64})[:;|](?!//)\S{4,128}$", re.MULTILINE)
CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?!\d)")
NATIONAL_IDS = (
    re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"),
    re.compile(r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"),
)
TOKEN_RUN = re.compile(r"[A-Za-z0-9_\-+/=.$]{24,}")
HEX = re.compile(r"[0-9a-fA-F]{32,}")
UPPER, LOWER, DIGIT = re.compile("[A-Z]"), re.compile("[a-z]"), re.compile("[0-9]")


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    # The part that identifies whose secret it is, hashed by the redaction gate. For a pair it stops
    # before the separator, so a password is never hashed: a keyed hash of one is a verifier.
    key_end: int


def find(text: str) -> list[Span]:
    # Highest priority first. A span overlapping one already taken is dropped; the storage layer reruns
    # this on what the redaction gate wrote, so anything a drop leaves exposed fails closed there.
    candidates = [*addresses(text), *user_pairs(text), *cards(text), *national_ids(text), *tokens(text)]
    taken = bytearray(len(text))
    spans = []
    for span in candidates:
        if taken.find(1, span.start, span.end) == -1:
            taken[span.start:span.end] = b"\x01" * (span.end - span.start)
            spans.append(span)
    return sorted(spans, key=lambda span: span.start)


def contains_secret(text: str) -> bool:
    return bool(find(text))


def addresses(text: str) -> list[Span]:
    # Anchored on each "@" and bounded both ways. A regex that starts its local part anywhere goes
    # quadratic on a long run of address characters, and this runs on hostile 2 MB bodies.
    found = []
    at = text.find("@")
    while at != -1:
        start = at
        while start > 0 and at - start < MAX_LOCAL and text[start - 1] in LOCAL_CHARS:
            start -= 1
        domain = DOMAIN.match(text, at + 1, at + 1 + DOMAIN_WINDOW) if start < at else None
        if domain:
            end = domain.end()
            password = PASSWORD.match(text, end + 1, end + 129) if text[end:end + 1] in PAIR_SEPARATORS else None
            if password:
                found.append(Span(start, password.end(), "email_password", end))
            else:
                found.append(Span(start, end, "email", end))
        at = text.find("@", at + 1)
    return found


def user_pairs(text: str) -> list[Span]:
    return [Span(m.start(), m.end(), "user_password", m.end(1)) for m in USER_PAIR.finditer(text)]


def cards(text: str) -> list[Span]:
    return [Span(m.start(), m.end(), "card", m.end()) for m in CARD.finditer(text) if luhn_valid(m.group())]


def national_ids(text: str) -> list[Span]:
    return [Span(m.start(), m.end(), "national_id", m.end()) for pattern in NATIONAL_IDS for m in pattern.finditer(text)]


def tokens(text: str) -> list[Span]:
    found = []
    for m in TOKEN_RUN.finditer(text):
        run = m.group()
        if HEX.fullmatch(run) or (UPPER.search(run) and LOWER.search(run) and DIGIT.search(run)):
            found.append(Span(m.start(), m.end(), "token", m.end()))
    return found


def luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0
