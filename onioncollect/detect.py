import re
from dataclasses import dataclass

LOCAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
MAX_LOCAL = 64
DOMAIN = re.compile(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])")
DOMAIN_WINDOW = 300
# A dump writes "a@b.c:pw", "a@b.c : pw" or "a@b.c\t|\tpw". A spaced pair must end its line (or meet a tag),
# since contact prose puts more words after a spaced separator ("bob@acme.com | PGP key below").
SEPARATOR = re.compile(r"([ \t]{0,4})[:;|]([ \t]{0,4})")
SEPARATOR_WINDOW = 9
LINE_END = re.compile(r"[ \t]{0,4}(?:\r?\n|<|\Z)")
# Stops at a <br> tag, so entries a dump joins with <br> on one line stay separate pairs.
PASSWORD = re.compile(r"(?:(?!<[bB][rR]\b)\S){1,128}")
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
    # Highest priority first. A span overlapping one already taken keeps only its uncovered parts: dropping
    # it whole would leave whatever runs past the earlier span in the text, and a password tail does not trip
    # this again when the storage layer reruns it. A cut part has no whole key, so key_end = start (no hash).
    candidates = [*addresses(text), *user_pairs(text), *cards(text), *national_ids(text), *tokens(text)]
    taken = bytearray(len(text))
    spans = []
    for span in candidates:
        cursor = span.start
        while cursor < span.end:
            free = taken.find(0, cursor, span.end)
            if free == -1:
                break
            stop = taken.find(1, free, span.end)
            stop = span.end if stop == -1 else stop
            taken[free:stop] = b"\x01" * (stop - free)
            whole = free == span.start and stop == span.end
            spans.append(span if whole else Span(free, stop, span.kind, free))
            cursor = stop
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
            separator = SEPARATOR.match(text, end, end + SEPARATOR_WINDOW)
            password = separator and PASSWORD.match(text, separator.end(), separator.end() + 128)
            if password and (separator.group(1) or separator.group(2)) and not LINE_END.match(text, password.end()):
                password = None
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
