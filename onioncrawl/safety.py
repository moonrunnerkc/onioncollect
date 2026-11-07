import re

from onioncrawl import onion

# Checked in this order; the first category with a hit is the verdict.
CATEGORIES = ("child_exploitation", "credential_dump", "card_number")


def parse_exclusions(text: str) -> frozenset[str]:
    hosts = set()
    for number, line in enumerate(text.splitlines(), 1):
        host = line.split("#", 1)[0].strip().lower()
        if not host:
            continue
        if not onion.is_v3_onion(host):
            raise ValueError(f"line {number}: not a v3 onion host")
        hosts.add(host)
    return frozenset(hosts)


def is_excluded(host: str, exclusions) -> bool:
    return host.lower() in exclusions


def parse_patterns(text: str) -> tuple[re.Pattern, ...]:
    patterns = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        category, _, expression = line.strip().partition(" ")
        if category not in CATEGORIES or not expression.strip():
            raise ValueError(f"line {number}: expected '<category> <regex>' with category in {CATEGORIES}")
        # The category names the outermost group, which is always group 1, so the compiled pattern
        # carries its own category and Settings can hold plain patterns.
        try:
            patterns.append(re.compile(f"(?P<{category}>{expression.strip()})", re.IGNORECASE | re.MULTILINE))
        except re.error as exc:
            raise ValueError(f"line {number}: {exc}") from None
    missing = set(CATEGORIES) - {category_of(pattern) for pattern in patterns}
    if missing:
        raise ValueError(f"no patterns for {sorted(missing)}")
    return tuple(sorted(patterns, key=lambda pattern: CATEGORIES.index(category_of(pattern))))


def category_of(pattern: re.Pattern) -> str:
    return next(name for name, group in pattern.groupindex.items() if group == 1)


def body_triggers_exclusion(text: str, patterns: tuple[re.Pattern, ...]) -> str | None:
    for pattern in patterns:
        category = category_of(pattern)
        for match in pattern.finditer(text):
            if category != "card_number" or luhn_valid(match.group()):
                return category
    return None


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
