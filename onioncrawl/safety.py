import re
from pathlib import Path

from onioncrawl import onion

# Checked in this order; the first category with a hit is the verdict.
CATEGORIES = ("child_exploitation", "credential_dump", "card_number")


def load_exclusions(path: Path) -> set[str]:
    hosts = set()
    for number, line in enumerate(path.read_text().splitlines(), 1):
        host = line.split("#", 1)[0].strip().lower()
        if not host:
            continue
        if not onion.is_v3_onion(host):
            raise ValueError(f"{path}:{number}: not a v3 onion host")
        hosts.add(host)
    return hosts


def is_excluded(host: str, exclusions: set[str]) -> bool:
    return host.lower() in exclusions


def load_patterns(path: Path) -> list[tuple[str, re.Pattern]]:
    patterns = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        category, _, expression = line.strip().partition(" ")
        if category not in CATEGORIES or not expression.strip():
            raise ValueError(f"{path}:{number}: expected '<category> <regex>' with category in {CATEGORIES}")
        patterns.append((category, re.compile(expression.strip(), re.IGNORECASE | re.MULTILINE)))
    missing = set(CATEGORIES) - {category for category, _ in patterns}
    if missing:
        raise ValueError(f"{path}: no patterns for {sorted(missing)}")
    return sorted(patterns, key=lambda entry: CATEGORIES.index(entry[0]))


def body_triggers_exclusion(text: str, patterns: list[tuple[str, re.Pattern]]) -> str | None:
    for category, pattern in patterns:
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
