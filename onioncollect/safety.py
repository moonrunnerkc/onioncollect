import re

from onioncollect import onion

EXCLUDING = "child_exploitation"
# Credential and card patterns are handled by the redaction gate, so a pattern file still naming them is out of date.
MOVED_TO_REDACTION = ("credential_dump", "card_number")


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
        if category in MOVED_TO_REDACTION:
            raise ValueError(f"line {number}: {category} is handled by the redaction gate now; remove the line")
        if category != EXCLUDING or not expression.strip():
            raise ValueError(f"line {number}: expected '{EXCLUDING} <regex>'")
        try:
            patterns.append(re.compile(expression.strip(), re.IGNORECASE | re.MULTILINE))
        except re.error as exc:
            raise ValueError(f"line {number}: {exc}") from None
    return tuple(patterns)


def body_triggers_exclusion(text: str, patterns: tuple[re.Pattern, ...]) -> str | None:
    return EXCLUDING if any(pattern.search(text) for pattern in patterns) else None
