"""Section 13's queue entry rules and priorities. A run's numbers in, the items it raises out."""
from dataclasses import dataclass, field

from onioncollect import scheduler

UNREACHABLE, BELOW_EXPECTATION, REQUIRED_FIELD_LOST = "unreachable", "below-expectation", "required-field-lost"
PARSE_REFUSED, REDACTION = "parse-refused", "redaction"
KINDS = (REDACTION, UNREACHABLE, REQUIRED_FIELD_LOST, BELOW_EXPECTATION, PARSE_REFUSED)

FIXED, MIRROR_SWAPPED, DISABLED, WATCHING = "fixed", "mirror-swapped", "disabled", "watching"
# The note on items a clean golive closes as fixed.
PASSED_GOLIVE = "passed go-live"
DISPOSITIONS = (FIXED, MIRROR_SWAPPED, DISABLED, WATCHING)

# The shortfall formula tops out at 100, so a redaction outranks every other item whatever its source:
# a source publishing secret-shaped text may not belong in the approved set at all.
REDACTION_PRIORITY = 1000
MAX_PRIORITY = 100
CATEGORY_WEIGHT = {
    "journalism-publishing": 1.0,
    "privacy-services": 0.8,
    "software-infrastructure": 0.6,
    "directories": 0.4,
    "self-hosted": 0.2,
}


@dataclass(frozen=True)
class RunSummary:
    pages: int
    failed_runs: int
    listing_pages: int
    items: int
    incomplete: int
    parse_refused: int
    last_error: str | None = None
    field_hits: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    kind: str
    priority: int
    detail: str


def priority(kind: str, category: str, shortfall: float) -> int:
    if kind == REDACTION:
        return REDACTION_PRIORITY
    return max(1, round(MAX_PRIORITY * CATEGORY_WEIGHT[category] * min(max(shortfall, 0.0), 1.0)))


def redaction(detail: str) -> Finding:
    return Finding(REDACTION, REDACTION_PRIORITY, detail)


def assess(run: RunSummary, min_items: int, required: tuple[str, ...], category: str) -> list[Finding]:
    """Every item one finished run raises. `failed_runs` counts this run if it fetched nothing."""
    found = []

    def add(kind: str, shortfall: float, detail: str) -> None:
        found.append(Finding(kind, priority(kind, category, shortfall), detail))

    if run.parse_refused:
        add(PARSE_REFUSED, run.parse_refused / (run.pages + run.parse_refused),
            f"{run.parse_refused} pages over the tag cap, not parsed")
    elif run.pages == 0 and run.failed_runs > scheduler.QUICK_RETRY_RUNS:
        # The scheduler has spent its quick retries; from here the source is slowed down and handed over.
        add(UNREACHABLE, 1.0, f"nothing fetched in {run.failed_runs} runs in a row"
                              + (f", last error {run.last_error}" if run.last_error else ""))
    if not run.listing_pages:
        return found
    lost = [name for name in required if run.items and not run.field_hits.get(name)]
    if lost:
        add(REQUIRED_FIELD_LOST, len(lost) / len(required), f"{', '.join(lost)} resolved on none of {run.items} items")
        return found
    complete, expected = run.items - run.incomplete, run.listing_pages * min_items
    if complete < expected:
        add(BELOW_EXPECTATION, 1 - complete / expected,
            f"{complete} complete items on {run.listing_pages} listing pages, expected {min_items} a page")
    return found
