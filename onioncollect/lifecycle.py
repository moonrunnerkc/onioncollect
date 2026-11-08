import re

# Host rows hold the two states a host has before it belongs to a source; source rows hold the rest.
CANDIDATE, DECLINED, MEMBER = "candidate", "declined", "member"
APPROVED, LIVE, DEGRADED, DISABLED = "approved", "live", "degraded", "disabled"
HOST_STATES = (CANDIDATE, DECLINED, MEMBER)
SOURCE_STATES = (APPROVED, LIVE, DEGRADED, DISABLED)

# What the scheduler may fetch, and what only `golive` may fetch. Nothing else is ever fetched.
COLLECTING = frozenset({LIVE, DEGRADED})
UNDER_TEST = frozenset({APPROVED})

# Section 3's approved categories. Leak sites, markets and account-only forums have no entry, so no
# approval can name them.
CATEGORIES = (
    "journalism-publishing",
    "software-infrastructure",
    "privacy-services",
    "directories",
    "self-hosted",
)

SOURCE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")

TRANSITIONS = {
    APPROVED: {LIVE, DISABLED},
    LIVE: {DEGRADED, DISABLED},
    DEGRADED: {LIVE, DISABLED},
    DISABLED: {APPROVED},
}


def check_approval(source_id: str, category: str, note: str) -> None:
    if not SOURCE_ID.fullmatch(source_id):
        raise ValueError(f"source id {source_id!r}: lowercase letters, digits and hyphens, 2 to 63 characters")
    if category not in CATEGORIES:
        raise ValueError(f"category {category!r} is not in the source policy: {', '.join(CATEGORIES)}")
    if not note.strip():
        raise ValueError("an approval needs a reviewer note")


def check_transition(current: str, target: str) -> None:
    if target not in TRANSITIONS.get(current, ()):
        raise ValueError(f"a source cannot go from {current} to {target}")
