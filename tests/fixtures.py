from onioncrawl import safety
from onioncrawl.config import Settings
from tests.test_onion import build_address

# Throwaway patterns and a generated host. The operator's two safety files never enter the repo.
LISTED = build_address(bytes([0xEE] * 32), 3)
PATTERNS = safety.parse_patterns(
    "child_exploitation \\bforbiddenterm\\b\ncredential_dump zzcredzz\ncard_number \\b\\d{4}(?:-?\\d{4}){3}\\b\n"
)


def throwaway_settings(**overrides) -> Settings:
    return Settings(**{"control_password": "x", "exclusions": frozenset({LISTED}), "safety_patterns": PATTERNS} | overrides)
