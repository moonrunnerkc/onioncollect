from datetime import datetime, timedelta

PERMANENT_ERRORS = {"redirect", "not_text", "gated", "not_approved", "not_source_host", "excluded", "bad_path",
                    "parse_refused", "excluded_body", "auth_refused", "auth_rejected", "credential_unreadable"}
FLAKY_ERRORS = {"timeout", "tor_unreachable"}
QUICK_RETRY_RUNS = 3
QUICK_RETRY_DIVISOR = 4
MIN_RETRY = timedelta(minutes=30)
SLOWED_MULTIPLIER = 2
ROTATE_BELOW = 0.5


def retry_cost(error: str) -> int:
    return 1 if error in FLAKY_ERRORS else 2


def next_due_for_failure(retries: int, error: str, max_retries: int, now: datetime) -> datetime | None:
    if error in PERMANENT_ERRORS or retries >= max_retries:
        return None
    return now + timedelta(minutes=2 ** retries)


def next_run(cadence: timedelta, failed_runs: int, run_failed: bool, now: datetime) -> datetime:
    # Section 9's health multiplier: a source whose run fetched nothing is retried sooner for a few
    # runs, then slowed down. `failed_runs` counts the failed runs before this one.
    if not run_failed:
        return now + cadence
    if failed_runs + 1 <= QUICK_RETRY_RUNS:
        return now + max(cadence / QUICK_RETRY_DIVISOR, MIN_RETRY)
    return now + cadence * SLOWED_MULTIPLIER


def should_rotate(error: str, instance) -> bool:
    return error == "tor_unreachable" and instance.success_rate() < ROTATE_BELOW
