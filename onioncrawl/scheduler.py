from datetime import datetime, timedelta

from onioncrawl.config import Settings
from onioncrawl.db import PageInfo, Task

PERMANENT_ERRORS = {"redirect_offsite", "redirect_excluded", "not_text", "not_onion"}
FLAKY_ERRORS = {"timeout", "tor_unreachable"}
QUIET_AFTER_UNCHANGED = 3
GATED_RECRAWL = timedelta(days=7)
DEAD_SPREAD = timedelta(hours=24)
ROTATE_BELOW = 0.5


def next_due_for_url(task: Task, info: PageInfo, changed: bool, settings: Settings, now: datetime) -> datetime:
    if info.gated:
        return now + GATED_RECRAWL
    active = timedelta(hours=settings.recrawl_active_hours)
    if changed:
        due = now + active
    elif task.unchanged_streak + 1 < QUIET_AFTER_UNCHANGED:
        due = now + 2 * active
    else:
        due = now + timedelta(hours=settings.recrawl_quiet_hours)
    return min(due, now + active) if task.depth == 0 else due


def retry_cost(error: str) -> int:
    return 1 if error in FLAKY_ERRORS else 2


def next_due_for_failure(task: Task, error: str, settings: Settings, now: datetime) -> datetime | None:
    if error in PERMANENT_ERRORS:
        return None
    retries = task.retries + retry_cost(error)
    if retries >= settings.max_retries:
        return None
    return now + timedelta(minutes=2 ** retries)


def host_is_dead(failures: list[datetime], settings: Settings) -> bool:
    return len(failures) >= settings.dead_after_failures and max(failures) - min(failures) >= DEAD_SPREAD


def retest_due(host_row, settings: Settings, now: datetime) -> bool:
    since = {"dead": host_row["last_down"], "gated": host_row["last_up"]}.get(host_row["state"])
    return since is not None and now - since >= timedelta(hours=settings.retest_dead_hours)


def should_rotate(error: str, instance) -> bool:
    return error == "tor_unreachable" and instance.success_rate() < ROTATE_BELOW
