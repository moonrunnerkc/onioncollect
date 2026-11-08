# What collecting from benign onion services showed

Every number, excerpt and table below comes from the guest through `make writeup-capture`. Until it is pasted in,
its place holds a marker, and `make writeup-check` fails while any marker is left.

## The collection

Sources live at the time of writing: [PASTE: count of live and degraded sources by category, from sources-export.jsonl]

Candidates found by discovery, and what triage did with them: [PASTE: candidate, approved and declined counts, and
two declines with their reasons]

Collection window: [PASTE: first and last run dates, and the number of runs, from health runs]

## Mirror churn

How it was measured: a sibling probe fetches the first seed of every non-active host of a live source once a day
and records only whether it answered. Mirrors are matched by 64-bit simhash fingerprints of the seed pages, 8 bits
or fewer apart on both content and structure, and a host joins another source's set only by a human decision.

What it showed: [PASTE: hosts per cluster, how many changed address or went dark in the window, and the longest
outage of an active host]

The mirror swap: [PASTE: the health item, its disposition and the config diff, if one happened]

## Layout drift

How it was measured: each run records per-field hit rates against the source's config, and `config test` replays
the extractor against the latest snapshot and the go-live baseline without fetching.

What it showed: [PASTE: hit rate over time for two sources, from health runs]

The break and the fix: [PASTE: the health item that went from degraded to fixed, the field that was lost, and the
selector diff]

## Circuit health

How it was measured: each Tor instance's success rate over its recent fetches, logged with its rotations, and per
page timings and error names in the page metrics.

What it showed: [PASTE: per-instance success rates and rotation counts from tor-lines.txt]

[PASTE: share of fetches that timed out or found Tor unreachable, and median and worst page times]

## Authenticated collection, on a service I own

The one login is to an onion service the operator hosts on its own VM, with the operator's own credential,
bounded by a containment test that fails the build if a request other than a GET, a request body, a cookie or a
login appears anywhere outside the three-method auth step.

What it showed: [PASTE: testonion's runs, the session start lines and the log audit's credential check]

## Go-live

[PASTE: one source's golive output, the failing check, what was changed, and the passing run]

## What I would do next

[PASTE: your own conclusions, once the numbers above are in]
