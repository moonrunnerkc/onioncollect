# What collecting from benign onion services showed

Every number, excerpt and table below comes from the guest through `make writeup-capture`. Until it is pasted in,
its place holds a marker, and `make writeup-check` fails while any marker is left.

## The collection

Sources live at the time of writing: 4 live, 0 degraded (captured 2026-11-11 00:46 UTC): software-infrastructure 2,
journalism-publishing 1, self-hosted 1. Two more are approved and not yet live, and three are disabled.

Candidates found by discovery, and what triage did with them: 0 candidates waiting, 9 sources approved at some
point (4 live, 2 approved, 3 disabled) and 2 hosts declined. The two declines, from `sources-export.jsonl` with the
address left out:

```
{"kind": "host", "state": "declined", "found_on": "bbc-news", "first_seen": "2026-11-10 21:59:40.796", "decided_at": "2026-11-11 00:36:29.720", "decided_by": "analyst", "reason": "operator could not be verified from the publisher's own pages (decided by the build agent under the operator's written rules, 2026-11-10)"}
{"kind": "host", "state": "declined", "found_on": "request: SecureDrop directory entry for The New York Times", "first_seen": "2026-11-11 00:36:29.819", "decided_at": "2026-11-11 00:36:29.918", "decided_by": "analyst", "reason": "submission form only, nothing to collect, and a tip intake should not be polled (decided by the build agent under the operator's written rules, 2026-11-10)"}
```

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

What it showed: one run so far (captured 2026-11-11 00:46 UTC), from `health runs testonion`:

```
run    started           pages failed reached status  mean   max  items complete  hit  new redacted refused
3      2026-11-10 21:17      8      0   8/8      200   2.2   6.1      6        6  1.00    6        0       0
```

The log audit after it counted 1 session line among 324 log lines, none of unknown shape, and checked the credential:

```
credential values checked against the logs and every file under the data dir: 2, found: 0
visited paths, queries and record text checked against the logs: 274, found: 0
```

## Go-live

bbc-news, from `golive-bbc-news.txt` (captured 2026-11-11 00:46 UTC). The failing run: the seed answered, and the listing selector
matched nothing.

```
golive bbc-news at 2026-11-10 21:59: failed
PASS  state is approved (found approved)
PASS  hosts: 1 valid v3, all approved for this source
PASS  policy: journalism-publishing, reviewer note on file
PASS  leak tests: all 4 passed 0 h ago, run by unit
PASS  reachability: 2 of 2 instances
PASS  seed 1: status 200
FAIL  seed 1: 0 complete items of 10 expected, hit rate 0.00, redaction events 0
```

What was changed: the onion answers with the publisher's co.uk layout, and the selector had been written for the
.com one. The config's `item`, `headline` and `summary` selectors now match both, and a card whose link carries a
query string is left out (`configs/bbc-news.toml`). The passing run:

```
golive bbc-news at 2026-11-11 00:24: passed
PASS  state is approved (found approved)
PASS  hosts: 1 valid v3, all approved for this source
PASS  policy: journalism-publishing, reviewer note on file
PASS  leak tests: all 4 passed 1 h ago, run by unit
PASS  reachability: 2 of 2 instances
PASS  seed 1: status 200
PASS  seed 1: 53 complete items of 10 expected, hit rate 0.70, redaction events 0
PASS  mirror: no other source matches
PASS  baseline: 1 snapshots written, bbc-news is live
```

Two runs between these failed for other reasons and are kept in the same file: one reachability timeout, and one
with 4 redaction events from links with tracking parameters, which the last selector change removed.

## What I would do next

[PASTE: your own conclusions, once the numbers above are in]
