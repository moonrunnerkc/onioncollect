# Onion Collection Platform: Build Guide

## 1. What you're building

A darknet collection platform, scaled down to one operator, that runs lawfully end to end. It takes a source from candidate to live collection, extracts structured records from it over Tor, keeps those records in a searchable store, watches the health of every live source, and routes failures to a triage queue. The targets are benign public onion services only: news organizations' onion mirrors, SecureDrop instances, the Tor Project, Debian, Proton, DuckDuckGo, and the legitimate directories that list them. Nothing in the pipeline ever touches stolen data, because nothing in the approved source set hosts any.

Three ideas define the design, and every later section serves them:

1. Approved sources only. Discovery is real and runs continuously, but a discovered host is a candidate, not a target. Nothing is fetched until a human has reviewed it against the source policy and approved it. The approval gate is enforced in code.
2. Collection is the product. Each source gets a declarative config (seeds, selectors, pagination, cadence) that turns pages into structured records. Records persist, are indexed, and are searchable. Health of every config is measured on every run.
3. Operator safety is a hard boundary. All egress is Tor, enforced by the firewall, not by the code. A redaction gate runs before every write so that even an approved page can't put a credential or a person's data on disk.

The output is a running system you can point a hiring manager at: a source list with lifecycle states, configs with hit-rate history, a searchable index of extracted records, a health queue with dispositions, and a test suite that proves the boundaries hold.

This replaces the earlier breach-exposure-monitor plan. The Tor plumbing carries over intact. The feeds-first strategy, the client target list, and the match-gated storage are gone; they were designed for a product sold to clients, and this project is built to demonstrate collection capability instead.

## 2. Hard non-goals, enforced in code

These lines keep the project lawful without relying on discipline. Each is enforced by the code or the OS so a bug or a bad night can't cross them.

| Non-goal | How the code prevents it |
| --- | --- |
| Never fetch a host that isn't approved | The fetcher takes a source id, not a URL. It resolves the source, refuses any state other than `live` or `go-live-check`, and refuses any URL whose host isn't in that source's host set. Discovered links are written to the candidate table and nowhere else. |
| Never collect outside the benign-source policy | Approval is a CLI action that requires a policy category and a reviewer note. The policy categories are an enum; "leak site," "market," and "forum requiring an account you don't own" aren't in it. |
| Never download a dump or any non-text payload | Text-only Content-Type allowlist (`text/html`, `application/xhtml+xml`, `text/plain`), 2 MB read cap. Binaries and archives are refused before the body is read. |
| Never store a plaintext credential or PII | The redaction gate runs before any write. The storage layer rejects any payload that still trips the secret detector, as a second independent check. |
| Never validate, replay, or submit a credential to a third party | The only auth code path is bound to the self-hosted test onion in section 15. Any auth attempt against another host raises before a request is built. No form submission, no account creation, no messaging anywhere else in the codebase. |
| Never engage anyone | No posting, no messaging, no purchase. The system sends GET requests and, for the self-hosted onion only, one POST to its own login form. |
| Never leave Tor, never follow a clearnet link | Firewall drops all non-Tor egress from the crawler user; only validated v3 `.onion` hosts are ever fetched; redirects are recorded, not followed. |

Treat the approval gate and the redaction gate the way you treat the firewall: controls that make every other mistake survivable.

## 3. Source policy

One page, version-controlled, applied at triage. It's the rubric that decides what gets approved and it's the document you show when someone asks how you kept this lawful.

Approved categories:

- Journalism and publishing: onion mirrors operated by news organizations, their SecureDrop instances.
- Software and infrastructure: Tor Project, Debian and other distro mirrors, package archives, documentation sites.
- Privacy services with public onion front ends: mail providers, search engines, messaging projects.
- Directories and indexes whose purpose is listing the above.
- Your own hosted onion services (section 15).

Declined, always, with the reason recorded: anything selling or distributing data, credentials, or goods; forums or markets that require an account you don't own; anything whose primary content is other people's personal data; anything the reviewer can't categorize.

Retention: page snapshots 30 days, extracted records 180 days, health and uptime history indefinitely. A retention sweep runs nightly and is tested.

Nothing here is legal advice. Accessing public onion services is no different in kind from accessing public websites, but if this ever becomes a commercial service, have counsel review the policy and your handling procedures first.

## 4. Architecture overview

```
source list ──► scheduler ──► tor pool / fetcher ──► extractor ──► redaction gate ──► records DB + FTS index
    ▲                              │                      │
    │                              │                      └─► link discovery ──► candidate table ──► triage (human) ──► approve / decline
    │                              │
    └── go-live checks             └─► health metrics ──► health queue ──► disposition (fix / mirror swap / disable)
```

Component responsibilities:

- Source list: every known onion host with a lifecycle state (section 7), its config, its policy category, and its mirror cluster.
- Scheduler: picks which live sources are due, by cadence and by health, and hands source ids to workers.
- Tor pool and fetcher: carried over from the original plan (sections 5 and 9). Fetches only what a source id resolves to.
- Extractor: runs the source's config against the page, emits structured records and a selector hit-rate report.
- Redaction gate: strips credential- and PII-looking spans before anything is written.
- Records DB and FTS index: persistence plus full-text search over extracted records.
- Link discovery: pulls onion links out of fetched pages into the candidate table. Nothing else.
- Triage: a human reviews candidates against the policy, checks for mirrors, approves or declines.
- Health queue: failed or degraded sources, ordered by priority and age, with dispositions.
- Go-live checks: the gate between `approved` and `live`.

## 5. Operator safety (carried over)

Every anonymity control from the original plan stays. Accessing onion services exposes the operator's network position, and the point of this section is that the operator never has to think about it.

- Dedicated, full-disk-encrypted VM; two users (`crawler` for collection, `analyst` for triage, health, and search); snapshot after setup.
- Six to ten Tor instances via `tor-instance-create`, each `ClientOnly 1`, `SafeLogging 1`, `IsolateSOCKSAuth`, per-instance system user.
- The firewall kill-switch: iptables OUTPUT allows loopback, SSH replies, the Tor UIDs, and the network daemon's DHCP lease renewal (`systemd-network`, UDP 68 to 67, to the guest's own subnet only), then DROP; ip6tables OUTPUT policy DROP. The crawler user can't send a packet off the box. The DHCP rule exists because a dropped renewal makes the client fall back to a raw-socket broadcast that iptables never sees, which leak test 3 flags; letting the unicast renewal through keeps DHCP off the wire except as traffic to the local gateway, which test 3 already accepts.
- Pinned reproducible dependencies with hashes.
- Data directory on the encrypted disk, mode 700, owned by `analyst`; the crawler writes through a small local socket service so it never holds the DB file open. Analyst tooling never needs the crawler's circuits.

The full environment setup (sections 3.1 to 3.4 of the original plan) is unchanged.

## 6. Collection configs

This is the artifact a collections analyst produces daily, so it's the center of the codebase. One TOML file per source under `configs/`, version-controlled, validated against a schema on load. TOML rather than YAML because the standard library's `tomllib` reads it, which keeps the dependency count at five.

```toml
id = "tor-project-blog"
hosts = ["<56-char>.onion"]
category = "software-infrastructure"
cadence = "6h"
seeds = ["/blog/"]

[pagination]
next = "a.pagination-next"
max_pages = 5

[listing]
item = "article.post-preview"

[listing.fields]
title = "h2 a"
url = "h2 a@href"
published = "time@datetime"

[detail]
follow = "url"

[detail.fields]
body = "div.post-content"
author = "span.author"

[expect]
min_items_per_page = 3
required_fields = ["title", "url"]

[auth]
type = "none"
```

Rules the schema enforces:

- `hosts` must all pass `is_v3_onion`, and every seed and followed URL must resolve to one of them.
- Selectors are CSS with an optional `@attr` suffix. No XPath, no regex-on-HTML, no eval of any kind.
- `follow` may only reference a field extracted from the same host set. Off-host links go to discovery, never to the frontier.
- `expect` is what the go-live check and the health monitor measure against. A config without expectations can't go live.
- `auth.type` is `none` for every source except the self-hosted onion in section 15, and the loader rejects any other combination.

Keep the configs in data, not code. Adding, tuning, or disabling a source is a reviewed file change, not a deploy.

## 7. Source lifecycle and discovery

Every onion host the system has ever seen is a row in the source table with one of these states:

- `candidate`: discovered or requested, not yet reviewed. Never fetched.
- `approved`: reviewed against the policy, has a config, hasn't passed go-live checks. Fetched only by the go-live command.
- `live`: collecting on cadence.
- `degraded`: live but failing expectations; still collecting, in the health queue.
- `disabled`: taken out of rotation by a human, with a reason. Not fetched.
- `declined`: reviewed and rejected, with a policy reason. Never fetched, and re-discovery doesn't resurrect it.

Discovery runs on every fetched page: extract v3 onion hosts from links and text, drop anything already in the table, insert the rest as `candidate` with the referring source and first-seen time. That's the whole discovery feature. It never queues a fetch, never expands the frontier, never auto-approves. It exists so triage has a steady stream of real sourcing requests to work, which is the first responsibility in the posting.

Triage is a CLI session under the `analyst` user: show candidates by age, show where each was found, show its mirror cluster if any (section 8), approve with a category and note, or decline with a reason. The approve action also scaffolds a config file for the analyst to fill in.

## 8. Mirrors and duplicates

Legitimate onion services run multiple addresses, rotate them, and get listed under stale ones. Collections teams spend real time on this, so make it a first-class feature.

- Fingerprint every fetched page two ways: a content hash of normalized visible text, and a structure hash of the DOM shape (tag sequence with attributes stripped). Store both per page.
- Cluster hosts whose fingerprints match above a threshold across their seed pages. Two hosts in a cluster are mirrors of one logical source.
- At triage, show "candidate matches live source X" so the analyst can approve it as a mirror of X (adds it to X's host set) instead of as a new source.
- In the health queue, when a live source fails reachability, show the cluster's other hosts with their last-seen status and offer a mirror swap as a disposition.
- Dedup extracted records across a cluster by content hash so the index doesn't carry the same article from three addresses.

## 9. The fetcher and Tor pool (carried over)

Mechanically this is the original `tor_pool` / `fetcher` design. What carries over unchanged: the Tor pool with per-instance health and NEWNYM rotation; the anonymity-critical client config (SOCKS5 with `rdns=True`, per-host SOCKS username for circuit isolation, `http2=False`, `follow_redirects=False`, `trust_env=False`, fixed Tor Browser headers, cookies cleared in a `finally`); the 45 s budget, 2 MB cap, and Content-Type allowlist; WAL-mode SQLite frontier that survives crashes.

Two changes:

1. The fetcher's public interface takes a source id and a path, never a bare URL. It resolves the source, checks state, checks the host set, builds the URL, and only then opens a circuit. There is no code path that fetches an arbitrary URL.
2. Scheduling is cadence-driven with a health multiplier: a source that's failing is retried sooner for a bounded number of attempts, then handed to the health queue and slowed down. Uptime history is kept per host for mirror selection.

The `onion.py` validation gate stays exactly as speced; it's still the only thing that lets a host into the table at all:

```python
def is_v3_onion(host):
    label = host.lower().removesuffix(".onion")
    if len(label) != 56:
        return False
    try:
        raw = base64.b32decode(label.upper())
    except Exception:
        return False
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34]
    expected = hashlib.sha3_256(b".onion checksum" + pubkey + bytes([version])).digest()[:2]
    return version == 3 and checksum == expected
```

## 10. The extractor

Runs the source's config against a fetched page and produces two things: records and a hit-rate report.

- Records: one per matched `listing.item`, with each field resolved by its selector. Missing required fields mark the record incomplete; incomplete records are counted but not stored.
- Hit-rate report: items found vs `min_items_per_page`, fields resolved vs fields declared, per page. This is written to health metrics on every run and is how layout changes get caught before a source goes fully dark.
- `detail.follow` enqueues the referenced URL on the same source's frontier, host-checked, up to the configured depth.
- Parsing is `selectolax` or `lxml` over the in-memory body. Nothing about extraction touches disk until the redaction gate has run.

## 11. The redaction gate

Carried over from the earlier plan and repositioned as defense in depth. With a benign source set it should almost never fire, which is exactly why it has to be there: if it does fire, something about the source or the policy is wrong, and you want to know before the data is on disk.

- Every record field and every page snapshot passes through the detector before write. Detected spans (email:password and user:password pairs, long credential-shaped tokens, card-number patterns, national-ID patterns, bulk email lists) are replaced with a type tag, a count, and a salted hash.
- Any redaction event on a live source raises a health-queue item at top priority, because a source that's publishing credentials doesn't belong in the approved set.
- The storage layer runs the same detector independently and refuses any write that still trips it. Two detectors, one rule.
- Per-deployment salt, kept with the same care as the Tor control password.

## 12. Storage and search

Three stores, all under the `analyst` user on the encrypted disk.

- Source table (SQLite, WAL): hosts, state, category, config path, mirror cluster id, lifecycle timestamps, reviewer notes. Indexed by state and cluster.
- Records DB (SQLite, WAL) with an FTS5 virtual table over the text fields: one row per extracted record, keyed by source, content hash, first-seen and last-seen. Dedup across a mirror cluster by content hash. Retention clock per section 3.
- Snapshot store: redacted page bodies, content-addressed, 30-day retention, used for diffing a source against its last known-good layout when a config breaks.

Search is a CLI command and a small read-only local web UI under the `analyst` user: full-text query, filter by source, category, date range; results link to the source and the snapshot. This is the demo surface. It's a scaled-down version of what a collections product exists to feed.

## 13. Collection health queue

Every run writes metrics per source: reachability, status code, timing, selector hit rate, items extracted, redaction events. The health queue is a view over those metrics plus a dispositions table.

A source enters the queue when it fails reachability past the retry budget, falls below `min_items_per_page`, loses a required field across a run, or trips the redaction gate. Queue ordering is priority then age, where priority is derived from category weight and how far below expectation the source fell.

Dispositions, each recorded with a note: `fixed` (config updated, passed go-live again), `mirror-swapped` (host set changed to a cluster sibling), `disabled` (with reason), `watching` (snoozed for N runs). Dispositions are the audit trail of how collections were kept healthy, which is most of what the posting describes.

## 14. Go-live checks

A single command that gates a source from `approved` to `live`. It's the only thing other than the scheduler that can trigger a fetch, and it only fetches the source under test.

1. Host validation: every host in the config passes `is_v3_onion`.
2. Policy check: category is in the approved enum, reviewer note present.
3. Firewall and leak tests pass (section 17); the command refuses to run if they don't.
4. Reachability through at least two pool instances.
5. Extraction sample: fetch the seeds, run the extractor, require hit rate at or above `expect`, zero redaction events.
6. Mirror check: if the fingerprints match an existing cluster, require the analyst to confirm "new source" vs "add as mirror."
7. Write the first snapshot as the known-good baseline and flip state to `live`.

Any step failing leaves the source `approved` and prints what to fix. The posting's "complete go-live checks before collection begins" is this command.

## 15. Authenticated collection against a self-hosted onion

The posting calls out sites that require authentication. The only lawful way to demonstrate that is against a service you own, so host one.

- Stand up a v3 onion service on a separate box or container (not the crawler VM): a small web app with a login form, a session cookie, and a few pages that are only visible when logged in.
- Add `auth.type = "form-session"` to the config schema with fields for the login path, the username and password field names, a success selector, and a credential reference (a secrets file, never in the config).
- The fetcher's auth step is allowlisted by source id to this one onion. The allowlist is a constant in code, the auth step asserts membership before building the request, and the no-auth invariant test (section 17) greps for any other use.
- The session cookie lives in memory for the duration of one source run and is cleared in the existing `finally`.

This proves you can build, tune, and troubleshoot an authenticated collection config, which is the hard case in the job, without ever logging into a site that isn't yours. Personas, forum access, and chat-platform collection stay out of the repo entirely; that's interview conversation drawn from your own experience, not something a portfolio project should contain.

## 16. CLI

Entry point `python -m onioncollect <command>`. Every command refuses to run as root, checks data-dir ownership, and checks which user it's running as (`crawler` for `crawl`, `analyst` for everything else).

- `crawl run [--workers N]`: run due live sources through the pool. Logs source ids, status codes, timings, hit rates, and error names only; never page text.
- `triage`: work the candidate queue: show, approve (category, note, optionally as mirror of X), decline (reason). Approve scaffolds a config.
- `config validate <id>`, `config test <id>`: schema check, then a dry extraction against the latest snapshot without fetching.
- `golive <id>`: section 14.
- `health`: show the queue by priority and age; `health resolve <id> --disposition … --note …`.
- `mirrors <id>`: show the cluster, last-seen per host, fingerprint distances.
- `search <query> [--source] [--category] [--since]`: FTS over records.
- `sources list [--state]`, `sources disable <id> --reason`, `sources export`: lifecycle management and a JSON-lines dump of the source table for the write-up.
- `retention sweep`: apply section 3's clocks; scheduled nightly.

There is no command that fetches an arbitrary URL and no command that exports raw unredacted content, because neither exists.

## 17. Verification and leak tests

Run the original four leak tests (clearnet block, DNS block, packet capture, redirect trap) before any crawl, unchanged; they guard the Tor boundary. Add five that guard the new boundaries:

1. Approval gate. Insert a `candidate` and a `declined` host, run the scheduler and a direct fetcher call for each, and assert zero requests were built and nothing was written beyond the source table.
2. Frontier containment. Feed a live source a page full of off-host onion links and assert every one lands in the candidate table and none on any frontier.
3. Redaction gate. Feed a live source a synthetic page containing fake credentials and assert the stored record and snapshot contain tags and hashes only, a grep of the whole data dir for the plaintext returns nothing, and a top-priority health item was raised.
4. Storage refusal. Call the storage layer directly with a payload that still contains a secret pattern and assert it refuses the write.
5. Auth containment. Grep the codebase for any non-GET request, any form submission, and any cookie jar use, and assert each occurrence is inside the auth step and that the step asserts the self-hosted allowlist. Wire this into CI so a future change that widens it fails the build.

If any test fails, stop. The firewall, the approval gate, and the redaction gate each have to hold on their own.

## 18. Build order

1. Environment hardening and Tor pool (section 5), with the four original leak tests passing. Nothing else starts until these do.
2. Source table, lifecycle states, `is_v3_onion`, and the fetcher with its source-id-only interface. Prove the approval gate and frontier containment tests here, before a second source exists.
3. Config schema, loader, and extractor against two or three approved sources. Hit-rate metrics from the first run.
4. Redaction gate, records DB, FTS index, snapshot store, retention sweep. Prove the redaction and storage refusal tests.
5. Discovery into the candidate table, triage CLI, fingerprinting and mirror clustering.
6. Health metrics, health queue, dispositions, go-live checks. Convert the existing sources to go through `golive` so the baseline snapshots exist.
7. Self-hosted onion with login, `form-session` auth, auth containment test.
8. Search UI, scheduling, and the write-up.

Steps 1 through 4 give you a running collector with provable boundaries. Steps 5 and 6 are the collections-analyst workflow. Step 7 is the hard case the posting names. Step 8 is what you hand over.

## 19. Presenting it

The repo should answer the posting's bullets without a cover letter. Make these easy to find:

- The source policy and a triage log with real approve and decline decisions, including declines with reasons.
- A few configs with their hit-rate history, and at least one health item that went from `degraded` to `fixed` or `mirror-swapped` with the diff that fixed it.
- The go-live command's output for a source that failed a check and then passed.
- The auth config for the self-hosted onion and the containment test that bounds it.
- The leak tests and boundary tests, green in CI.
- A short write-up of what collecting from benign onion services taught you about mirror churn, layout drift, and circuit health. That's the "share what we're seeing" expectation, met with data you can publish.
