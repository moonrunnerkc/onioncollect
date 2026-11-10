# onioncollect

Collection platform for benign public onion services, scaled to one operator. It takes a source from candidate to live collection, extracts structured records from it over Tor, keeps them searchable, and measures every source's health. The sources are news organizations' onion mirrors, SecureDrop instances, the Tor Project, Debian, privacy services, and the directories that list them. Full spec is in docs/build-guide.md; read it before changing anything.

## What this is and isn't

It fetches HTML and plain text from sources a human has approved against the source policy and that have passed go-live, runs each source's collection config over the page, and stores redacted records and snapshots. Discovery only records the onion hosts a page names as candidates for triage; it never fetches, queues or approves anything. It does not download dumps or anything that isn't HTML or plain text, store an unredacted credential or personal data, validate or replay a credential, log in, submit forms, solve captchas, post, message, buy, or attempt to identify or locate anyone. The one exception is section 15's login to `testonion`, a self-hosted onion the operator owns, with the operator's own credential. Keep it that way; those boundaries are what make it safe and legal to run.

## Hard rules (correctness, not style)

Violating any of these is a bug, not a judgment call:

- One network call site: `Fetcher.fetch(source_id, path)`, Tor only. It takes a source id and a path, never a URL. It resolves the source, refuses any state but the set it was built with (`lifecycle.COLLECTING` for the crawler, `lifecycle.UNDER_TEST` for `golive`), refuses a host that is not in both the source's approved host set and its config, and only then opens a client. No `urllib`, no `requests`, no other httpx call sites.
- Every `Fetcher` is built with `lifecycle.COLLECTING` or `lifecycle.UNDER_TEST` as its last positional argument, and only `golive.go_live` uses the latter. `test_every_fetcher_is_built_for_collecting_or_under_test_only` lists every construction site; a new one is a reviewed change to that list.
- A host other than a source's active one is fetched only through `sources.PinnedHost`, which changes the active host and nothing else, so the fetcher's state, host-set, config and exclusion checks still decide. Its only users are the sibling probes (once a day, first seed, up or down only, body dropped unread, nothing extracted or stored) and `golive.recheck`.
- GET only. No request bodies, no form actions followed, no cookie jar use beyond clearing it, everywhere but section 15's auth step: `Fetcher.log_in`, `Fetcher._post_form` and `Fetcher._session_for`. Each tests `source_config.AUTH_ALLOWLIST` (exactly `{"testonion"}`, assigned once, never changed) as its first statement, and `log_in` raises `AuthRefused` before a client, a credential read or a request exists. `AuthContainmentTest` fails the build on any POST, body, cookie name, session store use or login word outside those three methods, on a new caller of `log_in` (only `session.Logins.sign_in`), and on a new `Logins` (only `Crawler.open` and `golive.recheck`).
- The auth step sends one POST of the login form to the source's active host, only while the source is live or degraded, after every check a GET passes. Its redirect is recorded, never followed; `session.Logins` confirms the session with a GET of the redirect target, if it is on the source, checked against `success_selector` in `pages.signed_in`. One login per source run, shared by the crawl's fetchers through one `fetcher.Sessions`, ended at the run's end (`Logins.end`) and by `Fetcher.close` in the worker's `finally`, so a crash ends it too. The client cookie jar is still cleared after every response, the POST's included.
- `auth.type = "form-session"` is accepted by the loader only for an id in `AUTH_ALLOWLIST`, and any auth key that looks like a credential, or a credential-shaped value, is refused. The credential lives only in `settings.credentials_dir/<credential_ref>.env` (`/etc/onioncollect/testonion.env` in the guest): a regular file owned by the crawler, mode 600, outside the configs and the data dir, one `username=` and one `password=` line, neither value present in the config text. Only `config.load_credential` reads it, only `Fetcher._post_form` calls that, and the values never reach a log, a metric, a result, a snapshot or a record.
- `golive` refuses a form-session config: the source goes live on its public pages with `auth.type = "none"` and moves to form-session once live. `golive.recheck` logs in only on the active host.
- Every httpx client sets `trust_env=False`, `follow_redirects=False`, `http2=False`, `rdns=True`, and its SOCKS username is the target host on every request (per-host circuit isolation).
- Redirects are recorded, never followed. A target on the source's own hosts is queued as its own fetch, another onion becomes a candidate, anything else is dropped.
- `host_prefix` is a config key with one legal value, `"www"`, refused on a form-session source. It changes the request line only: `Fetcher._get` asks for `onion.with_label(url, prefix)`, and `onion.without_label` maps a link or a redirect on `www.<one of the source's hosts>` back to the bare host before `normalize` sees it. The host set, approval, exclusions, `result.host`, `result.url` and the SOCKS username stay the bare address, and a prefixed name on any other address is still refused.
- `onion.normalize` and `is_v3_onion` are the only URL and host gates. `SourceConfig.path_for` is the only way a link becomes a frontier path, and it accepts only the source's own hosts. Every other onion host a page names goes to `SourceTable.add_candidates` and nowhere else.
- A host is fetched only after a human approves it (`triage approve`: a category from `lifecycle.CATEGORIES`, a reviewer note, never a host on the exclusion list), and collected only after `golive` passes. Declined is final; rediscovery never resurrects a host.
- A host joins another source's host set only by a human decision: `triage approve --as-mirror-of X`, `golive --as-mirror-of X`, or `sources merge A --into X` (seed fingerprints within `MIRROR_MAX_BITS`, or `--force` with a note). Clustering reads stored seed-page fingerprints and writes `sources.cluster_id`, nothing else; it never fetches and never changes a host set or a state. A config's `hosts` array is edited only by `source_config.with_hosts`, which proves the edit by reading it back.
- `golive` refuses a source whose seed pages match another source's until the analyst passes `--confirm-new-source` or `--as-mirror-of`.
- `golive` refuses before any fetch (check 3), and `crawl run` refuses before Tor or a client exists, unless `settings.leak_test_result`, written as root by `make leak-test`, is owned by root, is writable by nobody but its owner, names all four leak tests as passed, is under `LEAK_TEST_MAX_AGE` (36 h) old, and records the deploy stamp `make deploy` wrote beside it (`golive.DEPLOY_STAMP`, also root's). Code deployed after the last leak test never fetches; `make deploy` ends by running the leak tests.
- `crawl run` loads every collecting source's config through the loader before Tor starts and refuses to run if any fails, then logs the form-session sources by id. A config can change with no golive (testonion's switch to form-session), so this is its gate.
- `active_host` changes only through `SourceTable.set_active_host`, to a host already in the source's set, and only after that host passes golive checks 1, 4 and 5 (`health resolve --disposition mirror-swapped`). A failed check is recorded as a refused disposition and changes nothing.
- An open health item makes a live source degraded. It leaves the queue only by a disposition with a note: `fixed` (checks 1, 4 and 5 pass on the active host, or the source passes `golive` again), `mirror-swapped`, `disabled`, or `watching` for N runs, which closes itself only if nothing recurred. Every disposition, applied or refused, is a row in `dispositions`.
- A redaction event or a refused write on a live source raises a health item at `health.REDACTION_PRIORITY`, above anything the shortfall formula can give. It is never only a log line.
- A body with more than `extractor.MAX_TAGS` '<' characters is never parsed: the page fails as `parse_refused` and raises a health item. The count happens in `pages.inspect` and `pages.signed_in` after the safety check; never in the fetcher.
- Rows of two sources merge only through `RecordStore.merge` (the oldest row survives with every host sighting), run when a cluster gains a source, by `records merge <cluster>`, and by `sources merge`.
- Cookies cleared in a `finally` after every response. Content-Type allowlist and the 2 MB cap (inflated size) are enforced before the body is read.
- A body lives only inside `pages.py`: `inspect` for a page of a run, `signed_in` for the page a login lands on. What comes out of `inspect` is redacted records, a redacted snapshot, a fingerprint of the redacted visible text and the bare tag shape, host names and counts; out of `signed_in`, a safety category and a yes or no. A probe's body is dropped unread.
- `RecordStore` is the only writer of records, snapshots and fingerprints. It reruns `detect.find` on every field and snapshot and refuses any write that still trips it. Passwords are never hashed; identifiers are hashed with the keyed salt.
- A body that trips `safety.body_triggers_exclusion` disables its source and is never extracted or stored.
- Logs record source ids, page kinds, status codes, byte and item counts, hit rates, timings, error names. Never hosts, paths, query strings, page titles, page text or record text. The UI logs its route name, status, result count and time, never a query.
- The search UI reads. It never writes and never fetches. `ui.py` opens each store per request through a `mode=ro` SQLite connection with `query_only` on, reads snapshot files only after the id matches the content-address format and the snapshots table, imports nothing that can reach the network, and binds only the literal `127.0.0.1` (`UIContainmentTest`). It starts from `ui_main.py`, never `cli.py`; `test_ui_entry` holds its import closure to an exact list, statically and as loaded in a clean interpreter. It refuses root, the crawler, and any user who can write the stores, answers only GET under a local Host name, and sends `default-src 'none'; style-src 'unsafe-inline'`. Every stored value reaches the page through `views.text`, and the only links are its own routes: a record's onion link or a snapshot's markup is shown as text, never followed or rendered.
- Search input, from the CLI or the UI, is quoted down to literal FTS5 terms by `search.literal_query` and bound as a parameter. Operator syntax is matched as text, never parsed.
- The analyst owns the stores (`/home/analyst/data`, mode 700, umask 077). The crawler never opens a store file: every write and every store read of `crawl run`, `golive` and the fixed and mirror-swapped dispositions goes through `writer_client.Writer` over `/run/onioncollect/writer.sock` to `writer.py`, run as the analyst, which admits the crawler's uid alone (SO_PEERCRED, root refused) before reading a byte, takes one op from `writer_ops.OPS` per line, checks every field against the op's spec, and runs `RecordStore`, so the second detector runs as the analyst. The crawler keeps its frontier (`urls`, paths and scheduling only) in its own state dir. `test_writer` and `test_writer_boundary` hold this; a new op is a reviewed change to `writer_ops.OPS`. Reader commands (`reader=True`: search, sources list and export, triage list, health and its runs and log) open both stores read-only, need no secret file, and never create a store. `Database.close` leaves empty `-wal` and `-shm` files so a read-only reader can open a WAL database the crawler has closed.
- `make deploy` never deletes a guest config unless `PRUNE_CONFIGS=1` and a typed `yes` (`deploy/sync_configs.sh`). No timer runs golive, triage, sources, a disposition or a deploy; `test_deploy` reads every unit's `User=` and `ExecStart=`.

- The kill switch accepts by owner: loopback, SSH replies, the six Tor uids, the DHCP renewal. Its one accept by connection is TCP on a connection carrying `TOR_MARK`, which only the SYN of a new connection from a Tor instance's uid sets (`provision.sh` `kill_switch_rules`, held line for line by `test_provision`). It passes the kernel's own last packets for a connection Tor has closed, which have no owner. No generic ESTABLISHED rule, no UDP by mark, IPv6 policy DROP. Leak test 3 credits a packet by its exact connection: owned only by Tor uids, or carrying the mark with no other owner ever seen; a marked connection any other uid was on fails the test.

If you touch fetcher.py, the torrc files, or the firewall, rerun the four Tor leak tests (`make leak-test`) before committing and before the next golive. testonion/torrc is the second VM's, not the crawler's, and is not covered by this rule.

## Known limits

- A hex-only token inside a URL path is not detected: `detect.tokens` judges a whole run of token characters, and with the slashes of the path in it the run is not all hex. A mixed-case token in a path or query is detected. Recorded 2026-11-10, not fixed.

## Stack

Python 3.13 (Debian 13's system Python), asyncio, single process, single event loop. Five dependencies, no more without discussion: `httpx`, `httpx-socks`, `stem`, `selectolax`, `aiosqlite`. Collection configs are TOML read with the standard library's `tomllib`. SQLite in WAL mode with hand-written SQL and FTS5. No ORM, no web framework, no task queue.

## Layout

One job per file. Nothing imports from a file below it in this list.

```
onioncollect/
  onion.py          v3 validation, URL normalization, onions in text (pure)
  safety.py         host exclusions, child-safety body check (pure)
  detect.py         secret spans: credential pairs, emails, cards, IDs, tokens (pure)
  lifecycle.py      source and host states, policy categories, transitions (pure)
  source_config.py  collection config schema, TOML parsing, the approval scaffold (pure)
  extractor.py      records, hit rate, next page and follows from one page (pure)
  redact.py         text to tags, counts and keyed hashes (pure)
  parser.py         links, discovered hosts, gate detection, visible text (pure)
  matching.py       Fingerprint, distances, the mirror threshold, clustering (pure, standard library)
  fingerprint.py    content and structure simhashes of a page (pure)
  scheduler.py      page retries, run cadence with the health multiplier (pure)
  health.py         section 13's entry rules, priorities, kinds and dispositions (pure)
  search.py         the full-text query shared by the CLI and the UI, input quoted to literal terms (pure)
  views.py          the search UI's HTML, every stored value escaped, links only to its own routes (pure)
  config.py         frozen Settings, loaded once; config file loading and writing
  tor_pool.py       the Tor instances, circuit rotation
  schema.py         CREATE TABLE and CREATE INDEX statements
  db.py             Database helper; the crawler's Frontier (its own state dir), Task and PageMetric
  sources.py        SourceTable: candidates, approve, mirror approve, fold and merge, decline, state changes,
                    cluster ids, redirect evidence, active host, reapprove, note corrections (append only); PinnedHost
  runs.py           RunLog: run totals, page metrics, per-field hits, uptime and probes, visited paths (writer side)
  health_queue.py   HealthQueue: items, dispositions, snoozes, run summaries and per-run metrics
  records.py        RecordStore: records, host sightings, cluster dedup and merge, FTS, snapshots and baselines,
                    fingerprints, retention
  mirrors.py        clusters and matches from stored fingerprints, merge on cluster growth; no fetch
  stores.py         opening both stores for one analyst command
  wire.py           the write socket's line protocol and error codes (pure)
  writer_ops.py     every op the crawler may send: its field spec and what it does to the stores
  writer.py         the write socket server, as the analyst: peer check, line cap, spec check, one op at a time
  writer_client.py  the crawler's side of the socket: one connection per op, typed errors
  fetcher.py        one GET through Tor for a source id and path, all in-code anonymity controls; section 15's
                    auth step (log_in, _post_form, _session_for) and the Sessions store
  pages.py          the whole life of a body: inspect, and signed_in for the login check (no I/O)
  probes.py         daily reachability probes of non-active hosts, through PinnedHost
  session.py        Logins: one login per form-session run, shared by the crawl's fetchers, ended with the run
  crawler.py        workers, run scheduling, health items as pages and runs finish
  golive.py         section 14's checks, and checks 1, 4 and 5 again for fixed and mirror-swapped
  crawl_cli.py      crawl run / status, golive (crawler user)
  health_cli.py     health / runs / log / resolve (analyst; fixed and mirror-swapped fetch, as crawler)
  config_cli.py     config validate / test, the latest snapshot against the golive baseline (analyst)
  ui.py             the read-only search UI on 127.0.0.1, standard library, as the analyst
  ui_main.py        the UI's own entry point: arguments, the user check, the stores opened read-only; never cli.py
  triage_cli.py     triage list / approve / decline / request (analyst); a request is a candidate row, never a fetch
  cli.py            sources / records / mirrors / search / retention (analyst), and the entry point
configs/            one reviewed TOML file per source, committed
deploy/             make deploy's guest half (install.sh), the config sync, and the systemd units it installs
tools/              writeup_check.py (markers left in the write-up), writeup_capture.py (the guest's evidence, stripped)
                    and settings_check.py (make deploy's preflight: each user's settings load, or nothing restarts)
docs/writeup.md     the write-up; every number is a [PASTE: ...] marker until it comes from the guest
testonion/          section 15's self-hosted onion for its own VM (testonion-vm): the stdlib app, its torrc,
                    systemd unit, setup script and Lima file, and the stage 1 and stage 2 configs
```

## Conventions

- snake_case modules and functions, PascalCase classes.
- 300-line file limit. Past it means the design drifted; flag it instead of splitting mechanically.
- Keep the pure modules above free of I/O so they stay unit-testable.
- No em dashes anywhere, in code, comments, or docs. Use commas, colons, or separate sentences.
- Comments only where the work is genuinely non-obvious: the atomic `claim()` query, the SOCKS-auth circuit trick, why a detector is anchored the way it is. No comments restating what the code plainly does.
- Code reads as handwritten: specific names, no boilerplate filler, no scaffolding left in.
- One frozen Settings object passed down. No globals, no env-var config.
- No speculative abstraction. No base class with a single subclass, no flag with a single value, no config for what doesn't vary.
- A regex that runs on page text and opens with a character run starts with a lookbehind, so a hostile 2 MB body can't hold the GIL in one long C call. `tests/live/pattern_timing.py` measures it, including a body one tag under `MAX_TAGS`, the most markup the parser ever sees.

## Testing

- Every pure module gets unit tests. onion.py uses known-good and mangled v3 addresses; detect.py includes hostile 2 MB bodies.
- Section 17's tests are the acceptance bar. The four Tor leak tests run live in the guest (`make leak-test`); the redirect trap and the five boundary tests (approval gate, frontier containment, redaction gate, storage refusal, auth containment) run in CI. `test_network_boundary` maps each to its test. Auth containment is `AuthContainmentTest` for the code and `test_fetcher_auth` and `test_session` for behaviour; widening any of them is a reviewed change to the test, never a skip. `UIContainmentTest` bounds the search UI the same way, and `test_ui` covers its read-only connection, escaping, literal search and ids; `test_scheduling` the timer's crawl and its gates; `test_deploy` the units and the config sync; `test_writeup` the capture's stripping.
- Build in the order in section 18. Each step must run on its own before the next starts.

## Commits

- No AI attribution trailers. No "Co-Authored-By", no "Generated with" lines, no session links.
- Short imperative subject, body only when the change needs a reason.
- Never commit collect.db, records.db, snapshots, the control-password or redaction-salt files, the safety files, or anything under data/. They belong in .gitignore. Collection configs under configs/ are committed; they are the reviewed record of what is collected.

## Running

In the guest, systemd runs the routine jobs from a root-owned copy of the code and venv under /opt/onioncollect (`deploy/systemd/`): `crawl run --until-idle` as crawler every 15 minutes, the retention sweep nightly as the analyst, the writer as the analyst at boot (the crawl unit requires it), the leak tests daily as root, the log audit as the analyst after every crawl, and the search UI as the analyst on 127.0.0.1:8470, reached by an SSH forward. `crawl run`, `golive` and the two fetching dispositions (`health resolve --disposition fixed|mirror-swapped`) run only as the unprivileged `crawler` user inside the venv, and take the run lock, on the hardened VM described in section 5. The self-hosted onion runs on its own VM (`make testonion`), never on the crawler's; `make testonion-credentials` pipes its credential into the crawler guest without it touching the host's disk. The firewall is the backstop; the code is the first line of defense. Both must hold independently. Triage, search and the rest belong to the `analyst` user, which never holds the Tor control password or any secret file. The analyst runs triage, the reader commands, the retention sweep, the writer and the UI. Never open a snapshot in a browser on that box.
