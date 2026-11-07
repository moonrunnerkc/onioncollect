# onioncrawl

Text-only crawler for Tor v3 onion sites. Runs several Tor circuits in parallel, keeps a persistent frontier in SQLite, and is boxed so it physically cannot reach the clearnet. Full spec is in docs/build-guide.md; read it before changing anything.

## What this is and isn't

It fetches HTML and plain text from onion services, extracts links and metadata, stores pages compressed, and tracks host uptime over time. It does not render JavaScript, submit forms, log in, solve captchas, or download images or binaries. It does not attempt to identify or locate anyone. Keep it that way; those boundaries are what make it safe and legal to run.

## Hard rules (correctness, not style)

Violating any of these is a bug, not a judgment call:

- All network access goes through `Fetcher.fetch`. No other module touches the network. No `urllib`, no `requests`, no bare `httpx` call sites.
- Every httpx client sets `rdns=True`, `trust_env=False`, `follow_redirects=False`, `http2=False`.
- The SOCKS username is the target host on every request (per-host circuit isolation).
- `onion.normalize` is the only way a URL enters the frontier. `is_v3_onion` is the only thing that validates a host. Clearnet hosts never enter the system.
- Cookies cleared in a `finally` after every response.
- Content-Type allowlist and the 2 MB body cap are enforced before the body is read.
- Logs record hosts, status codes, byte counts, timings, error names. Never page titles, paths, query strings, or body text.
- Content never saved to disk: anything that isn't HTML or plain text, any excluded host, any body that trips `safety.body_triggers_exclusion`.

If you touch fetcher.py, the torrc files, or the firewall, rerun the four leak tests in section 15 of the guide before committing.

## Stack

Python 3.13 (Debian 13's system Python), asyncio, single process, single event loop. Five dependencies, no more without discussion: `httpx`, `httpx-socks`, `stem`, `selectolax`, `aiosqlite`. SQLite in WAL mode with hand-written SQL. No ORM, no web framework, no task queue.

## Layout

One job per file. Nothing imports from a file below it in this list except crawler.py and cli.py.

```
onioncrawl/
  onion.py       v3 validation, URL normalization (pure)
  safety.py      host exclusions, body content checks (pure)
  config.py      frozen Settings dataclass, loaded once
  tor_pool.py    the Tor instances, circuit rotation
  schema.py      CREATE TABLE and CREATE INDEX statements
  db.py          Frontier class, Task and PageInfo dataclasses
  fetcher.py     one request through Tor, all in-code anonymity controls
  parser.py      links, text onions, metadata, simhash (pure)
  storage.py     content-addressed page store
  scheduler.py   host health and recrawl timing (pure)
  crawler.py     workers and main loop
  cli.py         seed / run / status / export
```

## Conventions

- snake_case modules and functions, PascalCase classes.
- 300-line file limit. Past it means the design drifted; flag it instead of splitting mechanically.
- Keep onion.py, safety.py, parser.py, scheduler.py free of I/O so they stay unit-testable.
- No em dashes anywhere, in code, comments, or docs. Use commas, colons, or separate sentences.
- Comments only where the work is genuinely non-obvious: the atomic `claim()` query, the simhash bit math, the SOCKS-auth circuit trick. No comments restating what the code plainly does.
- Code reads as handwritten: specific names, no boilerplate filler, no scaffolding left in.
- One frozen Settings object passed down. No globals, no env-var config.
- No speculative abstraction. No base class with a single subclass, no flag with a single value, no config for what doesn't vary.

## Testing

- Every pure module gets unit tests. onion.py uses known-good and mangled v3 addresses.
- The four leak tests in section 15 are the acceptance bar. Automate what can be automated, especially the mocked clearnet-redirect test, and keep them in CI.
- Build in the order in section 16. Each step must run on its own before the next starts.

## Commits

- No AI attribution trailers. No "Co-Authored-By", no "Generated with" lines, no session links.
- Short imperative subject, body only when the change needs a reason.
- Never commit crawl.db, the pages directory, the control-password file, the exclusion lists, or anything under data/. They belong in .gitignore.

## Running

Runs only as the unprivileged `crawler` user inside the venv, on the hardened VM described in section 3. The firewall is the backstop; the code is the first line of defense. Both must hold independently. Never open a stored page in a browser on that box.
