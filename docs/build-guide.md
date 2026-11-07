# Onion Crawler Build Guide

## 1. What you're building

A text-only crawler for Tor v3 onion sites that runs many Tor circuits in parallel, never forgets what it has seen, and cannot physically reach the clearnet. Call it `onioncrawl`. One Python package, about 1,200 lines when finished, nine files.

What it does on each run:

1. Pulls the next URLs from a persistent queue (the frontier) in SQLite.
2. Fetches each one through one of several Tor processes, HTML only, with a size cap.
3. Pulls out links, onion addresses buried in plain text, the title, headings, and server headers.
4. Stores the raw page compressed on disk and a fingerprint in the database.
5. Queues new onion addresses, schedules recrawls, and tracks which hosts are alive over time.

Where it beats TorBot, TorCrawl, and the Ahmia-style crawlers:

| Weakness in existing tools | What this build does instead |
| --- | --- |
| One Tor process, one circuit, everything waits on it | 6 to 10 Tor processes, each worker pinned to one, per-host stream isolation |
| In-memory queue, a crash restarts from zero | SQLite frontier, resumes exactly where it stopped |
| Links only from `<a href>` tags | Also regex-scans raw text for 56-character v3 addresses with checksum validation |
| Hangs for minutes on dead hosts | Hard 45 s budget per request, dead-host tracking, weekly retest |
| No idea what changed since last visit | Content hash and simhash per page, change detection and mirror detection |
| No host history | Uptime log per host; this alone is data most tools never collect |
| Can leak to the clearnet by accident | Firewall allows outbound only from the Tor user; the crawler user is fully blocked |

The design rule for the whole project: every request goes through Tor or it does not go at all, and nothing about the machine, the operator, or previous requests rides along with it.

## 2. Threat model: how a crawler leaks, and the rule that closes each hole

A crawler can expose you in seven ways. Each one gets a hard rule that the code or the OS enforces, not a habit you have to remember.

| Leak | How it happens | Rule that closes it | Enforced in |
| --- | --- | --- | --- |
| Direct clearnet connection | A bug, a redirect to a clearnet mirror, a library ignoring the proxy, an `HTTP_PROXY` env var | Firewall drops every outbound packet from the crawler user. Only the Tor users may leave the box. | iptables (section 3) |
| DNS leak | Client resolves the hostname itself before handing it to the proxy, so `.onion` names hit your resolver | SOCKS5 with remote DNS (`rdns=True`). The firewall also drops port 53 from the crawler user. | fetcher.py, iptables |
| Clearnet link following | Onion pages link to clearnet sites, mirrors, images, and CDNs | Only `.onion` hosts are ever queued or fetched. Redirects are not followed automatically; the `Location` header is checked first. | onion.py, fetcher.py |
| Browser fingerprint | Default `python-httpx/x.y` user agent, odd header order, HTTP/2 negotiation | Fixed Tor Browser header set, HTTP/1.1 only, no compression quirks, no `Referer`. | fetcher.py |
| Cross-site linking | Cookies or a shared circuit tie your visits to site A and site B together | Cookies cleared after every response. SOCKS username set to the hostname, so Tor gives each host its own circuit. | fetcher.py |
| Timing pattern | Perfectly regular request intervals look like a bot and correlate across sites | Random jitter between requests, per-host concurrency cap of 2, circuit rotation on failure. | crawler.py |
| Local disk and logs | Raw pages, URLs, and timestamps sit on an unencrypted disk; logs contain page content | Full-disk encryption on the VM. Logs carry hashes and hosts, never page text. Text only, no images or binaries ever downloaded. | section 3, storage.py |

Two things the crawler does not try to do, on purpose:

- It never runs JavaScript or a headless browser. Nearly every onion site is static HTML, and a browser through Tor is slow, fragile, and a much larger fingerprint.
- It never submits forms, logs in, or solves captchas. Pages behind those are marked `gated` and skipped.

Legal note in one line: downloading HTML text only, with a 2 MB cap and no images, keeps you from ever storing the kinds of content that create legal exposure. Keep it that way.

## 3. Environment setup

Do this in order. The firewall comes last because package installs need the network.

### 3.1 The machine

- A dedicated VM, never your daily machine. Debian 13 server (Python 3.13), 2 vCPU, 4 GB RAM, 40 GB disk. This project builds it locally with Lima from `provision/`; see `provision/README.md`.
- Turn on full-disk encryption (LUKS) in the installer. Everything the crawler stores lives on that disk.
- No shared folders, no shared clipboard, no guest additions. Hostname something bland like `node1`. Timezone UTC.
- Two users: `crawler` (no sudo, runs the code) and your admin account (sudo, used only for setup).
- Snapshot the VM once setup is done so you can roll back.

### 3.2 Tor, as separate system instances

Install Tor from the Tor Project's own apt repository, not the distro's, so you get current releases. Follow the repo setup on torproject.org, then:

```bash
sudo apt install tor deb.torproject.org-keyring
sudo systemctl disable --now tor@default
for i in 1 2 3 4 5 6; do sudo tor-instance-create crawl$i; done
```

`tor-instance-create` makes a service `tor@crawlN`, a config at `/etc/tor/instances/crawlN/torrc`, and a system user `_tor-crawlN`. That per-instance user is what the firewall keys on later.

Generate one control password: `tor --hash-password 'pick-a-long-random-string'`. Put this in every instance's torrc, changing only the two port numbers (instance N uses SOCKS `1005N` and control `1105N`):

```text
SocksPort 127.0.0.1:10051 IsolateSOCKSAuth
ControlPort 127.0.0.1:11051
HashedControlPassword 16:<output of tor --hash-password>
ClientOnly 1
SafeLogging 1
MaxCircuitDirtiness 600
Log notice syslog
```

What each line buys you: `IsolateSOCKSAuth` gives a separate circuit to each distinct SOCKS username, and the fetcher sets the username to the target hostname, so no two onion sites ever share a circuit. `ClientOnly` stops Tor from ever acting as a relay. `SafeLogging` scrubs addresses from Tor's own logs. `MaxCircuitDirtiness 600` retires circuits after 10 minutes even when nothing failed.

Start them: `for i in 1 2 3 4 5 6; do sudo systemctl enable --now tor@crawl$i; done`. Check with `ss -ltnp | grep 1005` that six SOCKS ports are listening.

### 3.3 Python and dependencies

As the `crawler` user:

```bash
python3 -m venv ~/venv && source ~/venv/bin/activate
pip install pip-tools
```

Put these five names in `requirements.in`: `httpx`, `httpx-socks`, `stem`, `selectolax`, `aiosqlite`. Then `pip-compile --generate-hashes requirements.in` and `pip install --require-hashes -r requirements.txt`. The hashes mean a tampered package index cannot hand you a modified wheel later. Commit `requirements.txt` so the exact versions are reproducible.

Why these five: httpx is the async HTTP client; httpx-socks adds SOCKS5 with remote DNS and per-connection proxy auth; stem talks to Tor's control port; selectolax parses HTML about 10x faster than BeautifulSoup; aiosqlite is SQLite without blocking the event loop. Nothing else is needed.

### 3.4 The firewall (the kill switch)

This is the control that makes every other mistake survivable. Outbound traffic is allowed only for the six Tor users, for loopback, and for replies on your SSH session. The `crawler` user cannot send a single packet off the box.

```bash
sudo iptables -F OUTPUT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
for i in 1 2 3 4 5 6; do sudo iptables -A OUTPUT -m owner --uid-owner _tor-crawl$i -j ACCEPT; done
sudo iptables -A OUTPUT -j DROP
sudo ip6tables -F OUTPUT && sudo ip6tables -P OUTPUT DROP
sudo apt install iptables-persistent && sudo netfilter-persistent save
```

The final rule is DROP on purpose: a blocked connection gets no reply at all, so it times out (curl exits 28) instead of failing fast with a network error, and that timeout is the expected failure mode, not a reason to switch to REJECT.

Test it right away as `crawler`: `curl -m 5 https://example.com` must fail. `curl -m 60 --socks5-hostname 127.0.0.1:10051 https://check.torproject.org` must succeed and say you are using Tor. If both hold, the box is sealed.

When you later need to update packages, insert a temporary rule at the top (`sudo iptables -I OUTPUT 1 -m owner --uid-owner crawler -j ACCEPT`), run pip, then delete it (`sudo iptables -D OUTPUT 1`). Never leave it in place.

## 4. Project layout

Twelve files, one job each. Nothing imports from a file below it in this list except `crawler.py` and `cli.py`, which tie everything together. `onion.py` and `safety.py` come first because they are pure and import nothing else from the package, and `config.py` uses `safety.py` to parse the two safety files.

```text
onioncrawl/
  onion.py        v3 address validation, URL normalization
  safety.py       host exclusions, body content checks (pure)
  config.py       settings, loaded once, never mutated
  tor_pool.py     talks to the six Tor instances, rotates circuits
  schema.py       the CREATE TABLE and CREATE INDEX statements
  db.py           the Frontier class over that schema
  fetcher.py      one HTTP request through Tor, safely
  parser.py       links, onion addresses, metadata, simhash
  storage.py      raw page store on disk
  scheduler.py    host health, recrawl timing
  crawler.py      workers and the main loop
  cli.py          seed / run / status / export
data/
  crawl.db        the frontier and all metadata
  pages/          gzip'd raw HTML, named by sha256
requirements.in
requirements.txt
```

How a single URL moves through the code:

1. `cli run` builds a `Crawler`, which opens the `Frontier` (db.py) and the `TorPool` (tor_pool.py).
2. A worker asks `Frontier.claim()` for the next URL and gets a lease on it.
3. The worker's `Fetcher` sends the request through its pinned Tor instance with the hostname as the SOCKS username.
4. The response body goes to `parser.parse()`, which returns a `PageInfo` with links, onion hosts, title, and hashes.
5. `storage.save()` writes the gzip'd body to disk. `Frontier.complete()` records the result and queues every new onion URL.
6. `scheduler.next_due()` decides when that URL and that host are looked at again.
7. On any failure, `Frontier.fail()` bumps the retry count and `TorPool.rotate()` may ask that instance for a fresh circuit.

Two small dataclasses are shared across files and live in `db.py`: `Task` (a claimed frontier row: `url`, `host`, `depth`, `retries`, `last_hash`, and the host's `unchanged_streak`, which the scheduler needs) and `PageInfo` (what the parser returns). Keeping them there avoids circular imports.

## 5. config.py

One frozen dataclass called `Settings`, built once in `cli.py` and passed down. No globals, no environment variables (an env var is one more thing that can silently point the crawler somewhere else).

| Setting | Default | Why this value |
| --- | --- | --- |
| `tor_instances` | 6 | List of `(socks_port, control_port)` pairs: `(10051, 11051)` through `(10056, 11056)`. One worker per instance. |
| `control_password` | required | The plaintext you hashed in section 3.2. Read from a file with mode 600, never from argv. |
| `exclusions` | required | Hosts whose content is never fetched or saved. Parsed from the operator's exclusion list. |
| `safety_patterns` | required | Compiled body checks, one per pattern line, in category order. Parsed from the operator's pattern list. |
| `workers_per_instance` | 3 | 6 instances x 3 = 18 requests in flight. Tor handles this fine; onion sites are the slow part. |
| `per_host_concurrency` | 2 | More than this looks like an attack and gets you banned or rate-limited. |
| `request_timeout` | 45 s | Total budget: connect + read. Onion sites that take longer are effectively down. |
| `max_body_bytes` | 2,000,000 | Read cap. Stops a 500 MB page from eating memory and keeps you text-only. |
| `max_retries` | 3 | Per URL before it's parked. |
| `dead_after_failures` | 5 | Consecutive failed fetches, across at least 24 h, before a host is marked dead. |
| `max_depth` | 6 | Link depth from a seed. Deeper than this is almost always pagination noise. |
| `jitter_seconds` | (1.0, 4.0) | Random sleep between requests on one worker. Breaks timing regularity. |
| `recrawl_active_hours` | 24 | Hosts that changed on the last visit. |
| `recrawl_quiet_hours` | 168 | Hosts unchanged for 3 visits in a row. |
| `retest_dead_hours` | 168 | Dead hosts get one probe a week. Onion sites come back from the dead constantly. |
| `data_dir` | `./data` | Holds `crawl.db` and `pages/`. On the encrypted disk. |
| `user_agent` | Tor Browser's current UA | Check the Tor Browser release notes and update it when they bump the Firefox ESR version. |

The only logic in this file is `Settings.load(path)`, which reads a small TOML file, reads the three files it names, and raises if any Tor port in the list is not listening on 127.0.0.1. Fail at startup, not three hours in.

The TOML names its files with three required keys:

```toml
control_password_file = "/home/crawler/control-password"
exclusions_file = "/home/crawler/exclusions.txt"
safety_patterns_file = "/home/crawler/safety-patterns.txt"
```

The two safety files are operator-supplied config. The repository never contains them, not in a commit, a README, or a test fixture; `.gitignore` keeps both out, and tests use their own throwaway patterns. `exclusions.txt` holds one v3 onion host per line, `#` starting a comment. `safety-patterns.txt` holds one `<category> <regex>` per line, with category `child_exploitation`, `credential_dump`, or `card_number`, matched case-insensitively against the decoded body; a `card_number` hit counts only if its digits pass the Luhn check. `safety.parse_exclusions(text)` and `safety.parse_patterns(text)` turn the text into the frozenset and the tuple of compiled patterns that `Settings` carries; safety.py itself never touches the disk. `Settings.load` raises if either file is missing, has a bad line, or parses to empty, so a fresh checkout can never run unfiltered.

## 6. onion.py

Four pure functions, no I/O, fully unit-testable. This file is the gate: if a URL doesn't pass here, nothing else in the system ever sees it.

**`is_v3_onion(host: str) -> bool`**

True only for a real v3 address. A v3 address is 56 base32 characters followed by `.onion`. The 56 characters decode to 35 bytes: a 32-byte public key, a 2-byte checksum, and one version byte that must be 3. Recompute the checksum and compare. This rejects typos, fake addresses planted in link farms, and the old 16-character v2 addresses that no longer resolve.

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

**`normalize(url: str) -> str | None`**

Turns any href into one canonical form or returns None. Steps: lowercase the scheme and host; drop the fragment; drop a default port; drop any `user:password@` userinfo; keep the query string (many onion forums key pages on it); turn an empty path into `/` and leave every other path, trailing slash included, as it is; reject anything whose scheme is not http or https; reject any host that fails `is_v3_onion`. Returning None for clearnet hosts is the point: the frontier never learns they exist.

Two of those steps are decisions, recorded here so the code and the spec agree:

- The root of a site is always `http://<host>/`. An empty path becomes `/`, which matches the form `find_onions_in_text` queues, so `http://<host>` and `http://<host>/` share one dedup key.
- Userinfo is stripped, never kept. httpx turns `user:pw@` into an `Authorization` header, and the crawler never logs in.

**`host_of(url: str) -> str`**

Just the lowercase hostname, used as the SOCKS username and the per-host key everywhere else.

**`find_onions_in_text(text: str) -> set[str]`**

Regex `[a-z2-7]{56}\.onion` over the raw page text, then filter through `is_v3_onion`. This catches the majority of darknet links, which are pasted as plain text in forum posts, link lists, and "mirrors" pages rather than wrapped in anchor tags. Each hit becomes `http://<host>/` in the frontier at the current depth plus one.

## 7. tor_pool.py

Two classes. `TorInstance` wraps one running Tor process through its control port. `TorPool` holds six of them and decides which one a worker uses.

### class TorInstance

Constructor takes `socks_port`, `control_port`, `password`. Holds a stem `Controller`, a rolling window of the last 50 fetch outcomes, and the time of the last circuit rotation.

**`connect()`**: `Controller.from_port(port=control_port)` then `authenticate(password=...)`. Raises on failure so startup aborts cleanly. Call once.

**`is_ready() -> bool`**: asks `get_info("status/circuit-established")` and returns True when it is `"1"`. A freshly started Tor takes 10 to 60 seconds to build its first circuit; the pool waits on this before releasing workers.

**`socks_url() -> str`**: returns `socks5://127.0.0.1:<socks_port>`. The fetcher adds the per-host username.

**`record(ok: bool)`**: appends to the rolling window. That window is the instance's health score.

**`success_rate() -> float`**: successes over the window, or 1.0 if fewer than 10 samples. Below 0.3 means this instance has a bad guard or exit path and needs rotating.

**`rotate()`**: sends `Signal.NEWNYM`, which tells Tor to use fresh circuits for all new connections. Tor rate-limits this to once every 10 seconds, so check `is_newnym_available()` first and if false, sleep `get_newnym_wait()` seconds. Record the rotation time. Existing connections keep their old circuit, which is fine; the next request from each worker picks up a new one.

**`close()`**: closes the controller. Tor itself keeps running under systemd.

### class TorPool

Constructor takes the `Settings`. Builds one `TorInstance` per entry in `tor_instances`.

**`start()`**: connects every instance, then polls `is_ready()` on each every 2 seconds until all are up or 120 seconds pass. Any instance still not ready after that is dropped from the pool with a logged warning rather than blocking the run.

**`assign(worker_id: int) -> TorInstance`**: `instances[worker_id % len(instances)]`. Workers are pinned, not load-balanced. Pinning keeps each worker's traffic on a consistent set of circuits and makes per-instance health scores meaningful.

**`health_loop()`**: an async task that wakes every 60 seconds, checks `success_rate()` on each instance, and calls `rotate()` on any below 0.3. Also logs one line per instance: rate, fetches in the window, last rotation. This is where you'll see a bad guard before it wastes an hour.

**`rotate_for(instance)`**: the fetcher calls this after a URL exhausts its in-request retries. It rotates only if the last rotation was more than 30 seconds ago, so a burst of failures on one dead host doesn't thrash circuits for every other host on that instance.

**`stop()`**: closes every controller.

## 8. db.py

SQLite in WAL mode with `busy_timeout=5000`, one connection shared by all workers, one `asyncio.Lock` around writes. At 18 concurrent workers the database is never the bottleneck; Tor is.

### Schema

| Table | Columns | Purpose |
| --- | --- | --- |
| `urls` | `url` PK, `host`, `depth`, `status`, `priority`, `retries`, `next_due`, `lease_until`, `last_fetched`, `last_hash`, `last_code`, `discovered_at` | The frontier. `status` is one of `queued`, `leased`, `done`, `parked`. |
| `hosts` | `host` PK, `first_seen`, `last_up`, `last_down`, `consecutive_failures`, `state`, `title`, `unchanged_streak`, `simhash` | One row per onion service. `state` is `unknown`, `up`, `dead`, `gated`, or `excluded` (set by the safety checks; never changes back). |
| `pages` | `sha256` PK, `url`, `host`, `fetched_at`, `http_code`, `bytes`, `title`, `simhash`, `path` | One row per distinct page body ever stored. |
| `uptime` | `host`, `checked_at`, `up` | Append-only log. Every fetch attempt writes one row. This is the host history nobody else keeps. |

Timestamps are UTC text, `YYYY-MM-DD HH:MM:SS.mmm`, so they sort as strings and read cleanly in `sqlite3`. Simhashes are stored as signed 64-bit integers, because SQLite has no unsigned type.

Indexes: `urls(status, next_due, priority)` for claiming, `urls(host, status)` for per-host lease counts, `pages(simhash)` for near-duplicate lookup, `uptime(host, checked_at)`.

### class Frontier

**`open(path)`**: connects, sets WAL and busy timeout, runs the `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` statements from `schema.py` (plain string constants, split out so db.py stays under 300 lines). Then it applies the exclusion list: every host in `settings.exclusions` is upserted into `hosts` as `excluded`, with its title and simhash cleared, and every row of any excluded host that is not already `parked` is parked, leased rows included. The operator's list wins over anything the database remembers, so a listed host is never fetched, and a row that a crashed run had in flight when its host was excluded is not picked up again. Last it calls `release_stale_leases()` so a crashed previous run's work is picked up again.

**`seed(urls: list[str])`**: normalizes each URL through `onion.normalize`, inserts with `depth=0`, `priority=0`, `status='queued'`, `next_due=now`. `INSERT OR IGNORE`, so re-seeding is harmless.

**`claim(n: int) -> list[Task]`**: the one tricky query. In a single statement, pick up to `n` rows where `status` is `queued` or `done` (a `done` row is a page waiting for its recrawl; without it nothing is ever revisited) and `next_due <= now`, ordered by `priority`, then `depth`, then `discovered_at`; set them to `leased` with `lease_until = now + 10 minutes`; return them. SQLite 3.35+ supports `UPDATE ... RETURNING`, which makes this atomic without a transaction dance. Skip rows whose host already has `per_host_concurrency` leased rows. A correlated subquery count alone is not enough: inside one `UPDATE` it reads the table as it was before the update, so a batch could take three rows of a host with one free slot. Count leased rows per host once, then number each host's candidates with `ROW_NUMBER() OVER (PARTITION BY host ...)` and keep only those that fit the free slots. Never-fetched URLs get priority 0; `complete` sets priority 1 for the recrawl, so discovery always wins over revisiting.

**`complete(task, info: PageInfo, next_due, page_path)`**: in one transaction: set the url row to `done` at priority 1 with the new hash, code, and `next_due`; set the host row to `up` (or `gated` when `info.gated`; an `excluded` host stays excluded) with `consecutive_failures=0`, bump or reset `unchanged_streak` depending on whether the hash changed, and take the title and simhash only from the host's root page; insert the page row if the sha256 is new and the body was stored (`page_path` is None for a gated page); append the uptime row; then call `add_discovered` with the links from `info`, unless the page is gated.

**`fail(task, retries, next_due, host_answered)`**: db.py sits above scheduler.py in the layout, so it cannot call it; `crawler.py` asks the scheduler for the new retry count and `next_due` (None means park) and passes them in. Set the row to `queued` at that `next_due`, or `parked`. A row whose host was excluded while it was in flight is parked, not re-queued, so `claim` never has to check host state. When the host answered with an HTTP status (a redirect offsite, a PDF, a malformed response) it is up, not down: record `up=1` and reset its failures, or five PDFs in a day would mark a live site dead. Otherwise bump `consecutive_failures`, set `last_down`, and append `up=0`.

**`recent_failures(host) -> list[datetime]`** and **`mark_dead(host)`**: the dead-host rule. The crawler passes the failure times since the host was last up to `scheduler.host_is_dead`; if it says dead, `mark_dead` sets the state and parks every queued URL on the host.

**`exclude(task, info)`**: the safety path. Parks the URL and every queued or done URL on the host, sets the host `excluded`, appends an `up=1` uptime row, still queues the page's links, and writes no page row and no title.

**`add_discovered(urls, depth)`**: `INSERT OR IGNORE` each normalized URL at the given depth, skipping any beyond `max_depth` and any whose host is `dead`, `gated` or `excluded`. It runs inside the caller's transaction, so it is private (`_queue`) and `seed` uses it too. New hosts get a `hosts` row in state `unknown`.

**`release_stale_leases()`**: any `leased` row with `lease_until < now` goes back to `queued`. Run at startup and every 5 minutes.

**`stats() -> dict`**: counts by status, hosts by state, pages stored, fetches in the last hour. Feeds `cli status`.

## 9. fetcher.py

One class, `Fetcher`, one per worker, bound to one `TorInstance`. Every anonymity control that lives in code lives here. Read this section twice.

### class Fetcher

Constructor takes the `Settings` and a `TorInstance`. Builds the fixed header dict once:

```python
HEADERS = {
    "User-Agent": settings.user_agent,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}
```

That is the header set Tor Browser sends. No `Referer`, ever. No `DNT`. No custom headers. httpx's default `python-httpx/x.y` agent is overwritten, not merged.

**`_client_for(host: str) -> httpx.AsyncClient`**

Returns a client whose transport is a SOCKS5 proxy to this worker's Tor instance with the username set to `host`. Clients are cached in a small dict keyed by host and evicted after 32 entries (LRU), so a long-running worker doesn't hold thousands of idle connections.

```python
proxy_type, proxy_host, proxy_port, _, _ = parse_proxy_url(self.tor.socks_url())
transport = AsyncProxyTransport(
    proxy_type=proxy_type, proxy_host=proxy_host, proxy_port=proxy_port,
    username=host, password="x", rdns=True, http2=False, trust_env=False,
)
client = httpx.AsyncClient(
    transport=transport, headers=HEADERS, http2=False,
    follow_redirects=False, trust_env=False, timeout=self.timeout,
)
```

Two corrections to the original snippet, found against httpx-socks 0.13: `AsyncProxyTransport.from_url(url, username=host)` raises `TypeError` because `from_url` already passes the username it parsed from the URL, so the transport is built from its parts. And with a custom transport the client's `http2` and `trust_env` flags do not reach the connection: `http2=False` must be on the transport to keep `h2` out of the TLS ALPN offer, and the transport's own `trust_env` defaults to True for its SSL context.

Each argument closes a hole. `rdns=True`: the hostname is sent to Tor unresolved, so no DNS query ever leaves Python. `username=host`: with `IsolateSOCKSAuth` in torrc this gives every onion site its own circuit. `http2=False`: Tor Browser negotiates HTTP/2 but onion services rarely serve it and the ALPN handshake is one more fingerprint. `follow_redirects=False`: redirects are handled by hand so a `Location` pointing at the clearnet is never followed. `trust_env=False`: httpx will not read `HTTP_PROXY` or `.netrc` from the environment, so nothing outside this code can change where traffic goes. `timeout`: an `httpx.Timeout(45.0, connect=20.0)`.

**`fetch(url: str) -> FetchResult`**

The only public method. `FetchResult` holds `url`, `final_url`, `status`, `headers`, `body` (bytes or None), `error` (str or None), `elapsed`.

Steps, in order:

1. `host = onion.host_of(url)`. Check `onion.is_v3_onion(host)`; if it fails, return `error="not_onion"` without creating a client or sending anything. This is a belt-and-braces check; the frontier should never hand over a bad host, but the fetcher doesn't trust it.
2. Get the client for the host. Send `GET` with `stream=True` so the body is read under control.
3. If the status is 301, 302, 303, 307, or 308: read `Location`, resolve it against the current URL, run it through `onion.normalize`. If it comes back None (clearnet, bad host, bad scheme), return a result with `error="redirect_offsite"` and stop. Otherwise loop, at most 3 hops, with the new URL and possibly a new host (which means a new client and a new circuit). A fourth redirect ends the fetch with `error="other:TooManyRedirects"`.
4. Check `Content-Type`. If it does not start with `text/html`, `application/xhtml`, or `text/plain`, close the response and return `error="not_text"`. No images, PDFs, archives, or binaries are ever read into memory.
5. Read the body in chunks via `aiter_bytes()`, stopping at `max_body_bytes`. If the cap is hit, keep what you have and mark `truncated=True`; a truncated page still yields links.
6. Clear the client's cookie jar: `client.cookies.clear()`. Do it in a `finally` so it happens even on error.
7. Call `self.tor.record(ok)` where ok means a response arrived with any status code (a 404 is still a live host).
8. Return the result.

**Error mapping**: any `httpx.TimeoutException` and python-socks' `ProxyTimeoutError` become `error="timeout"`. Tor refusing the connection (usually the service is offline or the descriptor can't be fetched) becomes `error="tor_unreachable"`; httpx-socks surfaces that as python-socks' `ProxyError` or `ProxyConnectionError`, not `httpx.ProxyError`, so all three are caught. Anything else becomes `error="other:<ExceptionName>"`. The crawler uses these strings to decide whether to retry, rotate, or park.

**`close()`**: closes every cached client.

### What the fetcher never does

No `allow_redirects` shortcut. No session persistence across hosts. No reading of `robots.txt` (onion sites rarely have one and fetching it doubles your request count; the per-host concurrency cap and jitter are the politeness controls). No HEAD requests before GET; they cost a full circuit round-trip and many onion servers answer them wrong.

## 10. parser.py

Pure functions over a bytes body. No network, no database. Returns a `PageInfo` dataclass: `title`, `headings` (list of h1 and h2 text), `links` (set of normalized onion URLs), `text_onions` (set of hosts found in raw text), `sha256`, `simhash`, `server` (the `Server` header value), `gated` (bool), `word_count`, `http_code`, and `size` (body bytes; the `pages` row needs both).

**`parse(url, status: int, body: bytes, headers) -> PageInfo`**

The orchestrator. Decodes the body (`utf-8` with `errors="replace"`; onion sites are sloppy about charsets), builds a selectolax `LexborHTMLParser` (selectolax 1.0 removed the old Modest `HTMLParser`; the API is the same), and calls the helpers below. `status` is there because `detect_gate` needs it. `visible_text` runs before `detect_gate`, so a DDoS-guard page full of inline JavaScript is judged on its visible words.

**`extract_links(tree, base_url) -> set[str]`**

Iterate `tree.css("a[href]")`, resolve each href against `base_url` with `urllib.parse.urljoin`, pass through `onion.normalize`, keep what survives. Also pull `href` from `link[rel=alternate]` and `area[href]`, and `action` from `form` tags (login pages often point at a different host). Skip `mailto:`, `javascript:`, and `data:` before resolving.

**`extract_text_onions(raw_text) -> set[str]`**

Calls `onion.find_onions_in_text` on the raw decoded body, not the parsed text, so addresses inside comments, scripts, and broken markup are caught. In practice this finds 2 to 4 times as many new hosts as anchor tags do.

**`extract_meta(tree) -> tuple[str, list[str]]`**

Title from `<title>`, trimmed to 200 characters. Headings from `h1` and `h2`, first 10, each trimmed to 120. Stored for search and for mirror detection by title.

**`detect_gate(tree, status) -> bool`**

True when the page is a captcha wall, login wall, or DDoS-guard interstitial. Signals: a `<form>` with an `<input type="password">` and under 300 words of text; an `<img>` whose `src` or `alt` contains `captcha`; a title matching `DDoS`, `checking your browser`, or `queue`, or a body under 300 words matching them (on a full page those are ordinary words, and a forum thread mentioning a queue is not a wall); HTTP 403 or 429 with under 50 words. A gated host is marked in the database and recrawled weekly only, since it yields nothing until it changes.

**`content_hash(body: bytes) -> str`**

sha256 hex of the raw bytes. Exact-duplicate detection and the storage filename.

**`simhash(text: str) -> int`**

64-bit simhash over word 3-shingles of the visible text (selectolax `tree.body.text()` after removing `script` and `style` nodes). For each shingle, take the 64-bit hash (`hashlib.blake2b(digest_size=8)`), and for each bit position add +1 if set, -1 if not, across all shingles; the final bit is 1 where the sum is positive. Two pages whose simhashes differ in 3 bits or fewer are near-duplicates. This is how you spot mirrors of the same market or forum running under different addresses, which the hash alone misses because of per-request tokens and timestamps.

**`visible_text(tree) -> str`**

Strips `script`, `style`, `noscript`, and `template` nodes, then returns the body text with whitespace collapsed. Used by simhash and word count. Not stored; the raw HTML is the record.

## 11. storage.py

One class, `PageStore`, that owns the `data/pages/` directory. Content-addressed: the file name is the sha256 of the raw body, so the same page fetched from three mirror addresses is stored once.

**`__init__(root: Path)`**: creates `root/pages`, sets directory mode 700.

**`path_for(sha256: str) -> Path`**: `pages/ab/cd/abcd...gz`, two levels of two-character prefixes so no directory ever holds more than a few thousand files.

**`save(sha256: str, body: bytes) -> bool`**: if the file exists, return False (already stored). Otherwise gzip the body at level 6, write to a temp file in the same directory, `os.replace` it into place so a crash never leaves a half-written page, set mode 600, return True. Called from the worker after a successful parse; the `pages` table row is written by `Frontier.complete` in the same step.

**`load(sha256: str) -> bytes`**: read and gunzip. Used by `cli export` and by any analysis you run later.

**`size_on_disk() -> int`**: walks the tree once for `cli status`. Expect roughly 15 KB per page compressed, so a million pages is about 15 GB.

What is not stored: images, scripts, stylesheets, fonts, anything that was not HTML or plain text. The fetcher already refuses them, and the store has no method that would accept them. That constraint is what keeps the disk free of content you don't want on it.

## 12. scheduler.py

Pure decision functions. Given what just happened to a URL or host, when should it be looked at again? Keeping this logic out of the database class makes it easy to tune without touching SQL. Each function that needs the time takes `now` as an argument instead of reading the clock, so the tests can pin it.

**`next_due_for_url(task, info, changed: bool, settings, now) -> datetime`**

- Gated page: `now + 7 days`, even at depth 0.

- Page changed since the last visit: `now + recrawl_active_hours`.
- Unchanged, and the host's `unchanged_streak` counting this visit is under 3: `now + 2 x recrawl_active_hours`.
- Unchanged 3 or more visits in a row, this one included: `now + recrawl_quiet_hours`.
- Depth 0 (a seed or a host root): never later than `recrawl_active_hours` regardless, because root pages are where new links show up.

**`next_due_for_failure(task, error: str, settings, now) -> datetime | None`** and **`retry_cost(error) -> int`**

- `timeout` or `tor_unreachable`: `now + 2^retries minutes`, counting this failure (2, 4, 8 as far as `max_retries` allows; at the default of 3 the third failure parks). Returns None once `retries` would reach `max_retries`. Onion services flap constantly; a timeout at 14:00 says little about 14:10.
- `redirect_offsite`, `not_text`, `not_onion`: None, meaning park the URL permanently. Nothing will change.
- `other:*`: same backoff as timeout but counted double toward `max_retries` (`retry_cost` returns 2), since it's usually a malformed response that will repeat.

**`host_is_dead(failures: list[datetime], settings) -> bool`**

True when there are `dead_after_failures` or more consecutive failures and the first and last are at least 24 hours apart. The time spread matters: five timeouts in five minutes is a bad circuit or a brief outage, not a dead service.

**`retest_due(host_row, settings, now) -> bool`**

For hosts in `dead` or `gated`: True when `last_down` (or, for a gated host, `last_up`, since the gate page was the last successful fetch) is older than `retest_dead_hours`. Never for `excluded`. `Crawler.maintenance_loop` calls this hourly and re-queues the host's root URL at priority 2 (below discovery and normal recrawls).

**`should_rotate(error: str, instance) -> bool`**

True for `tor_unreachable` when the instance's success rate is also under 0.5. A single unreachable host with a healthy instance is the host's fault, not the circuit's.

## 13. crawler.py

The `Crawler` class starts everything, runs the workers, and shuts down cleanly on Ctrl-C.

**`__init__(settings)`**: builds `Frontier`, `TorPool`, `PageStore`, and an `asyncio.Event` called `stopping`.

**`run()`**: the entry point `cli run` awaits.

1. `await frontier.open()`, `await tor_pool.start()`.
2. Install a SIGINT and SIGTERM handler that sets `stopping`.
3. Create `tor_instances x workers_per_instance` worker tasks, each `worker(i)`. Create `tor_pool.health_loop()` and `maintenance_loop()` as tasks.
4. `await stopping.wait()`, then cancel the loops, let each worker finish its current fetch (they check `stopping` between tasks), release any leases they still hold, close the pool and the database.

**`worker(worker_id: int)`**

The heart of the system. Each worker owns one `Fetcher` bound to `tor_pool.assign(worker_id)`.

```text
loop until stopping:
    tasks = await frontier.claim(1)
    if none: sleep 5 s, continue
    task = tasks[0]
    result = await fetcher.fetch(task.url)
    if result.error:
        await handle_failure(task, result)
    else:
        await handle_success(task, result)
    await asyncio.sleep(random.uniform(*settings.jitter_seconds))
```

Claiming one at a time (not a batch) keeps the lease window tight and lets 18 workers interleave hosts naturally.

**`handle_success(task, result)`**

1. `info = parser.parse(result.final_url, result.status, result.body, result.headers)`.
2. Safety: if `task.host` or the host of `final_url` is in the exclusion list, or `safety.body_triggers_exclusion` names a category, save nothing. Add the host to the in-memory exclusion set, `await frontier.exclude(task, info)`, log only the host and the category, and stop. Nothing between this check and `store.save` may await, so a page from a host that another worker just excluded is never stored.
3. If `info.gated`: the body is not stored; `complete` marks the host `gated`, records the URL as done with the weekly `next_due` from the scheduler, and skips link extraction. Links on a captcha page are the captcha vendor's, not the site's.
4. `changed = info.sha256 != task.last_hash`.
5. `store.save(info.sha256, result.body)`, skipped for a gated page.
6. `due = scheduler.next_due_for_url(task, info, changed, settings, now)`.
7. `await frontier.complete(task, info, due, page_path)`, which also queues every URL in `info.links` and `http://<host>/` for every host in `info.text_onions`.
8. Log one line: host, status, bytes, new links count, changed or not, elapsed. Never the title, never the URL path. Hosts are enough to debug with and the log stays safe to keep.

**`handle_failure(task, result)`**

1. `due = scheduler.next_due_for_failure(...)`, `retries = task.retries + scheduler.retry_cost(error)`, then `await frontier.fail(task, retries, due, host_answered=result.status is not None)`. Then the dead-host rule: `scheduler.host_is_dead(await frontier.recent_failures(host))`, and `frontier.mark_dead(host)` if so.
2. If `scheduler.should_rotate(result.error, fetcher.tor)`: `await tor_pool.rotate_for(fetcher.tor)`.
3. Log host and error string.

**`maintenance_loop()`**

Every 5 minutes: `frontier.release_stale_leases()`. Every hour: for each `dead` or `gated` host where `scheduler.retest_due` is True, re-queue its root. Once a day: `VACUUM` is not needed with WAL, but run `PRAGMA wal_checkpoint(TRUNCATE)` so the WAL file doesn't grow unbounded.

A note on concurrency: all 18 workers share one event loop, one database connection, and one process. There are no threads and no multiprocessing. Python handles this load easily because every worker spends 99% of its time waiting on Tor.

## 14. cli.py

Argparse with four subcommands. Entry point `python -m onioncrawl --settings <settings.toml> <command>` from the `crawler` user inside the venv.

**`seed <file>`**: reads one URL or bare onion host per line, skips blank lines and `#` comments, calls `Frontier.seed`. Prints how many were accepted and how many rejected by validation. Good first seeds: the Ahmia onion address, a couple of the long-running link directories, and anything you already know. Fifty good seeds is plenty; discovery does the rest.

**`run [--workers N]`**: loads settings, overrides `workers_per_instance` if given, builds `Crawler`, runs it until Ctrl-C. Logs to stderr and to `data/crawl.log` with rotation at 50 MB, 5 files. Library loggers are filtered to WARNING and up on the handlers themselves: httpx logs every request, full URL included, at INFO, and stem sets its own logger to TRACE, so the root logger's level is not enough.

**`status`**: prints `Frontier.stats()` and per-instance health as a short table: queued, leased, done, parked; hosts up, dead, gated, unknown; pages stored and disk size; fetches and success rate over the last hour; one line per Tor instance. Run it in a second terminal while `run` is going. Fetch rate under 1 per second across 18 workers means Tor is struggling, usually a bad guard on one instance; check the per-instance lines.

**`export [--since DATE] [--hosts | --pages | --uptime]`**: writes JSON lines to stdout. `--hosts` gives one record per host with state, title, first seen, last up, and uptime percentage computed from the `uptime` table. `--pages` gives page metadata (no bodies). `--uptime` dumps the raw log. Pipe into whatever analysis you want; the crawler itself stays dumb.

Every command refuses to run as root (`os.geteuid() == 0` raises) and refuses to run if `data_dir` is not owned by the current user. Small checks that stop the two most common ways of accidentally breaking the permission model.

## 15. Security hardening checklist and leak tests

Work through this before the first real run and again after any change to fetcher.py, the torrc files, or the firewall.

### Machine

- [ ] Dedicated VM, full-disk encryption on, snapshot taken after setup
- [ ] `crawler` user has no sudo and owns `data/` with mode 700
- [ ] Six `tor@crawlN` services running, each with `ClientOnly 1`, `SafeLogging 1`, `IsolateSOCKSAuth` on the SocksPort
- [ ] Control password file is mode 600, owned by `crawler`, outside the repo
- [ ] iptables OUTPUT chain: lo, SSH replies, six Tor UIDs, then DROP; ip6tables OUTPUT policy DROP; rules persisted
- [ ] No `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY` in the environment (irrelevant with `trust_env=False`, but keep the environment clean anyway)
- [ ] System clock synced over Tor or not at all (NTP from the crawler box is a clearnet packet; let the hypervisor set the clock)
- [ ] Unattended security updates off; update manually with the temporary firewall rule, then remove it

### Code

- [ ] Every outbound request goes through `Fetcher.fetch`; grep the codebase for `httpx.` and `urllib.request` and confirm no other call site
- [ ] `rdns=True`, `trust_env=False`, `follow_redirects=False`, `http2=False` on every client
- [ ] SOCKS username equals the target host on every request
- [ ] `onion.normalize` is the only path into the frontier, and `is_v3_onion` is the only thing that returns True for a host
- [ ] Cookies cleared in a `finally` block
- [ ] Logs contain hosts, status codes, byte counts, timings, and error names; never titles, paths, query strings, or body text
- [ ] Content-Type allowlist and 2 MB cap enforced before the body is read
- [ ] `requirements.txt` has hashes; `pip install --require-hashes` is the only install path

### Leak tests (run all four)

1. **Clearnet block.** As `crawler`, inside the test 3 capture: `curl -m 5 http://example.com` and `curl -m 5 https://1.1.1.1`. Any non-zero exit is acceptable and exit 0 is a hard fail. The kill switch ends in DROP, so a blocked attempt gets no reply and curl gives up after five seconds: a timeout (exit 28) is the expected failure mode under DROP, not a sign of a slow site, and the exit code proves nothing either way. The test passes on evidence of the drop: the DROP rule's packet counter rises across the two calls, the kernel log (from a temporary `LOG --log-uid` rule) shows the `crawler` UID's attempt to 1.1.1.1, and the capture holds zero packets to 1.1.1.1. `example.com` never gets an address: curl asks systemd-resolved over a local socket, so the attempt that reaches the firewall is the resolver's upstream query, logged under the resolver's UID, and the capture must hold zero DNS packets.
2. **DNS block.** As `crawler`: `dig example.com` and `python3 -c "import socket; socket.gethostbyname('example.com')"`. Both must fail.
3. **Packet capture.** As root in a second terminal: `tcpdump -ni any not port 22 and not host 127.0.0.1`. Start a crawl and watch for five minutes. Every packet should be from a Tor instance's UID to a Tor relay. Relays listen on many ORPorts (443 and 9001 are common, but 80, 4430, 8080, 9040 and others show up), so judge by the owning process, not the port. To confirm which process owns a connection: `ss -tnp | grep -v 127.0.0.1` should list only `tor` processes.
4. **Redirect trap.** Seed the frontier with a URL you control on a test onion service that returns a 302 to `https://example.com`. The crawler must log `redirect_offsite` and the tcpdump window must stay silent. If you don't run an onion service, add a unit test that feeds `Fetcher` a mocked 302 with a clearnet `Location` and asserts no second request is made.

If any test fails, stop and fix it before crawling. The firewall is the backstop; the code is the first line. Both must hold on their own.

### Operational habits

- Never open a stored page in a browser on this VM, or any browser that can load remote resources. Read bodies with `cli export` or a text editor.
- Never copy `data/` to an unencrypted location.
- Rotate the Tor control password and rebuild the VM from the snapshot every few months.
- Update `user_agent` whenever Tor Browser moves to a new Firefox ESR, otherwise you stand out as the one client still on the old string.

## 16. Build order, first run, tuning, troubleshooting

### Build order

Write and test in this sequence. Each step produces something you can run.

1. `onion.py` with unit tests. Use a few known-good v3 addresses from Ahmia and a few mangled ones. This is 30 minutes and it's the gate for everything else.
2. `config.py` and a settings file. Confirm `Settings.load` rejects a dead port.
3. `tor_pool.py`. Run a script that starts the pool, waits for ready, prints success rates, rotates one instance, and stops. Confirm NEWNYM works and the 10-second rate limit is respected.
4. `fetcher.py`. Fetch one known-live onion site and print status, bytes, elapsed. Then fetch `http://example.com` through it and confirm `is_v3_onion` rejects it before any request. Run leak test 3 while doing this.
5. `db.py` and `storage.py`. Seed five URLs, claim them, complete them with fake `PageInfo`, check the tables by hand with `sqlite3`.
6. `parser.py` against a few saved bodies from step 4. Compare link counts from anchors versus raw text.
7. `scheduler.py`, pure functions, quick tests.
8. `crawler.py` with one worker on one instance. Let it run 10 minutes. Read the log.
9. Scale to full workers. `cli status` in a second terminal.
10. `cli export` and the maintenance loop last.

You have a usable crawler after step 8. Steps 9 and 10 make it the one you keep.

### First run

Seed with 30 to 50 addresses. Expect the first hour to be slow while circuits warm up and the frontier fills. By hour two you should see 1 to 3 successful fetches per second across 18 workers and a few hundred new hosts discovered. Roughly half of all discovered onion hosts are offline at any moment; that's normal, and the uptime table is how you tell dead from flapping.

### Tuning

| Symptom | Likely cause | Change |
| --- | --- | --- |
| Fetch rate under 0.5/s, all instances healthy | Onion sites are just slow | Add instances (8 to 10), not workers per instance |
| One instance at 20% success, others at 70% | Bad guard | `rotate()` won't fix a guard; restart that `tor@crawlN` service to pick a new one |
| Thousands of `parked` URLs on a few hosts | Infinite pagination or calendar pages | Lower `max_depth` for those hosts or add a per-host URL cap of around 2,000 |
| Memory climbing | Client cache or body cap not enforced | Check `_client_for` eviction and the chunked read |
| Same content under many hosts | Mirrors | Query `pages` by simhash within 3 bits; crawl one mirror on the normal cadence and the rest weekly |
| `database is locked` errors | Write lock contention | Confirm WAL mode and `busy_timeout`; confirm only one process has the database open |

### Troubleshooting

- Tor won't become ready: check `journalctl -u tor@crawl1`. Usually a torrc typo or the hashed password line missing.
- `ProxyError` on every host on one instance: that instance's SOCKS port isn't listening or the control password is wrong; `ss -ltnp` and the journal.
- Everything times out at once: Tor's network is having a bad hour or your ISP is throttling Tor. Wait, don't thrash. If it persists, obfs4 bridges in each torrc fix the throttling case.
- A host shows `gated` but you can load it in Tor Browser: your `detect_gate` heuristic fired on a normal login form. Loosen the word-count threshold or whitelist the host.

At that point the system is complete: six circuits in parallel, a frontier that survives crashes, discovery from raw text, change and mirror detection, host uptime history, and a machine that cannot leak even when the code is wrong.
