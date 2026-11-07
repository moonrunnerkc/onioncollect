# Breach Exposure Monitor — Build Guide

## 1. What you're building

A breach-exposure monitoring pipeline for companies you are authorized to monitor. It tells you, with evidence, when a client's data appears to be exposed or offered somewhere it shouldn't be, and it routes that to a human for confirmation and reporting. It is a detection and alerting system, not a collection system. Nothing about it acquires, accumulates, or retains stolen data.

Three ideas define the whole design, and every later section serves them:

1. Feeds first, crawler last. Most exposure is detectable through lawful, structured sources that already do the hard work. The Tor component is a narrow last mile for a curated set of sources those feeds don't cover, not the center of the product.
2. Scoped, not exploratory. The system watches a known source list for a known target list (your clients). It never discovers or indexes where data is sold, and it never builds a map of that ecosystem.
3. Ephemeral by default, findings only. Pages are processed in memory and discarded. The only thing that ever reaches disk is a redacted finding tied to an authorized target. There is no page corpus, no credential store, no dump archive, because the code has nowhere to put one.

The output is a stream of confirmed findings of the form "client X appears exposed on source Y as of time Z, claim is N records of type T, here is redacted evidence," suitable for notifying the client and, where warranted, the affected company, a CERT, or law enforcement.

This replaces the earlier general-crawler plan. The Tor plumbing from that plan carries over intact; its purpose is now operator safety while monitoring, and its outputs feed the matcher instead of a page store.

## 2. Hard non-goals, enforced in code

These are the lines that separate breach-exposure monitoring from trafficking. Each is enforced by the code or the OS, not by discipline, so a bug or a bad night can't cross them.

| Non-goal | How the code prevents it |
| --- | --- |
| Never download a dump or any non-text payload | Text-only, Content-Type allowlist (`text/html`, `application/xhtml`, `text/plain`), 2 MB read cap. Binaries and archives are refused before the body is read. |
| Never persist a page that doesn't match an authorized target | Storage is match-gated. A fetched body lives in memory only; if the matcher finds no authorized-target hit, the body is dropped and nothing but scheduling metadata (host reachable, when) is kept. |
| Never store plaintext credentials or PII | The redaction gate runs before any write. The storage layer has no method that accepts a raw body, and it rejects any write whose payload still contains a detectable secret pattern. |
| Never validate, replay, or submit a credential | No login, no form submission, no auth flows anywhere in the codebase. "Does this credential still work" is not a feature and is banned at review. This is account compromise under the CFAA regardless of intent. |
| Never engage a seller or marketplace | No posting, no messaging, no purchase, no account creation. The system reads public listing text and nothing else. |
| Never leave Tor, never follow a clearnet link | Firewall drops all non-Tor egress from the crawler user; only `.onion` hosts are ever fetched; redirects are checked, not followed. (Carried over from the original plan.) |

Treat the match-gated storage and the redaction gate the way you treat the firewall: controls that make every other mistake survivable.

## 3. Authorization, lawful basis, and data handling

This is a product that touches other people's data, so the paperwork is part of the architecture, not an afterthought. None of the below is legal advice; have counsel review before you operate this commercially, especially around CFAA, ECPA, and state stolen-data-possession statutes in Colorado and any client's jurisdiction.

What has to exist before the first run:

1. Written authorization per client, with an explicit scope: which company names, which domains, which brands. The target list is a contractual artifact, not a config convenience. You monitor only what a signed client has authorized.
2. A documented lawful basis for processing (contractual necessity plus legitimate interest is the usual pairing) and a retention policy. Redacted findings get a retention clock; expired findings are deleted. You keep evidence of exposure, not a growing library of it.
3. An incidental-data procedure. You will see third parties' data that isn't your client's. The rule: do not persist it, record only the source and timestamp if anything, and report through a proper channel (the affected org, a sector ISAC, IC3/FBI, or a CERT) if it's clearly actionable. You never collect it "just in case."
4. A handling and access policy for the findings DB: who can read it, encryption at rest, access logging, and a breach plan for your own system. A breach-monitoring tool that gets breached is the worst headline available to you.

For Aftermath's buyers this section is also the sales asset. Compliance customers diligence exactly this, and "here is our authorization model and our data-minimization proof" is more convincing than any feature.

## 4. Architecture overview

The pipeline, left to right:

```
feeds ─────────────┐
                    ├─► normalizer ─► matcher ─► redaction gate ─► findings DB ─► review queue ─► reporter
scoped Tor crawler ─┘                   │
                                        └─ (no match) ─► discard body
```

Feeds and the crawler are just two kinds of source that produce the same thing: candidate records of "some text, from some source, at some time." Everything after the normalizer is identical regardless of where the text came from, which keeps the sensitive logic (matching, redaction, storage) in one place you can audit.

Component responsibilities:

- Feed adapters pull structured exposure data from lawful providers and emit normalized candidates. No Tor involved.
- The scoped crawler fetches pages from a curated source list over Tor and emits the same normalized candidates. Its frontier is seeded only from the source list; it does not expand into discovered markets.
- The matcher tests each candidate against the authorized target list. No hit, no persistence.
- The redaction gate converts a hit into a redacted finding: claims and counts kept, secrets replaced by type plus count plus salted hash.
- The findings DB stores only redacted findings. The review queue is a status on those rows.
- The reporter turns a human-confirmed finding into a client notification and, where warranted, an outbound report to the affected org or authorities.

## 5. Operator safety (the carried-over hardening, restated)

Every anonymity control from the original plan stays, because accessing leak sources exposes the operator, not because you're hiding collection. Restated purpose, same mechanics:

- Dedicated, full-disk-encrypted VM; two users; snapshot after setup.
- Six to ten Tor instances via `tor-instance-create`, each `ClientOnly 1`, `SafeLogging 1`, `IsolateSOCKSAuth`, per-instance system user.
- The firewall kill-switch: iptables OUTPUT allows loopback, SSH replies, and the Tor UIDs only, then DROP; ip6tables OUTPUT policy DROP. The crawler user cannot send a packet off the box.
- Pinned reproducible dependencies with hashes.

The full environment setup (sections 3.1 to 3.4 of the original plan) is unchanged. The one addition: the findings DB and evidence store live on the encrypted disk with directory mode 700, and the review/reporter tooling runs under a separate user from the crawler so that analyst access to findings never needs the crawler's circuits.

## 6. Feed ingestion (build this first)

This is where 80% of the value comes from, and none of it touches an onion site.

1. Have I Been Pwned domain search. HIBP's domain-search API returns which breaches include addresses on a domain you control or are authorized for. It requires domain verification, which is exactly the authorization gate you want anyway. This alone covers a large share of "is my client's email estate in a known breach." Reasoning: lawful, structured, verification-gated, and it's the baseline every client expects.
2. Commercial CTI feeds. SpyCloud, Flashpoint, Recorded Future, DeHashed, IntelX and similar already crawl markets and forums under their own legal frameworks and sell normalized output, usually with APIs. Build one adapter against whichever you license; keep the adapter interface generic so swapping providers is a config change. Reasoning: you buy the risky collection as a service from entities set up to do it legally, instead of reproducing it.
3. A normalizer that maps each provider's schema onto your candidate shape: `source`, `observed_at`, `target_hint` (domain or org if the feed already attributes it), `text` (the listing or record description), `claim` (record count, data types), and `raw_secret_spans` (locations of credential/PII-looking substrings, for the redaction gate; never the values themselves past that stage).

Build and ship this feeds-only version first. It's a complete, useful product on its own, and it has no Tor surface at all. The crawler is an enhancement you add once this is solid.

## 7. The two watchlists

Two curated lists, both version-controlled, both reviewed.

- Source list. Specific leak forums, paste sites, and onion sources you already know and have decided to monitor. This is the crawler's entire universe. New sources are added by a human after review, never discovered and auto-added. Reasoning: a curated source list is the difference between monitoring known places and indexing the ecosystem. The crawler's frontier is seeded from this list and from same-source links only; it does not queue hosts found in page text.
- Target list. The company names, domains, brand terms, and authorized identifiers for each client under contract. Each entry references the authorizing client and contract. Reasoning: the target list is what gates persistence, so it's effectively your authorization boundary expressed as data.

A deliberate change from the original crawler: `find_onions_in_text` and cross-host link discovery are removed. The crawler follows links only within a source already on the list, up to a shallow depth, to page through that source's own listings. It never adds a new host from page content.

## 8. The scoped crawler

Mechanically this is the original `tor_pool` / `fetcher` / frontier design, with three changes.

What carries over unchanged: the Tor pool with per-instance health and NEWNYM rotation; the fetcher's anonymity-critical client config (SOCKS5 with `rdns=True`, per-host SOCKS username for circuit isolation, `http2=False`, `follow_redirects=False`, `trust_env=False`, fixed Tor Browser headers, cookies cleared in a `finally`); v3 onion validation; the 45 s budget, 2 MB cap, and Content-Type allowlist; WAL-mode SQLite frontier that survives crashes.

The three changes:

1. The frontier is seeded only from the source list, and `add_discovered` accepts only URLs whose host is already on the source list. Off-source links are dropped silently. This is the code expression of "scoped, not exploratory."
2. `handle_success` no longer stores the page. It hands the in-memory body to the normalizer, then the matcher. If there's no authorized-target match, the body is discarded; only the host's reachability and timestamp are written (for recrawl scheduling). There is no `PageStore`, no `pages/` directory, no raw-HTML on disk.
3. Recrawl cadence is driven by source volatility (a busy forum's index pages are checked often; a static paste rarely) rather than by content-change detection, since you're not keeping content to diff. Uptime history stays; it's useful and harmless.

The `onion.py` validation gate, including `is_v3_onion`, stays exactly as speced; it's still the only thing that lets a host through:

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

## 9. The matcher

A single stage that tests a normalized candidate against the target list and returns the matched target plus the spans that matched, or nothing.

- Match on domains, company names, and authorized brand terms, with normalization for the obvious evasions (spacing, common substitutions) but no fuzzy sprawl that would pull in unrelated orgs. Precision matters more than recall here; a false "your client is exposed" is expensive.
- A match carries the target's authorizing client, so everything downstream is already scoped to who's allowed to see it.
- No match means the candidate ends here and its body is dropped. This is the gate that keeps the system from retaining anything about anyone you're not authorized to monitor.

Keep the matcher rules in data (the target list), not code, so adding a client is a reviewed list change, not a deploy.

## 10. The redaction gate

The load-bearing change, and the reason the system can prove a breach without holding one.

On a match, you build a finding that captures the shape of the exposure and none of the payload:

- Kept in clear: source, observed-at timestamp, matched target and client, the seller's or poster's claims (record count, data types, price if stated), and the surrounding listing text with secrets stripped out.
- Replaced: every credential- or PII-looking span is swapped, before anything is written, for a tag plus a count plus a salted hash. So a sample block of 500 logins becomes "500 email:password pairs, domain acme.com, sample hashes [...]." You store the hashes, never the values.

Why hashes and counts are enough: you can confirm the exposure is real and quantify it, you can later check a hash against a client's own known accounts to see whether live credentials are implicated, and you can deduplicate findings across sources, all without your database ever containing a usable credential or a person's data. Use a per-deployment salt kept with the same care as the Tor control password, so the hashes aren't reversible via precomputed tables and aren't portable if the DB leaks.

Detection patterns to redact: email:password and user:password pairs, long credential-shaped tokens, card-number patterns, national-ID patterns, and bulk email lists. When in doubt, redact; a missed secret is a stored secret, which is the one failure this gate exists to prevent. The storage layer runs the same detector as a second check and refuses any write that still trips it.

## 11. Storage

Two small stores, both holding only redacted findings.

- Findings DB (SQLite, WAL). One row per confirmed-or-pending finding: id, client, target, source, observed_at, claim fields, status (`new`, `in_review`, `confirmed`, `dismissed`, `reported`), reviewer, and a pointer to the evidence artifact. Indexed by client and status for the review queue and reports.
- Evidence store. The redacted listing text and the sample hashes for each finding, content-addressed, directory mode 700, retention clock applied. This is what you'd attach to a client notification or an authority report.

There is deliberately no raw-page store and no credential store. If a future requirement seems to need one, that's the signal to stop and reread section 2, not to add a table.

## 12. Review queue and reporting

A human gate sits between detection and any outbound action, because automated breach claims are faked and recycled constantly, and a false alarm to a client or an authority costs you credibility you can't rebuild.

- Review queue. Findings land as `new`. An analyst (running under the separate findings user, not the crawler) confirms or dismisses, with a note. Only `confirmed` findings can be reported.
- Report format. Client, source, observed-at, the claim, the redacted evidence and sample hashes, and a confidence note. Enough for the client's security team to act, with nothing in it that would make the report itself a liability to send.
- Channels. Client notification first. Where the finding implicates a company that isn't your client, or clearly rises to a crime, report through a proper channel (the affected org's disclosure contact, a sector ISAC, IC3/FBI, or a national CERT) per the handling procedure in section 3. Log every outbound report.

## 13. CLI

Reoriented around the pipeline. Entry point `python -m breachmon <command>`, each refusing to run as root and checking data-dir ownership.

- `feeds pull` — run the feed adapters, normalize, match, and queue findings. No Tor. This is the command you schedule most often.
- `watchlist` — manage the source and target lists (`add`, `remove`, `list`), with each target change requiring a client/authorization reference. Rejects a target with no authorization on file.
- `crawl run [--workers N]` — run the scoped Tor crawler against the source list, feeding the same matcher. Logs hosts, status codes, timings, and error names only; never listing text, never matched values.
- `review` — work the queue: show `new` findings, confirm or dismiss with a note.
- `report <finding-id>` — generate the report artifact for a confirmed finding and record the outbound channel.
- `findings export [--client] [--since]` — redacted findings as JSON lines, for a client handoff or your own metrics. There is no command that exports raw pages or secrets, because none exist to export.

## 14. Verification and leak tests

Run the original four leak tests (clearnet block, DNS block, packet capture, redirect trap) before any crawl, unchanged; they still guard the Tor boundary. Add four that guard the new boundaries:

1. Match gate. Feed the pipeline a page that matches no target and assert nothing is written beyond host reachability metadata, and the body is not on disk anywhere.
2. Redaction gate. Feed a matching page containing synthetic credentials and assert the stored finding contains counts and hashes only, and that a grep of the entire data dir for the synthetic plaintext returns nothing.
3. Storage refusal. Call the storage layer directly with a payload that still contains a secret pattern and assert it refuses the write.
4. No-auth invariant. Grep the codebase for any HTTP method other than GET, any form submission, and any login flow, and assert there are none. Wire this into CI so a future change that adds one fails the build.

If any test fails, stop. The firewall, the match gate, and the redaction gate each have to hold on their own.

## 15. Build order

1. Feed adapters plus the normalizer, matcher, redaction gate, findings DB, and review CLI. This is a complete, Tor-free, shippable product. Prove the match gate and redaction gate with their tests here, before any onion traffic exists.
2. The reporter and the authorization/handling paperwork. Now you can run a real client end to end on feeds alone.
3. The environment hardening and Tor pool (carried over from the original plan), with the four original leak tests.
4. The scoped crawler, wired into the same matcher, with its source-list-only frontier. Run the four new boundary tests before and after.
5. Scale, schedule `feeds pull` and `crawl run`, and add metrics: findings per client, confirmed-vs-dismissed rate (your matcher precision), and time from observation to client notification.

You have a useful, lawful product after step 2. Steps 3 and 4 extend coverage to sources the feeds miss, under the same guarantees.
