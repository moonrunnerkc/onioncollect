# onioncollect

A collection platform for benign public onion services, built by one operator as a working sample for a
collections analyst role. It takes a source from candidate to live collection over Tor, extracts structured
records with a reviewed config per source, keeps them redacted and searchable, and measures every source's health.
The sources are news organizations' onion mirrors, SecureDrop instances, software projects, privacy services and
the directories that list them. It never logs in anywhere but one onion service the operator hosts, never submits a
form, posts, buys or messages, and never stores an unredacted credential.

The full design is [docs/build-guide.md](docs/build-guide.md). What collecting taught me is
[docs/writeup.md](docs/writeup.md).

## Where to find each piece

| What | Where |
| --- | --- |
| Source policy | [docs/build-guide.md, section 3](docs/build-guide.md#3-source-policy); enforced by `lifecycle.CATEGORIES` and `triage approve` / `triage decline` in [onioncollect/cli.py](onioncollect/cli.py) |
| Triage log, approvals and declines with reasons | `sources export` writes every host with its state, reviewer and reason; [PASTE: excerpt of sources-export.jsonl with at least two declines and their reasons] |
| Configs with hit-rate history | Reviewed TOML configs under `configs/` (kept in the guest until the first real set is copied back) and [testonion/config-public.toml](testonion/config-public.toml); history from `health runs <id>` and the search UI's source page. [PASTE: health runs for two sources] |
| A health item that went degraded to fixed or mirror-swapped, with the diff | `health log` records every disposition; [PASTE: health log line for the item, and the config diff that fixed it] |
| A go-live that failed a check, then passed | Every `golive` report is kept (`golive_reports`); [PASTE: golive output for one source, the failing run then the passing one] |
| The self-hosted onion's auth config | [testonion/config-session.toml](testonion/config-session.toml), the app in [testonion/app.py](testonion/app.py), its VM setup in [testonion/setup.sh](testonion/setup.sh) |
| The containment test that bounds it | `AuthContainmentTest` in [tests/test_network_boundary.py](tests/test_network_boundary.py); behaviour in [tests/test_fetcher_auth.py](tests/test_fetcher_auth.py) and [tests/test_session.py](tests/test_session.py). The auth step is `Fetcher.log_in`, `Fetcher._post_form` and `Fetcher._session_for` in [onioncollect/fetcher.py](onioncollect/fetcher.py) |
| Leak tests | The four Tor leak tests run live in the guest: [tests/live/leak_test.sh](tests/live/leak_test.sh), daily on a timer and at the end of every deploy. A crawl and `golive` both refuse a result older than 36 hours or older than the current deploy. [PASTE: latest leak-test.json from the capture bundle] |
| Boundary tests | Section 17's five, mapped to their tests in the docstring of [tests/test_network_boundary.py](tests/test_network_boundary.py), plus `UIContainmentTest` for the search UI |
| CI | [.github/workflows/ci.yml](.github/workflows/ci.yml) runs the whole unit and boundary suite. [PASTE: CI badge or link to a green run] |
| Search UI | [onioncollect/ui.py](onioncollect/ui.py) and [onioncollect/views.py](onioncollect/views.py): read-only, standard library, 127.0.0.1 only. Started by its own entry point, [onioncollect/ui_main.py](onioncollect/ui_main.py), never through the CLI, so the process loads no network library ([tests/test_ui_entry.py](tests/test_ui_entry.py)) |
| Write-up | [docs/writeup.md](docs/writeup.md) |

## Running it

Everything runs in a hardened Lima VM (section 5 of the guide). `make provision` builds it, `make deploy` installs
the code and the systemd units and ends by running the leak tests, and the crawl then runs on a quarter-hour timer
that fetches only what each source's cadence says is due. The search UI runs as the `analyst` user on 127.0.0.1:8470
inside the guest, started by `onioncollect-ui.service` as
`python -m onioncollect.ui_main --data-dir DIR --configs-dir DIR --port 8470`. It has its own entry point, not a
CLI subcommand, so the UI process imports only the UI, its views and search, and the standard library. Reach it
with an SSH forward through Lima's ssh config:

```
ssh -F ~/.lima/node1/ssh.config -N -L 8470:127.0.0.1:8470 lima-node1
```

then open http://127.0.0.1:8470/. `make test` runs the suite locally; `make writeup-capture` gathers the
write-up's evidence in the guest; `make writeup-check` lists any write-up marker still waiting for data.
