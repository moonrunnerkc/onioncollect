# The crawler VM

`lima.yaml` and `provision.sh` build the machine from section 5 of `docs/build-guide.md` as a local
Lima guest named `node1`: Debian 13, Python 3.13, six `tor@crawlN` instances, the unprivileged
`crawler` user, its venv installed with `--require-hashes`, and the iptables/ip6tables kill switch.
Nothing runs in the cloud. Traffic and disk stay on this Mac.

## Commands (run from the repo root on the Mac)

| Command | What it does |
| --- | --- |
| `make vm` | Creates and boots the guest. First boot runs `provision.sh`. |
| `make provision` | Copies the current `provision.sh`, `torrc.template` and `requirements.txt` in and reruns it. Safe to repeat: a converged guest prints only `provision: converged`. |
| `make install` | Copies `onioncollect/` and `tests/` to `/home/crawler/app`, owned by crawler, and with `tools/` to `/opt/onioncollect/app`, owned by root, which the systemd units run. Installs the safety files from the checkout when they exist there, the units from `deploy/systemd/`, the checkout's `configs/*.toml` (a guest config the checkout lacks is kept unless `PRUNE_CONFIGS=1` and you type yes), and a new deploy stamp. |
| `make deploy` | `make install`, then the four leak tests, then the crawl timer, which starts only if they pass. A crawl or golive refuses a leak test result older than the deploy stamp or 36 hours. |
| `make shell` | A shell as `crawler` in the guest. All live steps run from here. |
| `make checklist` | Machine checklist. Guest items run in the guest; FileVault and the snapshot are checked on the Mac. |
| `make leak-test` | The four Tor leak tests of section 14 in the guest from the installed copy, with a five-minute packet capture. A root timer also runs them daily. |
| `make writeup-capture` | As the analyst: the write-up's evidence in one bundle under `/home/analyst/writeup-capture`, stripped of the testonion address, credential values and IPs. |
| `make crawl-capture` | Runs `crawl run` over the live sources with one worker on one Tor instance for `CRAWL_SECONDS` (default 600) under the leak test 3 capture, then audits the crawl log against the visited paths and the stored record text. Refuses to start with no live source. |
| `make crawl-full` | The same capture and audit with every Tor instance at `workers_per_instance`, plus each instance's peak SOCKS stream count against its worker count. Run `crawl status` from a second `make shell` meanwhile. |
| `make snapshot` | Stops the guest, APFS-clones its disk to `disk.snapshot`, starts it again. |

Roll back to the snapshot: `limactl stop node1 && cp -c ~/.lima/node1/disk.snapshot ~/.lima/node1/disk`.

## How it differs from a hand-built VM

- **plain mode.** No shared folders, no port forwarding, no Lima guest agent. Code goes in with
  `limactl copy`. SSH runs over vsock, so it isn't IP traffic inside the guest at all.
- **Provisioning on every boot.** Lima runs `provision.sh` at each boot. Every step checks state
  before changing it. When the kill switch is already loaded and something needs the network, the
  script opens a temporary hole for root, apt, crawler and the resolver (the section 3.4 update
  procedure) and reloads the saved rules on exit, including when it fails.
- **Files Lima inlines.** Lima copies `provision.sh`, `torrc.template` and `requirements.txt` into
  the instance at create time; they seed only the first boot (`overwrite: false`). After that,
  `make provision` is how changes reach the guest. `requirements.txt` here is a symlink to the
  repo root copy because Lima rejects `..` in file paths.
- **Control password.** Generated in the guest into `/home/crawler/control-password` (mode 600,
  owned by crawler). The hash for torrc is computed by `provision.sh` from that file, so the
  plaintext never appears on a command line, in a log, or in this repo.
- **Safety files.** `provision.sh` creates an empty `/home/crawler/exclusions.txt` (mode 600) and
  points `settings.toml` at it and at `/home/crawler/safety-patterns.txt`. The pattern list is not
  committed; `make deploy` installs each of `safety-patterns.txt` and `exclusions.txt` from the checkout when it exists there (both are gitignored).
  The crawler refuses to start if either file is missing or lists nothing, so add at least one
  host to `exclusions.txt` before the first run. Both are operator config the repo never holds.
- **Data, configs and the salt.** `provision.sh` creates `/home/crawler/data` and
  `/home/crawler/configs` (mode 700) and a `/home/crawler/redaction-salt` (mode 600) that is never
  regenerated, since a new salt would orphan every keyed hash already stored. The crawler owns all
  three. The `analyst` user reads the data dir through its group (2750 crawler:analyst) and runs the
  search UI and the read-only commands with `/home/analyst/settings.toml`, which names no secret file.
  It has no firewall rule of its own, so it reaches loopback only. The local socket service the
  crawler writes through is not provisioned yet; until it is, the commands that write run as crawler.
- **Root-owned runtime.** `/opt/onioncollect/venv` (same hashes as the crawler's venv) and
  `/opt/onioncollect/app` are root's, so the user a systemd unit runs as cannot change the code it runs.
- **Right after `make provision`.** The update hole closes while apt's TLS connections to the Debian
  and Tor Project mirrors are still shutting down. For about 15 minutes those mirrors keep
  retransmitting; the guest's replies are dropped, and leak test 3 reports the inbound packets as
  not on a Tor socket. Nothing leaves the guest, but wait before running the leak tests.
- **Clock.** NTP is masked; the hypervisor sets the clock at boot. Without the Lima guest agent
  there is no resync after the Mac sleeps, so after a long sleep restart the guest
  (`limactl stop node1 && limactl start node1`) if Tor complains about clock skew.
- **Snapshots.** The vz driver has no snapshot support, so `make snapshot` clones the stopped disk.

## Encryption

Disk encryption comes from the host: FileVault encrypts the guest disk image at rest. FileVault must be
on before the first real crawl; `make checklist` fails until it is. Moving `data/` onto a LUKS
volume inside the guest is a possible later change if host encryption alone stops being enough.
