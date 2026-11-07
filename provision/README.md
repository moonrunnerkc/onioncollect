# The crawler VM

`lima.yaml` and `provision.sh` build the machine from section 3 of `docs/build-guide.md` as a local
Lima guest named `node1`: Debian 13, Python 3.13, six `tor@crawlN` instances, the unprivileged
`crawler` user, its venv installed with `--require-hashes`, and the iptables/ip6tables kill switch.
Nothing runs in the cloud. Traffic and disk stay on this Mac.

## Commands (run from the repo root on the Mac)

| Command | What it does |
| --- | --- |
| `make vm` | Creates and boots the guest. First boot runs `provision.sh`. |
| `make provision` | Copies the current `provision.sh`, `torrc.template` and `requirements.txt` in and reruns it. Safe to repeat: a converged guest prints only `provision: converged`. |
| `make deploy` | Copies `onioncrawl/` and `tests/` to `/home/crawler/app`, owned by crawler. |
| `make shell` | A shell as `crawler` in the guest. All live steps run from here. |
| `make checklist` | Section 15 machine checklist. Guest items run in the guest; FileVault and the snapshot are checked on the Mac. |
| `make leak-test` | Section 15 leak tests 1 to 4 in the guest, with a five-minute packet capture. |
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
- **Clock.** NTP is masked; the hypervisor sets the clock at boot. Without the Lima guest agent
  there is no resync after the Mac sleeps, so after a long sleep restart the guest
  (`limactl stop node1 && limactl start node1`) if Tor complains about clock skew.
- **Snapshots.** The vz driver has no snapshot support, so `make snapshot` clones the stopped disk.

## Encryption

Disk encryption comes from the host: FileVault encrypts the guest disk image at rest. FileVault must be
on before the first real crawl; `make checklist` fails until it is. Moving `data/` onto a LUKS
volume inside the guest is a possible later change if host encryption alone stops being enough.
