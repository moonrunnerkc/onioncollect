"""Leak test 3's third witness: each Tor instance's own list of its relay connections, sampled every second.

Usage (guest, as crawler): orconn_sample.py PASSWORD_FILE > ORCONN_SAMPLES
A connection Tor opened before the capture window has no line in the kernel's flow log, and ss samples only
established sockets, so one that never shows as established while the window is open has no owner on either.
Tor still lists it. Each line is `UID ADDRESS PORT`: the instance's uid and the relay's address and ORPort,
from the consensus. A relay the consensus does not name is left out, so its packets stay unattributed.
"""
import pwd
import sys
import time
from pathlib import Path

import stem
from stem.control import Controller

INSTANCES = range(1, 7)
# provision/torrc.template: instance N's control port is 1105N.
CONTROL_PORT_BASE = 11050


def relay_endpoint(controller, server_id: str, cache: dict) -> tuple[str, int] | None:
    # orconn-status names a relay as $FINGERPRINT~nickname, or as address:port until Tor knows its identity.
    if not server_id.startswith("$"):
        host, _, port = server_id.rpartition(":")
        return (host, int(port)) if host and port.isdigit() else None
    fingerprint = server_id[1:].split("~")[0].split("=")[0]
    if fingerprint not in cache:
        try:
            status = controller.get_network_status(fingerprint)
            cache[fingerprint] = (status.address, status.or_port)
        except (stem.ControllerError, ValueError):
            cache[fingerprint] = None
    return cache[fingerprint]


def main(password_file: Path) -> None:
    password = password_file.read_text().strip()
    instances = []
    for n in INSTANCES:
        controller = Controller.from_port(address="127.0.0.1", port=CONTROL_PORT_BASE + n)
        controller.authenticate(password=password)
        instances.append((pwd.getpwnam(f"_tor-crawl{n}").pw_uid, controller, {}))
    while True:
        print(f"sample {int(time.time())}")
        for uid, controller, cache in instances:
            try:
                lines = controller.get_info("orconn-status", "").splitlines()
            except stem.ControllerError:
                continue
            for line in lines:
                endpoint = relay_endpoint(controller, line.split(" ", 1)[0], cache)
                if endpoint:
                    print(uid, *endpoint)
        sys.stdout.flush()
        time.sleep(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
