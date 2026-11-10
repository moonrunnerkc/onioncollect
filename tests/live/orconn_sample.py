"""Leak test 3's describing witness: each Tor instance's own list of its relay connections, sampled every second.

Usage (guest, as crawler): orconn_sample.py PASSWORD_FILE > ORCONN_SAMPLES
Tor names a relay here, not a connection, so leak_analyze.py credits no packet by it. When a packet has no
owner, the list says whether a Tor instance held a connection to that relay during the window, which tells a
late packet on a connection closed before the pre-roll from traffic Tor knows nothing about. Each line is
`UID ADDRESS PORT`: the instance's uid and the relay's address and ORPort, from the consensus.
"""
import os
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
    # Started by runuser for the capture window; once runuser is gone, nothing will read another sample.
    parent = os.getppid()
    instances = []
    for n in INSTANCES:
        controller = Controller.from_port(address="127.0.0.1", port=CONTROL_PORT_BASE + n)
        controller.authenticate(password=password)
        instances.append((pwd.getpwnam(f"_tor-crawl{n}").pw_uid, controller, {}))
    while os.getppid() == parent:
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
