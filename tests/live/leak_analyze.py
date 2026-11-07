"""Leak test 3 analysis: every packet that left the guest must belong to a tor-owned connection.

Usage (guest, as crawler): leak_analyze.py CAPTURE_TXT SS_SAMPLES FLOW_LOG LOCAL_IP PASSWORD_FILE
CAPTURE_TXT is `tcpdump -r cap.pcap -nn -q -tt` output. FLOW_LOG is the kernel's LOG --log-uid line for
every new outbound flow during the window. SS_SAMPLES (repeated `ss -tnpH state established`) covers
connections Tor opened before the window started.
"""
import ipaddress
import pwd
import re
import sys
from collections import Counter
from pathlib import Path

from stem.control import Controller

SS_LINE = re.compile(r"\S+\s+\S+\s+(\S+):(\d+)\s+(\S+):(\d+)\s+users:\(\(\"([^\"]+)\"")
FLOW_LINE = re.compile(r"DST=(\S+) .*?PROTO=(\w+)(?: SPT=\d+ DPT=(\d+))?.*?UID=(\d+)")
DHCP_PORTS = {67, 68}
TOR_UIDS = {pwd.getpwnam(f"_tor-crawl{n}").pw_uid for n in range(1, 7)}


def split_endpoint(token: str) -> tuple[str, int | None]:
    token = token.rstrip(":")
    host, _, port = token.rpartition(".")
    if port.isdigit() and host:
        return host, int(port)
    return token, None


def parse_capture(path: Path, local_ip: str):
    packets = []
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[1] not in ("IP", "IP6"):
            continue
        src, dst = split_endpoint(parts[2]), split_endpoint(parts[4])
        outbound = src[0] == local_ip
        remote = dst if outbound else src
        protocol = parts[5].rstrip(",").lower() if len(parts) > 5 else "?"
        packets.append({"family": parts[1], "outbound": outbound, "remote": remote, "protocol": protocol})
    return packets


def parse_sockets(path: Path, local_ip: str):
    owners: dict[tuple[str, int], set[str]] = {}
    for match in SS_LINE.finditer(path.read_text()):
        local, _, peer, peer_port, process = match.groups()
        if local != local_ip:
            continue
        owners.setdefault((peer, int(peer_port)), set()).add(process)
    return owners


def parse_flows(path: Path) -> dict[tuple[str, int | None], set[int]]:
    flows: dict[tuple[str, int | None], set[int]] = {}
    for line in path.read_text().splitlines():
        match = FLOW_LINE.search(line)
        if match:
            dst, _, port, uid = match.groups()
            flows.setdefault((dst, int(port) if port else None), set()).add(int(uid))
    return flows


def consensus_relays(password_file: Path) -> set[tuple[str, int]]:
    with Controller.from_port(address="127.0.0.1", port=11051) as controller:
        controller.authenticate(password=password_file.read_text().strip())
        return {(entry.address, entry.or_port) for entry in controller.get_network_statuses()}


def main(capture: Path, samples: Path, flow_log: Path, local_ip: str, password_file: Path) -> int:
    packets = parse_capture(capture, local_ip)
    owners = parse_sockets(samples, local_ip)
    flows = parse_flows(flow_log)
    relays = consensus_relays(password_file)
    subnet = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    failures = []
    non_tor = {endpoint: procs for endpoint, procs in owners.items() if procs != {"tor"}}
    for endpoint, procs in non_tor.items():
        failures.append(f"socket to {endpoint[0]}:{endpoint[1]} owned by {sorted(procs)}")

    dhcp, ipv6, attributed = 0, 0, Counter()
    for packet in packets:
        host, port = packet["remote"]
        if packet["family"] == "IP6":
            ipv6 += 1
            failures.append(f"IPv6 packet to/from {host}")
            continue
        if port in DHCP_PORTS and ipaddress.ip_address(host) in subnet:
            dhcp += 1
            continue
        flow_uids = flows.get((host, port))
        if flow_uids is not None and flow_uids <= TOR_UIDS:
            attributed[(host, port)] += 1
        elif flow_uids is None and owners.get((host, port)) == {"tor"}:
            attributed[(host, port)] += 1
        else:
            failures.append(f"{packet['protocol']} packet {'to' if packet['outbound'] else 'from'} {host}:{port} not on a tor socket")

    on_wire = {packet["remote"] for packet in packets}
    blocked = {(dst, uid) for dst, uids in flows.items() for uid in uids - TOR_UIDS if dst not in on_wire}
    endpoints = set(attributed)
    in_consensus = endpoints & relays
    outbound = sum(1 for p in packets if p["outbound"])
    print(f"captured packets: {len(packets)} ({outbound} outbound, {len(packets) - outbound} inbound)")
    print(f"remote endpoints: {len(endpoints)}, all on tor-owned sockets: {not failures}")
    print(f"endpoints listed in the Tor consensus as relays: {len(in_consensus)}/{len(endpoints)}")
    print(f"remote ports: {dict(Counter(port for _, port in endpoints).most_common())}")
    print(f"protocols: {dict(Counter(p['protocol'] for p in packets))}")
    print(f"DHCP to local gateway: {dhcp}, IPv6: {ipv6}")
    print(f"non-tor sockets seen by ss: {len(non_tor)}")
    print(f"new flows logged by the kernel: {sum(len(u) for u in flows.values())}, "
          f"from tor UIDs: {sum(len(u & TOR_UIDS) for u in flows.values())}")
    for (dst, port), uid in sorted(blocked, key=str):
        print(f"blocked before the wire: uid {pwd.getpwuid(uid).pw_name} -> {dst}:{port}")
    for failure in sorted(set(failures))[:20]:
        print(f"  LEAK? {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5])))
