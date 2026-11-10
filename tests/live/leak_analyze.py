"""Leak test 3 analysis: every packet that left the guest must belong to a tor-owned connection.

Usage (guest, as crawler): leak_analyze.py CAPTURE_TXT SS_SAMPLES FLOW_LOG LOCAL_IP PASSWORD_FILE
CAPTURE_TXT is `tcpdump -r cap.pcap -nn -q -tt` output. FLOW_LOG is the kernel's LOG --log-uid line for
every new outbound flow during the window. SS_SAMPLES (repeated `ss -tnpeH state established`) covers
connections Tor opened before the window started. A window in which no packet left from a Tor UID fails: it saw
no fetch, so it proves nothing about the fetcher.
"""
import ipaddress
import pwd
import re
import sys
from collections import Counter
from pathlib import Path

from stem.control import Controller

SS_LINE = re.compile(r"\S+\s+\S+\s+(\S+):(\d+)\s+(\S+):(\d+)\s+users:\(\(")
# ss -e prints a socket's uid only when it is not root's.
SS_UID = re.compile(r"\buid:(\d+)")
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


def parse_sockets(path: Path, local_ip: str) -> dict[tuple[str, int], set[int]]:
    owners: dict[tuple[str, int], set[int]] = {}
    for line in path.read_text().splitlines():
        match = SS_LINE.match(line.strip())
        if not match or match[1] != local_ip:
            continue
        uid = SS_UID.search(line)
        owners.setdefault((match[3], int(match[4])), set()).add(int(uid[1]) if uid else 0)
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
    non_tor = {endpoint: uids for endpoint, uids in owners.items() if not uids <= TOR_UIDS}
    for endpoint, uids in non_tor.items():
        failures.append(f"socket to {endpoint[0]}:{endpoint[1]} owned by uid {sorted(uids - TOR_UIDS)}")

    dhcp, ipv6, from_tor, attributed = 0, 0, 0, Counter()
    for packet in packets:
        host, port = packet["remote"]
        if packet["family"] == "IP6":
            ipv6 += 1
            failures.append(f"IPv6 packet to/from {host}")
            continue
        if port in DHCP_PORTS and ipaddress.ip_address(host) in subnet:
            dhcp += 1
            continue
        # A new flow is judged by the uid the kernel logged for it; one Tor opened before the window, by ss.
        uids = flows.get((host, port), owners.get((host, port)))
        if uids and uids <= TOR_UIDS:
            attributed[(host, port)] += 1
            from_tor += packet["outbound"]
        else:
            failures.append(f"{packet['protocol']} packet {'to' if packet['outbound'] else 'from'} {host}:{port} not on a tor socket")

    on_wire = {packet["remote"] for packet in packets}
    blocked = {(dst, uid) for dst, uids in flows.items() for uid in uids - TOR_UIDS if dst not in on_wire}
    endpoints = set(attributed)
    in_consensus = endpoints & relays
    outbound = sum(1 for p in packets if p["outbound"])
    print(f"captured packets: {len(packets)} ({outbound} outbound, {len(packets) - outbound} inbound)")
    print(f"outbound packets from the Tor UIDs: {from_tor}")
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
    if not from_tor:
        print("  NO FETCH: no packet left the guest from a Tor UID, so the window proves nothing about the fetcher")
    return 1 if failures or not from_tor else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5])))
