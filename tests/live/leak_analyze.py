"""Leak test 3 analysis: every packet that left the guest must belong to a tor-owned connection.

Usage (guest, as crawler): leak_analyze.py CAPTURE_TXT SS_SAMPLES FLOW_LOG LOCAL_IP PASSWORD_FILE ORCONN_SAMPLES
       CONNTRACK_SAMPLES
CAPTURE_TXT is `tcpdump -r cap.pcap -nn -q -tt` output. FLOW_LOG is the kernel's LOG --log-uid line for
every new outbound flow from the pre-roll on. SS_SAMPLES is `ss -tanpeH` every second from the pre-roll on:
every TCP socket in every state. A packet is credited by its exact connection (local address, local port,
remote address, remote port) and by nothing less: the connection must have been owned by a Tor uid, and by
no other uid, in the flow log or in any ss sample. ss names no owner for a socket its process has closed
(FIN-WAIT-1 to TIME-WAIT, measured in the guest), so the owner a connection had while it was open is
remembered for the packets that follow its close. CONNTRACK_SAMPLES is /proc/net/nf_conntrack every second:
the kill switch marks a connection only on the SYN a Tor instance opens it with, and the entry outlives the
socket, so a packet on a connection with that mark is credited even when its close was before the pre-roll.
A connection with neither an owner nor the mark fails, and so does one any other uid ever owned, marked or not.
ORCONN_SAMPLES (orconn_sample.py) is each Tor instance's own list of its relay connections. It names a relay,
not a connection, so it credits nothing and only describes a failure. A window in which no packet left from
a Tor UID fails: it saw no fetch, so it proves nothing about the fetcher.
"""
import ipaddress
import pwd
import re
import sys
from collections import Counter
from pathlib import Path

from stem.control import Controller

SS_LINE = re.compile(r"(\S+)\s+\d+\s+\d+\s+(\S+):(\d+)\s+(\S+):(\d+)(?:\s|$)")
# ss -e prints a socket's uid only when it is not root's, and no users at all once its process has closed it.
SS_UID = re.compile(r"\buid:(\d+)")
FLOW_LINE = re.compile(r"SRC=(\S+) DST=(\S+) .*?PROTO=\w+(?: SPT=(\d+) DPT=(\d+))?.*?UID=(\d+)")
# The original direction of a TCP entry, which is the side that sent the SYN, and the entry's mark.
CONNTRACK_LINE = re.compile(r"\btcp\b.*?\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+) .*\bmark=(\d+)")
# provision.sh's TOR_MARK: set only by a Tor instance's SYN on a new connection.
TOR_MARK = 0x746f72
DHCP_PORTS = {67, 68}
# A connection: local address, local port, remote address, remote port.
Connection = tuple[str, int | None, str, int | None]


def tor_uids() -> set[int]:
    return {pwd.getpwnam(f"_tor-crawl{n}").pw_uid for n in range(1, 7)}


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
        local, remote = (src, dst) if outbound else (dst, src)
        protocol = parts[5].rstrip(",").lower() if len(parts) > 5 else "?"
        packets.append({"family": parts[1], "outbound": outbound, "remote": remote, "protocol": protocol,
                        "connection": (*local, *remote)})
    return packets


def parse_sockets(path: Path, local_ip: str):
    """What ss saw of each connection from the guest's address: the uids that ever owned it, whether an owner
    held it past SYN-SENT, and the states it showed with no owner."""
    owned: dict[Connection, set[int]] = {}
    connected: set[Connection] = set()
    unowned: dict[Connection, set[str]] = {}
    for line in path.read_text().splitlines():
        match = SS_LINE.match(line.strip())
        if not match or match[2] != local_ip:
            continue
        connection = (match[2], int(match[3]), match[4], int(match[5]))
        uid = SS_UID.search(line)
        if not uid and "users:((" not in line:
            unowned.setdefault(connection, set()).add(match[1])
            continue
        owned.setdefault(connection, set()).add(int(uid[1]) if uid else 0)
        # A SYN the kill switch dropped is an attempt, not a connection: test 1 makes two on purpose.
        if match[1] != "SYN-SENT":
            connected.add(connection)
    return owned, connected, unowned


def parse_flows(path: Path) -> dict[Connection, set[int]]:
    flows: dict[Connection, set[int]] = {}
    for line in path.read_text().splitlines():
        match = FLOW_LINE.search(line)
        if match:
            src, dst, sport, dport, uid = match.groups()
            connection = (src, int(sport) if sport else None, dst, int(dport) if dport else None)
            flows.setdefault(connection, set()).add(int(uid))
    return flows


def parse_marked(path: Path, local_ip: str) -> set[Connection]:
    """The connections the guest opened whose conntrack entry carried the Tor mark in any sample."""
    marked = set()
    for line in path.read_text().splitlines():
        match = CONNTRACK_LINE.search(line)
        if match and match[1] == local_ip and int(match[5]) == TOR_MARK:
            marked.add((match[1], int(match[3]), match[2], int(match[4])))
    return marked


def parse_orconns(path: Path) -> dict[tuple[str, int], set[int]]:
    owners: dict[tuple[str, int], set[int]] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].isdigit() and parts[2].isdigit():
            owners.setdefault((parts[1], int(parts[2])), set()).add(int(parts[0]))
    return owners


def owner_uids(connection: Connection, flows: dict, owned: dict) -> set[int]:
    # Every uid either witness ever saw on this exact connection. One that is not Tor's spoils it, whenever it
    # was seen, so a port a Tor instance used and another user then reused is never credited.
    return flows.get(connection, set()) | owned.get(connection, set())


def consensus_relays(password_file: Path) -> set[tuple[str, int]]:
    with Controller.from_port(address="127.0.0.1", port=11051) as controller:
        controller.authenticate(password=password_file.read_text().strip())
        return {(entry.address, entry.or_port) for entry in controller.get_network_statuses()}


def main(capture: Path, samples: Path, flow_log: Path, local_ip: str, password_file: Path,
         orconn_samples: Path, conntrack_samples: Path) -> int:
    tor = tor_uids()
    packets = parse_capture(capture, local_ip)
    owned, connected, unowned = parse_sockets(samples, local_ip)
    flows = parse_flows(flow_log)
    orconns = parse_orconns(orconn_samples)
    marked = parse_marked(conntrack_samples, local_ip)
    relays = consensus_relays(password_file)
    subnet = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    failures = []
    non_tor = {connection: owned[connection] for connection in connected if not owned[connection] <= tor}
    for (_, _, host, port), uids in non_tor.items():
        failures.append(f"socket to {host}:{port} owned by uid {sorted(uids - tor)}")

    # Only a Tor instance's SYN may set the mark. A marked connection another uid was seen on means the rule
    # marked a packet it must not, whether or not a packet of it reached the wire.
    for connection in sorted(marked, key=str):
        strangers = owner_uids(connection, flows, owned) - tor
        if strangers:
            failures.append(f"connection to {connection[2]}:{connection[3]} carries the Tor mark and uid"
                            f" {sorted(strangers)} was on it")

    dhcp, ipv6, from_tor, attributed = 0, 0, 0, Counter()
    after_close, by_mark, never_owned, tor_names_relay = set(), set(), 0, 0
    for packet in packets:
        host, port = packet["remote"]
        connection = packet["connection"]
        if packet["family"] == "IP6":
            ipv6 += 1
            failures.append(f"IPv6 packet to/from {host}")
            continue
        if port in DHCP_PORTS and ipaddress.ip_address(host) in subnet:
            dhcp += 1
            continue
        uids = owner_uids(connection, flows, owned)
        if uids <= tor and (uids or connection in marked):
            attributed[(host, port)] += 1
            from_tor += packet["outbound"] and bool(uids)
            if not uids:
                by_mark.add(connection)
            elif connection in unowned:
                after_close.add(connection)
        else:
            never_owned += not uids
            tor_names_relay += bool(orconns.get((host, port), set()) & tor)
            failures.append(f"{packet['protocol']} packet {'to' if packet['outbound'] else 'from'} {host}:{port} not on a tor socket")

    on_wire = {packet["connection"] for packet in packets}
    blocked = {(connection[2:], uid) for connection, uids in flows.items() for uid in uids - tor
               if connection not in on_wire}
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
    print(f"connections ss saw: {len(owned)} with an owner, {len(set(unowned) - set(owned))} only without one")
    print(f"connections credited to the Tor uid that owned them before ss showed them closed: {len(after_close)}")
    print(f"connections carrying the kill switch's Tor mark: {len(marked)}, credited by the mark alone (no owner"
          f" seen from the pre-roll on): {len(by_mark)}")
    print(f"packets on a connection with no owner and no mark: {never_owned}, "
          f"of them to or from a relay Tor's own list names, which credits nothing: {tor_names_relay}")
    print(f"new flows logged by the kernel: {sum(len(u) for u in flows.values())}, "
          f"from tor UIDs: {sum(len(u & tor) for u in flows.values())}")
    for (dst, port), uid in sorted(blocked, key=str):
        print(f"blocked before the wire: uid {pwd.getpwuid(uid).pw_name} -> {dst}:{port}")
    for failure in sorted(set(failures))[:20]:
        print(f"  LEAK? {failure}")
    if not from_tor:
        print("  NO FETCH: no packet left the guest from a Tor UID, so the window proves nothing about the fetcher")
    return 1 if failures or not from_tor else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5]),
                  Path(sys.argv[6]), Path(sys.argv[7])))
