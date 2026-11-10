"""Leak test 3's DHCP probe. Guest only, as the crawler with CAP_NET_RAW and nothing more, from root's copy:
dhcp_probe.py LABEL=ADDRESS...

The kill switch accepts UDP from port 68 to port 67 on the default-route interface to the guest's subnet, from uid
systemd-network only. The crawler can never bind port 68 (systemd-networkd holds it, and it is privileged), so a
datagram from a crawler UDP socket would be dropped by the port match alone and prove nothing about the owner match.
This one is built on an AF_INET raw socket instead, from port 68 to port 67: unlike networkd's AF_PACKET fallback it
passes through iptables OUTPUT, matches the rule in every field but the owner, and so reaches the wire only if
--uid-owner fails to hold. Netfilter's drop comes back from sendto as EPERM. The payload makes the datagram 24 bytes
long, which no real DHCP message is, so the capture can tell the probe's packets from the guest's renewals.
"""
import errno
import os
import socket
import struct
import sys

PAYLOAD = b"onioncollect-lt3"
UDP_LENGTH = 8 + len(PAYLOAD)


def datagram() -> bytes:
    # Checksum 0: none, which IPv4 allows.
    return struct.pack("!HHHH", 68, 67, UDP_LENGTH, 0) + PAYLOAD


def main(targets: list[str]) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sent = 0
    for target in targets:
        label, _, address = target.partition("=")
        try:
            sock.sendto(datagram(), (address, 0))
            outcome = "accepted by the stack"
            sent += 1
        except OSError as exc:
            outcome = f"refused, {errno.errorcode.get(exc.errno, exc.errno)}"
        print(f"uid {os.getuid()} udp 68 -> {label}:67, {UDP_LENGTH} bytes: {outcome}")
    return 1 if sent else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
