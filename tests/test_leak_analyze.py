"""Leak test 3's attribution: a packet is credited by its exact connection, to the Tor uid that owned it."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.live import leak_analyze

LOCAL = "192.168.5.15"
GUARD = ("198.51.100.7", 443)
RELAY = ("203.0.113.9", 9001)
TOR, CRAWLER = 105, 1000
MARK = leak_analyze.TOR_MARK


def packet(outbound: bool, remote: tuple[str, int], local_port: int = 40000) -> str:
    local, far = f"{LOCAL}.{local_port}", f"{remote[0]}.{remote[1]}"
    src, dst = (local, far) if outbound else (far, local)
    return f"1762750000.000001 IP {src} > {dst}: tcp 0"


def flow(remote: tuple[str, int], uid: int, local_port: int = 40000) -> str:
    return (f"onioncrawl-lt3: IN= OUT=eth0 SRC={LOCAL} DST={remote[0]} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF"
            f" PROTO=TCP SPT={local_port} DPT={remote[1]} WINDOW=64240 RES=0x00 SYN URGP=0 UID={uid} GID={uid}")


def socket_line(remote: tuple[str, int], uid: int | None, local_port: int = 40000, state: str = "ESTAB") -> str:
    """One `ss -tanpeH` row as the guest prints it. uid None is a socket its process has closed: ss shows
    neither users nor a uid for it, in every closing state."""
    owner = "" if uid is None else f'users:(("tor",pid=711,fd=14)) uid:{uid} '
    return f"{state:<6} 0      0      {LOCAL}:{local_port} {remote[0]}:{remote[1]} {owner}ino:1 sk:1 <->"


def tracked(remote: tuple[str, int], mark: int, local_port: int = 40000, state: str = "TIME_WAIT",
            protocol: str = "tcp      6", inbound: bool = False) -> str:
    """One /proc/net/nf_conntrack row as the guest prints it: the opener's direction first, then the reply's."""
    here, there = f"src={LOCAL} dst={remote[0]} sport={local_port} dport={remote[1]}", \
        f"src={remote[0]} dst={LOCAL} sport={remote[1]} dport={local_port}"
    first, second = (there, here) if inbound else (here, there)
    return f"ipv4     2 {protocol} 117 {state} {first} {second} [ASSURED] mark={mark} zone=0 use=2"


class AttributionTest(unittest.TestCase):
    def run_analyzer(self, capture, flows=(), sockets=(), orconns=(), conntrack=()) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for name, lines in (("cap", capture), ("ss", sockets), ("flows", flows), ("orconn", orconns),
                                ("conntrack", conntrack)):
                path = Path(tmp, name)
                path.write_text("".join(f"{line}\n" for line in lines))
                files.append(path)
            out = io.StringIO()
            with mock.patch.object(leak_analyze, "tor_uids", return_value={104, TOR}), \
                    mock.patch.object(leak_analyze, "consensus_relays", return_value={GUARD, RELAY}), \
                    mock.patch.object(leak_analyze.pwd, "getpwuid", return_value=mock.Mock(pw_name="crawler")), \
                    contextlib.redirect_stdout(out):
                code = leak_analyze.main(files[0], files[1], files[2], LOCAL, Path(tmp, "pw"), files[3], files[4])
        return code, out.getvalue()

    def test_a_connection_tor_closed_is_credited_to_the_uid_that_owned_it(self):
        # The 2026-11-10 14:49 run: a relay kept sending on a connection Tor had closed. Every closing state, in
        # the order a close can pass through them; ss shows none of them with an owner.
        for closing in ("FIN-WAIT-1", "FIN-WAIT-2", "CLOSING", "LAST-ACK", "TIME-WAIT"):
            with self.subTest(state=closing):
                sockets = ["sample 1", socket_line(GUARD, TOR), "sample 2", socket_line(GUARD, None, state=closing)]
                code, out = self.run_analyzer([packet(True, GUARD), packet(False, GUARD)], sockets=sockets)
                self.assertEqual(code, 0, out)
                self.assertIn("credited to the Tor uid that owned them before ss showed them closed: 1", out)
                self.assertIn("remote endpoints: 1, all on tor-owned sockets: True", out)

    def test_a_closed_connection_stays_credited_when_ss_no_longer_lists_it(self):
        code, out = self.run_analyzer([packet(True, GUARD), packet(False, GUARD)],
                                      sockets=["sample 1", socket_line(GUARD, TOR), "sample 2", "sample 3"])
        self.assertEqual(code, 0, out)

    def test_a_connection_never_seen_with_an_owner_fails(self):
        # Closed before the pre-roll: ss lists it, in TIME-WAIT, and has no owner to name.
        capture = [packet(True, RELAY), packet(False, GUARD, 40001)]
        sockets = [socket_line(RELAY, TOR), socket_line(GUARD, None, 40001, "TIME-WAIT")]
        code, out = self.run_analyzer(capture, sockets=sockets)
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet from {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
        self.assertIn("packets on a connection with no owner and no mark: 1", out)
        code, out = self.run_analyzer(capture, sockets=sockets[:1])
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet from {GUARD[0]}:{GUARD[1]} not on a tor socket", out)

    def test_a_relays_address_and_port_alone_credit_nothing(self):
        # Tor owns one connection to the guard, the consensus lists the guard and Tor's own list names it. A
        # packet to the same address and port from another local port is still nobody's.
        capture = [packet(True, GUARD), packet(True, GUARD, 40001)]
        orconns = ["sample 1", f"{TOR} {GUARD[0]} {GUARD[1]}"]
        for witness in ({"flows": [flow(GUARD, TOR)]}, {"sockets": [socket_line(GUARD, TOR)]}):
            with self.subTest(witness=list(witness)):
                code, out = self.run_analyzer(capture, orconns=orconns, **witness)
                self.assertEqual(code, 1)
                self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
                self.assertIn("to or from a relay Tor's own list names, which credits nothing: 1", out)
                code, out = self.run_analyzer(capture[:1], orconns=orconns, **witness)
                self.assertEqual(code, 0, out)

    def test_tors_own_list_credits_nothing(self):
        capture = [packet(True, RELAY), packet(False, GUARD, 40001)]
        code, out = self.run_analyzer(capture, [flow(RELAY, TOR)], orconns=[f"{TOR} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet from {GUARD[0]}:{GUARD[1]} not on a tor socket", out)

    def test_a_packet_from_a_non_tor_uid_fails_by_the_kernel_log(self):
        capture = [packet(True, RELAY), packet(True, GUARD, 40001)]
        code, out = self.run_analyzer(capture, [flow(RELAY, TOR), flow(GUARD, CRAWLER, 40001)])
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)

    def test_a_packet_from_a_non_tor_uid_fails_by_ss(self):
        capture = [packet(True, RELAY), packet(True, GUARD, 40001)]
        code, out = self.run_analyzer(capture, [flow(RELAY, TOR)], [socket_line(GUARD, CRAWLER, 40001)])
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
        self.assertIn(f"socket to {GUARD[0]}:{GUARD[1]} owned by uid [{CRAWLER}]", out)

    def test_a_non_tor_uid_spoils_a_connection_tor_owned_earlier(self):
        # The same four-part address, owned by Tor and then by the crawler: the memory credits neither witness.
        capture = [packet(True, GUARD)]
        sockets = ["sample 1", socket_line(GUARD, TOR), "sample 2", socket_line(GUARD, None, state="TIME-WAIT")]
        code, out = self.run_analyzer(capture, sockets=sockets)
        self.assertEqual(code, 0, out)
        code, _ = self.run_analyzer(capture, [flow(GUARD, CRAWLER)], sockets)
        self.assertEqual(code, 1)
        code, _ = self.run_analyzer(capture, sockets=sockets + ["sample 3", socket_line(GUARD, CRAWLER)])
        self.assertEqual(code, 1)

    def test_a_root_socket_is_not_tors(self):
        # ss prints no uid for root; the users it lists are what tell a root socket from a closed one.
        root = f'ESTAB 0 0 {LOCAL}:40001 {GUARD[0]}:{GUARD[1]} users:(("curl",pid=9,fd=5)) ino:1 sk:1 <->'
        code, out = self.run_analyzer([packet(True, RELAY), packet(True, GUARD, 40001)], [flow(RELAY, TOR)], [root])
        self.assertEqual(code, 1)
        self.assertIn(f"socket to {GUARD[0]}:{GUARD[1]} owned by uid [0]", out)

    def test_a_dropped_attempt_is_not_a_socket_failure_but_its_packet_is(self):
        # Test 1's curl sits in SYN-SENT while the kill switch drops its SYN.
        attempt = [socket_line(GUARD, CRAWLER, 40001, "SYN-SENT")]
        code, out = self.run_analyzer([packet(True, RELAY)], [flow(RELAY, TOR), flow(GUARD, CRAWLER, 40001)], attempt)
        self.assertEqual(code, 0, out)
        self.assertIn("non-tor sockets seen by ss: 0", out)
        code, out = self.run_analyzer([packet(True, RELAY), packet(True, GUARD, 40001)], [flow(RELAY, TOR)], attempt)
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)

    # The kill switch marks a connection on the SYN a Tor instance opens it with. FETCH is a live Tor connection,
    # so the window has a fetch; the guard's connection was closed before the pre-roll and no witness has an owner.
    FETCH = [packet(True, RELAY, 40009), packet(False, RELAY, 40009)]
    FETCHING = ["sample 1", socket_line(RELAY, TOR, 40009)]

    def test_a_marked_connection_closed_before_the_pre_roll_is_credited(self):
        late = [packet(False, GUARD), packet(True, GUARD)]
        code, out = self.run_analyzer(self.FETCH + late, sockets=self.FETCHING + [socket_line(GUARD, None, state="LAST-ACK")],
                                      conntrack=[tracked(RELAY, MARK, 40009, "ESTABLISHED"), tracked(GUARD, MARK)])
        self.assertEqual(code, 0, out)
        self.assertIn("connections carrying the kill switch's Tor mark: 2, credited by the mark alone (no owner seen"
                      " from the pre-roll on): 1", out)
        self.assertIn("outbound packets from the Tor UIDs: 1\n", out, "the kernel's reply for a closed socket is no fetch")

    def test_no_owner_and_no_mark_still_fails(self):
        late = [packet(False, GUARD)]
        for name, conntrack in (("no entry", []), ("unmarked entry", [tracked(GUARD, 0)]),
                                ("another mark", [tracked(GUARD, MARK + 1)]), ("mark as a prefix", [tracked(GUARD, MARK * 10)]),
                                ("marked, another local port", [tracked(GUARD, MARK, 40001)]),
                                ("marked, another relay port", [tracked((GUARD[0], 9001), MARK)]),
                                ("marked, opened from the far side", [tracked(GUARD, MARK, inbound=True)]),
                                ("marked udp", [tracked(GUARD, MARK, protocol="udp      17")])):
            with self.subTest(name):
                code, out = self.run_analyzer(self.FETCH + late, sockets=self.FETCHING, conntrack=conntrack)
                self.assertEqual(code, 1, out)
                self.assertIn(f"tcp packet from {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
                self.assertIn("packets on a connection with no owner and no mark: 1", out)

    def test_a_non_tor_owner_fails_whatever_the_mark_says(self):
        late = [packet(True, GUARD), packet(False, GUARD)]
        conntrack = [tracked(GUARD, MARK)]
        for name, witness in (("kernel log", {"flows": [flow(GUARD, CRAWLER)]}),
                              ("ss", {"sockets": self.FETCHING + [socket_line(GUARD, CRAWLER)]}),
                              ("tor then another uid", {"sockets": self.FETCHING + [socket_line(GUARD, TOR)],
                                                        "flows": [flow(GUARD, CRAWLER)]})):
            with self.subTest(name):
                witness = {"sockets": self.FETCHING} | witness
                code, out = self.run_analyzer(self.FETCH + late, conntrack=conntrack, **witness)
                self.assertEqual(code, 1, out)
                self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
                self.assertIn(f"connection to {GUARD[0]}:{GUARD[1]} carries the Tor mark and uid [{CRAWLER}] was on it", out)

    def test_a_blocked_syn_must_leave_no_marked_entry(self):
        # Test 1's curl as the crawler: the kernel logs the SYN and the kill switch drops it. Nothing reaches the
        # wire, so only this check can see a mark rule that marked it.
        blocked = [flow(("1.1.1.1", 443), CRAWLER, 50123)]
        code, out = self.run_analyzer(self.FETCH, flows=blocked, sockets=self.FETCHING)
        self.assertEqual(code, 0, out)
        code, out = self.run_analyzer(self.FETCH, flows=blocked, sockets=self.FETCHING,
                                      conntrack=[tracked(("1.1.1.1", 443), MARK, 50123, "SYN_SENT")])
        self.assertEqual(code, 1, out)
        self.assertIn(f"connection to 1.1.1.1:443 carries the Tor mark and uid [{CRAWLER}] was on it", out)

    def test_packets_credited_by_the_mark_alone_never_make_a_fetch(self):
        code, out = self.run_analyzer([packet(True, GUARD), packet(False, GUARD)], conntrack=[tracked(GUARD, MARK)])
        self.assertEqual(code, 1)
        self.assertIn("NO FETCH", out)
        self.assertNotIn("LEAK?", out)

    def test_inbound_packets_alone_never_make_a_fetch(self):
        code, out = self.run_analyzer([packet(False, GUARD)], sockets=[socket_line(GUARD, TOR)])
        self.assertEqual(code, 1)
        self.assertIn("NO FETCH", out)


class ParseTest(unittest.TestCase):
    def write(self, text: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name, "lines")
        path.write_text(text)
        return path

    def test_samples_and_stray_lines_are_skipped(self):
        path = self.write(f"sample 1\n{TOR} 198.51.100.7 443\n{TOR} 198.51.100.7 x\nnoise\n104 198.51.100.7 443\n")
        self.assertEqual(leak_analyze.parse_orconns(path), {("198.51.100.7", 443): {104, TOR}})

    def test_sockets_are_keyed_by_all_four_parts(self):
        listening = f'LISTEN 0 4096 {LOCAL}:10051 0.0.0.0:* users:(("tor",pid=7,fd=6)) ino:1 sk:1 <->'
        loopback = 'ESTAB 0 0 127.0.0.1:50000 127.0.0.1:10051 users:(("python",pid=8,fd=6)) uid:1000 ino:1 sk:1 <->'
        path = self.write("\n".join(["sample 1", socket_line(GUARD, TOR), socket_line(GUARD, TOR, 40001, "SYN-SENT"),
                                     socket_line(RELAY, None, 40002, "FIN-WAIT-2"), listening, loopback]) + "\n")
        owned, connected, unowned = leak_analyze.parse_sockets(path, LOCAL)
        self.assertEqual(owned, {(LOCAL, 40000, *GUARD): {TOR}, (LOCAL, 40001, *GUARD): {TOR}})
        self.assertEqual(connected, {(LOCAL, 40000, *GUARD)})
        self.assertEqual(unowned, {(LOCAL, 40002, *RELAY): {"FIN-WAIT-2"}})

    def test_flows_are_keyed_by_all_four_parts(self):
        ping = f"onioncrawl-lt3: IN= OUT=eth0 SRC={LOCAL} DST=198.51.100.7 LEN=84 PROTO=ICMP TYPE=8 UID=1000 GID=1000"
        path = self.write(f"{flow(GUARD, TOR)}\n{flow(GUARD, CRAWLER, 40001)}\n{ping}\n")
        self.assertEqual(leak_analyze.parse_flows(path), {(LOCAL, 40000, *GUARD): {TOR}, (LOCAL, 40001, *GUARD): {CRAWLER},
                                                          (LOCAL, None, GUARD[0], None): {CRAWLER}})

    def test_marked_connections_are_the_guests_own_tcp_entries_with_exactly_the_mark(self):
        path = self.write("\n".join([
            "sample 1", tracked(GUARD, MARK), tracked(RELAY, 0, 40001), tracked(RELAY, MARK, 40002, "ESTABLISHED"),
            tracked(GUARD, MARK, 40003, inbound=True), tracked(GUARD, MARK, 40004, protocol="udp      17"),
            "ipv4     2 tcp      6 9 CLOSE src=x", ""]))
        self.assertEqual(leak_analyze.parse_marked(path, LOCAL),
                         {(LOCAL, 40000, *GUARD), (LOCAL, 40002, *RELAY)})
        self.assertEqual(MARK, 0x746f72)

    def test_owner_uids_is_every_uid_either_witness_saw(self):
        key = (LOCAL, 40000, *GUARD)
        self.assertEqual(leak_analyze.owner_uids(key, {key: {1}}, {key: {2}}), {1, 2})
        self.assertEqual(leak_analyze.owner_uids(key, {}, {key: {2}}), {2})
        self.assertEqual(leak_analyze.owner_uids(key, {}, {}), set())


class CaptureScriptTest(unittest.TestCase):
    """capture.sh runs only in the guest. This holds the two things the attribution above depends on."""
    script = (Path(__file__).parent / "live" / "capture.sh").read_text()

    def test_ss_samples_every_tcp_state(self):
        self.assertEqual(self.script.count('ss -tanpeH; sleep 1; done ) > "$WORK/ss.txt"'), 1)
        self.assertNotIn("state established", self.script)

    def test_every_witness_starts_a_pre_roll_before_the_capture(self):
        start = self.script[self.script.index("capture_start() {"):self.script.index("capture_stop() {")]
        order = ["WITNESSES_FROM=$(date +%s)", 'iptables -I "${LOG_RULE[@]:0:1}"',
                 'cat /proc/net/nf_conntrack >> "$WORK/conntrack.txt"', "ss -tanpeH", "orconn_sample.py",
                 'sleep "$PREROLL"', 'tcpdump -i "$DEV"', "STARTED=$(date +%s)"]
        self.assertEqual([start.count(step) for step in order], [1] * len(order))
        positions = [start.index(step) for step in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("\nPREROLL=5\n", self.script)
        self.assertIn('journalctl -k --since "@$WITNESSES_FROM"', self.script)

    def test_the_conntrack_samples_reach_the_analyzer(self):
        self.assertIn('"$WORK/orconn.txt" "$WORK/conntrack.txt" | sed', self.script)
        self.assertIn('"$WORK/conntrack.txt"\n    echo "      capture closed', self.script, "readable by the crawler")

    def test_the_stream_count_reads_established_rows_of_the_all_state_sample(self):
        self.assertIn('$1 == "ESTAB" && $5 ~ /^127\\.0\\.0\\.1:100[0-9][0-9]$/ && $6 ~ /python/', self.script)


if __name__ == "__main__":
    unittest.main()
