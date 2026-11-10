"""Leak test 3's attribution: the kernel's flow log, then ss, then each Tor instance's own connection list."""
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


def packet(outbound: bool, remote: tuple[str, int]) -> str:
    local, far = f"{LOCAL}.40000", f"{remote[0]}.{remote[1]}"
    src, dst = (local, far) if outbound else (far, local)
    return f"1762750000.000001 IP {src} > {dst}: tcp 0"


def flow(remote: tuple[str, int], uid: int) -> str:
    return (f"onioncrawl-lt3: IN= OUT=eth0 SRC={LOCAL} DST={remote[0]} PROTO=TCP SPT=40000 DPT={remote[1]}"
            f" UID={uid} GID={uid}")


def socket_line(remote: tuple[str, int], uid: int) -> str:
    return f'0 0 {LOCAL}:40000 {remote[0]}:{remote[1]} users:(("tor",pid=711,fd=14)) uid:{uid} ino:1 sk:1'


class AttributionTest(unittest.TestCase):
    def run_analyzer(self, capture, flows=(), sockets=(), orconns=()) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for name, lines in (("cap", capture), ("ss", sockets), ("flows", flows), ("orconn", orconns)):
                path = Path(tmp, name)
                path.write_text("".join(f"{line}\n" for line in lines))
                files.append(path)
            out = io.StringIO()
            with mock.patch.object(leak_analyze, "tor_uids", return_value={104, TOR}), \
                    mock.patch.object(leak_analyze, "consensus_relays", return_value={GUARD, RELAY}), \
                    contextlib.redirect_stdout(out):
                code = leak_analyze.main(files[0], files[1], files[2], LOCAL, Path(tmp, "pw"), files[3])
        return code, out.getvalue()

    def test_a_guard_connection_opened_before_the_window_is_tors_by_its_own_list(self):
        # The 2026-11-10 05:09 run: packets from a Tor instance's guard on a connection that opened before the
        # window and never sampled as established, so neither the flow log nor ss named its owner.
        capture = [packet(True, RELAY), packet(False, GUARD), packet(False, GUARD)]
        flows = [flow(RELAY, TOR)]
        code, out = self.run_analyzer(capture, flows)
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet from {GUARD[0]}:{GUARD[1]} not on a tor socket", out)
        code, out = self.run_analyzer(capture, flows, orconns=["sample 1", f"{TOR} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 0, out)
        self.assertIn("endpoints only Tor's own connection list names: 1", out)
        self.assertIn("remote endpoints: 2, all on tor-owned sockets: True", out)

    def test_the_kernel_log_outranks_tors_list(self):
        capture = [packet(True, RELAY), packet(True, GUARD)]
        code, out = self.run_analyzer(capture, [flow(RELAY, TOR), flow(GUARD, CRAWLER)],
                                      orconns=[f"{TOR} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 1)
        self.assertIn(f"tcp packet to {GUARD[0]}:{GUARD[1]} not on a tor socket", out)

    def test_ss_outranks_tors_list(self):
        capture = [packet(True, RELAY), packet(True, GUARD)]
        code, out = self.run_analyzer(capture, [flow(RELAY, TOR)], [socket_line(GUARD, CRAWLER)],
                                      [f"{TOR} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 1)
        self.assertIn(f"socket to {GUARD[0]}:{GUARD[1]} owned by uid [{CRAWLER}]", out)

    def test_a_non_tor_uid_in_tors_list_attributes_nothing(self):
        capture = [packet(True, RELAY), packet(False, GUARD)]
        code, _ = self.run_analyzer(capture, [flow(RELAY, TOR)], orconns=[f"{CRAWLER} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 1)

    def test_tors_list_alone_never_makes_a_fetch(self):
        # Attributed packets that are all inbound still leave the window without a fetch.
        code, out = self.run_analyzer([packet(False, GUARD)], orconns=[f"{TOR} {GUARD[0]} {GUARD[1]}"])
        self.assertEqual(code, 1)
        self.assertIn("NO FETCH", out)


class ParseTest(unittest.TestCase):
    def test_samples_and_stray_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "orconn")
            path.write_text(f"sample 1\n{TOR} 198.51.100.7 443\n{TOR} 198.51.100.7 x\nnoise\n104 198.51.100.7 443\n")
            self.assertEqual(leak_analyze.parse_orconns(path), {("198.51.100.7", 443): {104, TOR}})

    def test_owner_uids_takes_the_first_witness_that_saw_the_endpoint(self):
        key = GUARD
        self.assertEqual(leak_analyze.owner_uids(key, {key: {1}}, {key: {2}}, {key: {3}}), {1})
        self.assertEqual(leak_analyze.owner_uids(key, {}, {key: {2}}, {key: {3}}), {2})
        self.assertEqual(leak_analyze.owner_uids(key, {}, {}, {key: {3}}), {3})
        self.assertIsNone(leak_analyze.owner_uids(key, {}, {}, {}))


if __name__ == "__main__":
    unittest.main()
