"""provision.sh's migrate_layout on a fake guest tree laid out as step 8 left it: the stores in the crawler's home
under a group the analyst read through, the frontier beside them. It runs as the test user, so every user and group
it names is that user's; ownership is the guest's to check, modes and places are checked here."""
import grp
import os
import pwd
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

PROVISION = Path(__file__).resolve().parent.parent / "provision" / "provision.sh"
LOG = "2026-11-08 10:00:00,000 INFO onioncollect.crawler: crawler: stopped\n"


class MigrateLayoutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        old = self.root / "home" / "crawler" / "data"
        (old / "snapshots" / "ab").mkdir(parents=True)
        (self.root / "home" / "crawler" / "configs").mkdir()
        (self.root / "home" / "analyst").mkdir()
        for name, text in (("collect.db", "sources"), ("records.db", "records"), ("frontier.db", "urls"),
                           ("crawl.log", LOG), ("run.lock", ""), ("snapshots/ab/ab12.html", "<p>x</p>")):
            (old / name).write_text(text)
            (old / name).chmod(0o640)
        (self.root / "home" / "crawler" / "configs" / "news.toml").write_text('id = "news"\n')
        old.chmod(0o750)
        (self.root / "home" / "crawler").chmod(0o710)

    def tearDown(self):
        self.tmp.cleanup()

    def migrate(self) -> str:
        user, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name
        environment = {"PATH": os.environ["PATH"], "CRAWLER": user, "ANALYST": user, "CRAWLER_GROUP": group,
                       "ANALYST_GROUP": group, "IPC_GROUP": group, "CRAWLER_HOME": str(self.root / "home/crawler"),
                       "ANALYST_HOME": str(self.root / "home/analyst"), "SHARED": str(self.root / "var/lib/onioncollect"),
                       "LOG_DIR": str(self.root / "var/log/onioncollect")}
        done = subprocess.run(["bash", "-c", 'source "$1"; migrate_layout', "_", str(PROVISION)], env=environment,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def tree(self) -> dict[str, tuple[int, bytes]]:
        return {str(path.relative_to(self.root)): (path.stat().st_mode, path.read_bytes() if path.is_file() else b"")
                for path in self.root.rglob("*")}

    def mode(self, relative: str) -> int:
        return stat.S_IMODE((self.root / relative).stat().st_mode) & 0o777

    def test_the_stores_go_to_the_analyst_and_the_frontier_stays_the_crawlers(self):
        self.migrate()
        data, state = self.root / "home/analyst/data", self.root / "home/crawler/state"
        self.assertEqual(sorted(path.name for path in data.iterdir()), ["collect.db", "records.db", "snapshots"])
        self.assertEqual((data / "snapshots/ab/ab12.html").read_text(), "<p>x</p>")
        self.assertEqual([path.name for path in state.iterdir()], ["frontier.db"])
        self.assertEqual((self.root / "var/log/onioncollect/crawl.log").read_text(), LOG)
        self.assertEqual((self.root / "var/lib/onioncollect/configs/news.toml").read_text(), 'id = "news"\n')
        self.assertFalse((self.root / "home/crawler/data").exists(), "the run lock went with the old data dir")
        self.assertFalse((self.root / "home/crawler/configs").exists())
        for path in [data, *data.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path)
        self.assertEqual((self.mode("home/analyst/data"), self.mode("home/crawler/state"), self.mode("home/crawler")),
                         (0o700, 0o700, 0o700))
        self.assertEqual((self.mode("var/lib/onioncollect/configs"), self.mode("var/lib/onioncollect/configs/news.toml"),
                          self.mode("var/log/onioncollect/crawl.log")), (0o750, 0o640, 0o640))

    def test_a_second_run_changes_nothing(self):
        self.assertIn("collect.db moved", self.migrate())
        before = self.tree()
        self.assertEqual(self.migrate(), "")
        self.assertEqual(self.tree(), before)

    def test_another_tools_crawl_log_stays_in_the_crawlers_home(self):
        old = self.root / "home/crawler/data"
        older = "2026-11-07 20:54:09,665 INFO onioncrawl.crawler: crawler: 1 worker\n"
        (old / "crawl.log").write_text(older)
        (old / "crawl.log.1").write_text(LOG)
        self.assertIn("kept: it holds files no store uses", self.migrate())
        self.assertEqual((old / "crawl.log").read_text(), older)
        self.assertEqual(sorted(path.name for path in (self.root / "var/log/onioncollect").iterdir()), ["crawl.log.1"])

    def test_a_store_already_in_place_is_never_overwritten(self):
        data = self.root / "home/analyst/data"
        data.mkdir()
        (data / "collect.db").write_text("newer")
        self.assertIn("kept: it holds files no store uses", self.migrate())
        self.assertEqual((data / "collect.db").read_text(), "newer")
        self.assertEqual((self.root / "home/crawler/data/collect.db").read_text(), "sources")


class CreateCrawlerTest(unittest.TestCase):
    """create_crawler under the script's own set -e, with id and gpasswd stubbed: it must return 0 for a crawler
    in no privileged group, the guest's normal case, and take it out of any it is in."""

    def run_with_groups(self, groups: str) -> tuple[subprocess.CompletedProcess, str]:
        with tempfile.TemporaryDirectory() as tmp:
            stubs = Path(tmp)
            (stubs / "id").write_text(f'#!/bin/sh\n[ "$1" = -nG ] && echo "{groups}"\nexit 0\n')
            (stubs / "gpasswd").write_text(f'#!/bin/sh\necho "$*" >> {tmp}/calls\n')
            for stub in ("id", "gpasswd"):
                (stubs / stub).chmod(0o755)
            done = subprocess.run(["bash", "-c", 'source "$1"; create_crawler; echo returned', "_", str(PROVISION)],
                                  env={"PATH": f"{tmp}:{os.environ['PATH']}"}, capture_output=True, text=True,
                                  timeout=60)
            calls = (stubs / "calls").read_text() if (stubs / "calls").exists() else ""
        return done, calls

    def test_a_crawler_in_no_privileged_group_returns(self):
        done, calls = self.run_with_groups("crawler onioncollect-ipc")
        self.assertEqual((done.returncode, done.stdout, calls), (0, "returned\n", ""), done.stderr)

    def test_a_crawler_in_sudo_and_adm_is_taken_out(self):
        done, calls = self.run_with_groups("crawler sudo adm")
        self.assertEqual((done.returncode, done.stdout, calls), (0, "returned\n", "-d crawler sudo\n-d crawler adm\n"))


class KillSwitchRulesTest(unittest.TestCase):
    """The whole IPv4 kill switch, line for line: any new ACCEPT is a reviewed change to this list."""

    def rules(self, subnet: str, device: str) -> list[str]:
        done = subprocess.run(["bash", "-c", 'source "$1"; kill_switch_rules "$2" "$3"', "_", str(PROVISION),
                               subnet, device], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_loopback_ssh_replies_the_tor_users_and_dhcp_renewal_only(self):
        self.assertEqual(self.rules("192.168.5.0/24", "eth0"), [
            "*filter",
            ":INPUT ACCEPT [0:0]",
            ":FORWARD ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A OUTPUT -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
            # Non-terminating: the SYN that opens a Tor instance's connection marks it, and falls through to the
            # owner rule that accepts it.
            *(f"-A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW"
              f" -m owner --uid-owner _tor-crawl{n} -j CONNMARK --set-xmark 0x746f72/0xffffffff" for n in range(1, 7)),
            *(f"-A OUTPUT -m owner --uid-owner _tor-crawl{n} -j ACCEPT" for n in range(1, 7)),
            # The lease renewal, unicast to the gateway's subnet. Dropped, it fell back to a raw-socket broadcast
            # from 0.0.0.0:68 that iptables never sees and leak test 3 rightly flags.
            "-A OUTPUT -o eth0 -d 192.168.5.0/24 -p udp -m udp --sport 68 --dport 67"
            " -m owner --uid-owner systemd-network -j ACCEPT",
            # The kernel's own packets for a connection Tor has closed: they have no owner, only the mark.
            "-A OUTPUT -p tcp -m connmark --mark 0x746f72 -j ACCEPT",
            "-A OUTPUT -j DROP",
            "COMMIT",
        ])

    def test_only_a_tor_instances_syn_on_a_new_connection_sets_the_mark(self):
        rules = self.rules("192.168.5.0/24", "eth0")
        setting = [rule for rule in rules if "CONNMARK" in rule or "--set-" in rule or "-j MARK" in rule]
        self.assertEqual(len(setting), 6)
        for n, rule in enumerate(setting, 1):
            words = rule.split()
            self.assertEqual(words[words.index("--uid-owner") + 1], f"_tor-crawl{n}")
            for needed in ("-p tcp", "--tcp-flags FIN,SYN,RST,ACK SYN", "--ctstate NEW", "-m owner",
                           "-j CONNMARK --set-xmark 0x746f72/0xffffffff"):
                self.assertIn(needed, rule)
            self.assertNotIn("ESTABLISHED", rule)
            self.assertNotIn("RELATED", rule)
        self.assertFalse([rule for rule in rules if "--restore-mark" in rule or "--save-mark" in rule])

    def test_one_accept_reads_the_mark_after_the_owner_rules_and_right_before_the_drop(self):
        rules = self.rules("192.168.5.0/24", "eth0")
        reading = [rule for rule in rules if "-m connmark" in rule or "-m mark" in rule]
        self.assertEqual(reading, ["-A OUTPUT -p tcp -m connmark --mark 0x746f72 -j ACCEPT"])
        self.assertEqual(rules.index(reading[0]) + 1, rules.index("-A OUTPUT -j DROP"))
        owners = [n for n, rule in enumerate(rules) if rule.endswith("-j ACCEPT") and "--uid-owner _tor-crawl" in rule]
        marks = [n for n, rule in enumerate(rules) if "-j CONNMARK" in rule]
        self.assertLess(max(marks), min(owners), "a mark rule after its owner ACCEPT would never run")
        self.assertLess(max(owners), rules.index(reading[0]))
        # No rule accepts by connection state but the SSH reply rule, and no UDP but the lease renewal.
        self.assertEqual([rule for rule in rules if "ESTABLISHED" in rule or "RELATED" in rule],
                         ["-A OUTPUT -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT"])
        self.assertEqual(len([rule for rule in rules if "-p udp" in rule]), 1)
        self.assertEqual(len([rule for rule in rules if rule.endswith("-j ACCEPT")]), 10)

    def test_the_mark_is_the_one_the_leak_test_reads_and_ipv6_stays_closed(self):
        from tests.live import leak_analyze
        script = PROVISION.read_text()
        self.assertEqual(script.count("\nTOR_MARK=0x746f72\n"), 1)
        self.assertEqual(leak_analyze.TOR_MARK, 0x746f72)
        self.assertIn("printf '*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT DROP [0:0]\\nCOMMIT\\n'"
                      " > /etc/iptables/rules.v6", script)
        self.assertNotIn("ip6tables -A", script)
        self.assertNotIn("ip6tables -I", script)

    def test_the_dhcp_rule_follows_the_guest_network(self):
        rules = self.rules("10.0.2.0/24", "enp0s1")
        self.assertIn("-A OUTPUT -o enp0s1 -d 10.0.2.0/24 -p udp -m udp --sport 68 --dport 67"
                      " -m owner --uid-owner systemd-network -j ACCEPT", rules)

    def test_no_subnet_means_no_dhcp_rule(self):
        # A guest with no default route gets the spec's original kill switch, never a rule with an empty match.
        rules = self.rules("", "")
        self.assertFalse([rule for rule in rules if "systemd-network" in rule])
        self.assertEqual(rules[-3:], ["-A OUTPUT -p tcp -m connmark --mark 0x746f72 -j ACCEPT", "-A OUTPUT -j DROP", "COMMIT"])


if __name__ == "__main__":
    unittest.main()
