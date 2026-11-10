"""What make deploy installs in the guest: the systemd units, read as files, and the config sync, run on a fake
guest tree. The units must run each job as the right user from the root-owned copy, hardened, and no timer may
reach golive, triage, sources or a deploy."""
import configparser
import grp
import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

from onioncollect import ui

ROOT = Path(__file__).resolve().parent.parent
UNITS = ROOT / "deploy" / "systemd"
SYNC = ROOT / "deploy" / "sync_configs.sh"
PYTHON = "/opt/onioncollect/venv/bin/python"
CLI = f"{PYTHON} -s -E -m onioncollect --settings"

EXPECTED = {
    "onioncollect-crawl.service": ("crawler", f"{CLI} /home/crawler/settings.toml crawl run --until-idle"),
    "onioncollect-retention.service": ("analyst", f"{CLI} /home/analyst/settings.toml retention sweep"),
    "onioncollect-writer.service": ("analyst", f"{PYTHON} -s -E -m onioncollect.writer --data-dir /home/analyst/data"
                                               " --configs-dir /var/lib/onioncollect/configs"),
    "onioncollect-leak-test.service": ("root", "/bin/bash /opt/onioncollect/app/tests/live/leak_test.sh"),
    "onioncollect-log-audit.service": ("analyst", f"{PYTHON} -s -E tests/live/log_audit.py --data /home/analyst/data"
                                                  " --credentials %d /var/log/onioncollect/crawl.log /home/analyst/ui.log"),
    "onioncollect-ui.service": ("analyst", f"{PYTHON} -s -E -m onioncollect.ui_main --data-dir /home/analyst/data"
                                           f" --configs-dir /var/lib/onioncollect/configs --port {ui.PORT}"),
    "onioncollect-capture.service": ("analyst", f"{PYTHON} -s -E tools/writeup_capture.py --settings"
                                                " /home/analyst/settings.toml --credentials %d"
                                                " --out /home/analyst/writeup-capture"),
}
TIMERS = {"onioncollect-crawl.timer": "*:0/15", "onioncollect-retention.timer": "*-*-* 03:30",
          "onioncollect-leak-test.timer": "*-*-* 05:00"}
# Where each unit may write. The stores are written by the writer and the retention sweep alone; the UI and the
# capture write only the analyst's home outside them; the crawl, its state dir and its log.
WRITES = {
    "onioncollect-crawl.service": ["/home/crawler/state", "/var/log/onioncollect"],
    "onioncollect-writer.service": ["/home/analyst/data", "/var/lib/onioncollect/configs"],
    "onioncollect-retention.service": ["/home/analyst/data"],
    "onioncollect-ui.service": ["/home/analyst"],
    "onioncollect-capture.service": ["/home/analyst"],
    "onioncollect-log-audit.service": [],
}
READ_ONLY = {"onioncollect-ui.service": "/home/analyst/data", "onioncollect-capture.service": "/home/analyst/data"}
NEVER_SCHEDULED = ("golive", "triage", "sources", "deploy", "install.sh", "resolve", "records merge", "config ")


def unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string((UNITS / name).read_text())
    return parser


class UnitFilesTest(unittest.TestCase):
    def test_exactly_these_units(self):
        self.assertEqual({path.name for path in UNITS.iterdir()}, set(EXPECTED) | set(TIMERS))

    def test_each_service_runs_as_its_user_and_runs_this(self):
        for name, (user, command) in EXPECTED.items():
            with self.subTest(unit=name):
                service = unit(name)["Service"]
                if user == "root":
                    # Root by systemd's default. An explicit User=root, with NoNewPrivileges and the syscall
                    # filters, leaves CAP_SETUID out of the effective set, so the leak test's runuser to the
                    # crawler failed with EPERM and every scheduled run failed all four tests.
                    self.assertNotIn("User", service)
                else:
                    self.assertEqual(service["User"], user)
                self.assertEqual(service["ExecStart"], command)
                if user != "root":
                    self.assertEqual(service["Group"], user)
                    self.assertEqual(service["WorkingDirectory"], "/opt/onioncollect/app",
                                     "root-owned code, never the crawler's writable copy")

    def test_each_timer_fires_its_own_service_on_its_schedule(self):
        for name, calendar in TIMERS.items():
            with self.subTest(timer=name):
                timer = unit(name)
                self.assertEqual(timer["Timer"]["OnCalendar"], calendar)
                self.assertNotIn("Unit", timer["Timer"])
                self.assertIn(name.replace(".timer", ".service"), EXPECTED)
                self.assertEqual(timer["Install"]["WantedBy"], "timers.target")

    def test_no_timer_ever_reaches_golive_triage_sources_or_a_deploy(self):
        reached = set()
        todo = [name.replace(".timer", ".service") for name in TIMERS]
        while todo:
            name = todo.pop()
            if name in reached:
                continue
            reached.add(name)
            parsed = unit(name)
            for key in ("OnSuccess", "OnFailure", "Wants", "Requires"):
                todo.extend(parsed["Unit"].get(key, "").split())
        self.assertEqual(reached, {"onioncollect-crawl.service", "onioncollect-retention.service",
                                   "onioncollect-leak-test.service", "onioncollect-log-audit.service",
                                   "onioncollect-writer.service"})
        for name in reached:
            command = unit(name)["Service"]["ExecStart"]
            for word in NEVER_SCHEDULED:
                self.assertNotIn(word, command.split("settings.toml")[-1], (name, word))

    def test_every_service_is_hardened(self):
        for name, (user, _) in EXPECTED.items():
            with self.subTest(unit=name):
                service = unit(name)["Service"]
                self.assertEqual(service["NoNewPrivileges"], "yes")
                self.assertEqual(service["PrivateTmp"], "yes")
                self.assertEqual(service["SystemCallArchitectures"], "native")
                if user == "root":
                    # iptables, tcpdump and the kernel log: see the unit's comment.
                    self.assertEqual(service["ProtectSystem"], "full")
                    continue
                self.assertEqual(service["ProtectSystem"], "strict")
                self.assertEqual(service["ProtectHome"], "read-only")
                self.assertEqual(service["CapabilityBoundingSet"], "")
                self.assertEqual(service.get("ReadWritePaths", "").split(), WRITES[name], name)
                self.assertEqual(service.get("ReadOnlyPaths"), READ_ONLY.get(name), name)

    def test_network_reach_per_unit(self):
        for name in EXPECTED:
            service = unit(name)["Service"]
            with self.subTest(unit=name):
                if name == "onioncollect-writer.service":
                    self.assertEqual((service["PrivateNetwork"], service["RestrictAddressFamilies"],
                                      service["IPAddressDeny"]), ("yes", "AF_UNIX", "any"))
                elif name in ("onioncollect-crawl.service", "onioncollect-ui.service"):
                    self.assertEqual((service["IPAddressDeny"], service["IPAddressAllow"]), ("any", "localhost"))
                elif name != "onioncollect-leak-test.service":
                    self.assertEqual(service["PrivateNetwork"], "yes")
        service = unit("onioncollect-ui.service")["Service"]
        self.assertEqual((service["SocketBindAllow"], service["SocketBindDeny"]), (f"tcp:{ui.PORT}", "any"))
        self.assertEqual(service["RestrictAddressFamilies"], "AF_INET AF_UNIX")

    def test_the_crawl_may_bind_no_port(self):
        service = unit("onioncollect-crawl.service")["Service"]
        self.assertEqual(service["SocketBindDeny"], "any")
        self.assertNotIn("SocketBindAllow", service)
        self.assertEqual(service["RestrictAddressFamilies"], "AF_INET AF_UNIX")

    def test_the_ui_starts_from_its_own_entry_point_and_never_through_the_cli(self):
        for path in sorted(UNITS.glob("*.service")):
            command = unit(path.name)["Service"]["ExecStart"].split()
            with self.subTest(unit=path.name):
                if "onioncollect" in command:
                    self.assertNotIn("ui", command)
        self.assertIn("-m onioncollect.ui_main ", unit("onioncollect-ui.service")["Service"]["ExecStart"])

    def test_the_crawl_needs_the_writer_and_the_writer_its_socket_dir(self):
        crawl = unit("onioncollect-crawl.service")["Unit"]
        self.assertEqual(crawl["Requires"], "onioncollect-writer.service")
        self.assertIn("onioncollect-writer.service", crawl["After"].split())
        writer = unit("onioncollect-writer.service")
        self.assertEqual((writer["Service"]["RuntimeDirectory"], writer["Service"]["SupplementaryGroups"]),
                         ("onioncollect", "onioncollect-ipc"))
        self.assertEqual(writer["Install"]["WantedBy"], "multi-user.target", "enabled at boot")

    def test_the_ui_starts_after_the_writer_that_creates_the_stores(self):
        ui_unit = unit("onioncollect-ui.service")["Unit"]
        self.assertIn("onioncollect-writer.service", ui_unit["After"].split())
        self.assertEqual(ui_unit["Wants"], "onioncollect-writer.service")

    def test_the_credential_reaches_the_analyst_units_through_systemd_only(self):
        # The bare id makes systemd search its credstore, where a missing credential falls back to SetCredential.
        # A missing file named by an absolute path fails the unit instead (status 243, systemd 257), so the audit
        # never ran on a guest without testonion's credential.
        for name in ("onioncollect-log-audit.service", "onioncollect-capture.service"):
            service = unit(name)["Service"]
            self.assertEqual(service["LoadCredential"], "testonion.env")
            self.assertEqual(service["SetCredential"], "testonion.env:")
        # The credential itself stays at /etc/onioncollect; the credstore holds only a link to it, which must
        # exist exactly when the file does (a dangling link fails the unit like a missing path).
        install = (ROOT / "deploy" / "install.sh").read_text()
        self.assertIn("ln -sfn /etc/onioncollect/testonion.env /etc/credstore/testonion.env", install)
        self.assertIn("rm -f /etc/credstore/testonion.env", install)
        make = (ROOT / "Makefile").read_text()
        self.assertIn("ln -sfn /etc/onioncollect/testonion.env /etc/credstore/testonion.env", make)
        crawl = unit("onioncollect-crawl.service")["Unit"]
        self.assertEqual((crawl["OnSuccess"], crawl["OnFailure"]), ("onioncollect-log-audit.service",) * 2)

    def test_install_enables_the_timers_and_the_ui_and_leaves_the_crawl_to_make_deploy(self):
        install = (ROOT / "deploy" / "install.sh").read_text()
        self.assertIn('install -m 644 -o root -g root "$STAGE"/deploy/systemd/* /etc/systemd/system/', install)
        self.assertIn("systemctl enable $TIMERS onioncollect-ui.service onioncollect-writer.service", install)
        self.assertIn("systemctl restart onioncollect-writer.service", install)
        self.assertIn("getent group onioncollect-ipc >/dev/null || groupadd --system onioncollect-ipc", install)
        self.assertNotIn("start onioncollect-crawl.timer", install)
        makefile = (ROOT / "Makefile").read_text()
        deploy = makefile[makefile.index("\ndeploy: install"):].split("\n\n")[0]
        self.assertEqual(deploy.strip().splitlines()[1:], [
            "\tlimactl shell $(VM) sudo bash /opt/onioncollect/app/tests/live/leak_test.sh",
            "\tlimactl shell $(VM) sudo systemctl start onioncollect-crawl.timer"])

    def test_install_loads_each_users_settings_before_anything_is_swapped_in_or_restarted(self):
        install = (ROOT / "deploy" / "install.sh").read_text()
        check = 'runuser -u "$1" -- "$OPT/venv/bin/python" -s -E "$OPT/app.new/tools/settings_check.py" "${@:2}"'
        order = ["systemctl stop onioncollect-crawl.timer",
                 "install -m 600 -o analyst -g analyst /home/crawler/exclusions.txt /home/analyst/exclusions.txt",
                 check, "settings_check crawler --crawl /home/crawler/settings.toml",
                 "settings_check analyst /home/analyst/settings.toml", 'mv "$OPT/app.new" "$OPT/app"',
                 "systemctl restart onioncollect-writer.service", "deploy-stamp"]
        self.assertEqual([install.count(step) for step in order[:-1]], [1] * (len(order) - 1))
        positions = [install.index(step) for step in order]
        self.assertEqual(positions, sorted(positions))


class ConfigSyncTest(unittest.TestCase):
    """deploy/sync_configs.sh on a fake guest tree: a guest config the checkout lacks is never deleted unless
    PRUNE_CONFIGS=1 and a typed yes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.staged, self.guest = root / "staged", root / "guest"
        self.staged.mkdir()
        self.guest.mkdir()
        (self.staged / "news.toml").write_text("new news\n")
        (self.guest / "news.toml").write_text("old news\n")
        (self.guest / "testonion.toml").write_text("hand-installed\n")

    def tearDown(self):
        self.tmp.cleanup()

    def sync(self, answer: str = "", **env: str) -> str:
        owner = {"OWNER": pwd.getpwuid(os.getuid()).pw_name, "GROUP": grp.getgrgid(os.getgid()).gr_name}
        done = subprocess.run(["bash", str(SYNC), str(self.staged), str(self.guest)], input=answer, text=True,
                              capture_output=True, env={"PATH": os.environ["PATH"]} | owner | env, check=True)
        return done.stdout

    def guest_files(self) -> dict[str, str]:
        return {path.name: path.read_text() for path in self.guest.iterdir()}

    def test_a_dry_run_changes_nothing_and_deletes_nothing_without_prune(self):
        out = self.sync(DRY_RUN="1")
        self.assertEqual(self.guest_files(), {"news.toml": "old news\n", "testonion.toml": "hand-installed\n"})
        self.assertIn("would run: install -m 640", out)
        self.assertIn("kept; PRUNE_CONFIGS=1", out)
        self.assertNotIn("would run: rm", out)

    def test_a_dry_run_with_prune_and_yes_still_deletes_nothing(self):
        out = self.sync("yes\n", DRY_RUN="1", PRUNE_CONFIGS="1")
        self.assertIn("testonion.toml", self.guest_files())
        self.assertIn(f"would run: rm -- {self.guest / 'testonion.toml'}", out)

    def test_a_real_run_installs_and_keeps_the_guest_only_config(self):
        out = self.sync("yes\n")
        self.assertEqual(self.guest_files(), {"news.toml": "new news\n", "testonion.toml": "hand-installed\n"})
        self.assertIn("kept", out)

    def test_prune_deletes_only_after_a_typed_yes(self):
        for answer in ("", "no\n", "y\n", "YES\n"):
            with self.subTest(answer=answer):
                self.assertIn("kept, nothing deleted", self.sync(answer, PRUNE_CONFIGS="1"))
                self.assertIn("testonion.toml", self.guest_files())
        out = self.sync("yes\n", PRUNE_CONFIGS="1")
        self.assertIn("deleted testonion.toml", out)
        self.assertEqual(self.guest_files(), {"news.toml": "new news\n"})


if __name__ == "__main__":
    unittest.main()
