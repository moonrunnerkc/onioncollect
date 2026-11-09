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


if __name__ == "__main__":
    unittest.main()
