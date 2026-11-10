"""The search UI's own entry point, ui_main.py. It never goes through cli.py, so the UI process holds no network
library: checked statically over its import closure, and live by starting it in a clean interpreter and listing
every module loaded once it has set up."""
import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from onioncollect import cli, ui, ui_main
from tests.test_ui import build_stores
from tests.fixtures import throwaway_settings

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "onioncollect"

CLOSURE = {
    "onioncollect.ui_main": {"argparse", "os", "pwd", "sqlite3", "pathlib", "onioncollect.ui"},
    "onioncollect.ui": {"json", "logging", "logging.handlers", "os", "re", "sqlite3", "sys", "time", "datetime",
                        "http.server", "pathlib", "urllib.parse", "onioncollect.lifecycle", "onioncollect.search",
                        "onioncollect.views"},
    "onioncollect.lifecycle": {"re"},
    "onioncollect.search": set(),
    "onioncollect.views": {"html", "urllib.parse"},
}
NEVER_LOADED = ("httpx", "httpcore", "httpx_socks", "python_socks", "socks", "socksio", "h11", "h2", "anyio",
                "stem", "aiosqlite", "selectolax", "asyncio", "urllib.request", "smtplib", "ftplib", "xmlrpc")
NEVER_LOADED_HERE = ("fetcher", "tor_pool", "crawler", "crawl_cli", "cli", "golive", "session", "probes", "config",
                     "health_cli", "config_cli", "db", "stores", "records", "sources")
# Loaded by http.server itself, standard library, and unavoidable short of writing an HTTP server. The UI calls
# none of them (UIContainmentTest), and its unit allows it to bind its one port on loopback and nothing else.
SERVER_NETWORK = {"socket", "socketserver", "selectors", "select", "ssl", "http", "http.client", "http.server"}
NETWORK_ROOTS = {"socket", "socketserver", "selectors", "select", "ssl", "http", "asyncio", "urllib.request",
                 "smtplib", "ftplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "nntplib"}


def own_imports(module: str) -> set[str]:
    """Every module a file imports, by full name: `from onioncollect import ui` counts as onioncollect.ui."""
    path = PACKAGE / f"{module.split('.')[-1]}.py"
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "onioncollect":
                names.update(f"onioncollect.{alias.name}" for alias in node.names)
            else:
                names.add(node.module)
    return names


def closure(start: str) -> dict[str, set[str]]:
    found, waiting = {}, [start]
    while waiting:
        module = waiting.pop()
        if module not in found:
            found[module] = own_imports(module)
            waiting.extend(name for name in found[module] if name.startswith("onioncollect."))
    return found


def loaded_modules(data_dir: Path, configs_dir: Path, home: Path) -> list[str]:
    # serve_forever is swapped for a listing of sys.modules, so the list is taken where serving would begin.
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(home)}
    done = subprocess.run(
        [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from onioncollect import ui, ui_main;"
         " ui.UIServer.serve_forever = lambda server: print(' '.join(sorted(sys.modules)));"
         " ui_main.main(sys.argv[2:])", str(ROOT), "--data-dir", str(data_dir), "--configs-dir", str(configs_dir),
         "--port", "0"],
        capture_output=True, text=True, env=environment, timeout=60)
    if done.returncode != 0:
        raise AssertionError(done.stderr)
    return done.stdout.split()


class StaticClosureTest(unittest.TestCase):
    def test_the_entry_point_reaches_exactly_these(self):
        self.assertEqual(closure("onioncollect.ui_main"), CLOSURE)

    def test_everything_outside_the_package_is_standard_library(self):
        for module, names in closure("onioncollect.ui_main").items():
            outside = {name.split(".")[0] for name in names if not name.startswith("onioncollect.")}
            self.assertEqual(outside - sys.stdlib_module_names, set(), module)

    def test_cli_no_longer_serves_the_ui(self):
        self.assertNotIn("onioncollect.ui", own_imports("onioncollect.cli"))
        (commands,) = [action for action in cli.build_parser()._actions if action.dest == "==SUPPRESS=="
                       and action.choices]
        self.assertNotIn("ui", commands.choices)


class LoadedModulesTest(unittest.TestCase):
    """The entry point in a clean interpreter (-I: no PYTHON* variables, no user site, no script directory) against
    read-only stores: it checks the user, opens the stores, logs and binds, then lists sys.modules."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        settings = throwaway_settings(data_dir=root / "data", configs_dir=root / "configs")
        settings.data_dir.mkdir()
        build_stores(settings)
        everything = [*settings.data_dir.rglob("*"), settings.data_dir]
        for path in everything:
            path.chmod(0o550 if path.is_dir() else 0o440)
        try:
            cls.loaded = loaded_modules(settings.data_dir, settings.configs_dir, root)
        finally:
            for path in reversed(everything):
                path.chmod(0o750 if path.is_dir() else 0o640)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_it_set_up_before_listing(self):
        self.assertIn("onioncollect.ui_main", self.loaded)
        self.assertIn("logging.handlers", self.loaded)

    def test_no_network_library_and_no_crawler_module_is_loaded(self):
        forbidden = [name for name in self.loaded if name in NEVER_LOADED or name.split(".")[0] in NEVER_LOADED
                     or name in {f"onioncollect.{module}" for module in NEVER_LOADED_HERE}]
        self.assertEqual(forbidden, [])

    def test_the_package_modules_loaded_are_exactly_the_closure(self):
        self.assertEqual({name for name in self.loaded if name.startswith("onioncollect.")}, set(CLOSURE))

    def test_nothing_loaded_is_outside_the_standard_library(self):
        outside = {name.split(".")[0] for name in self.loaded} - sys.stdlib_module_names - {"__main__", "onioncollect"}
        self.assertEqual(outside, set())

    def test_the_only_network_modules_are_the_ones_http_server_brings(self):
        network = {name for name in self.loaded if name in NETWORK_ROOTS or name.split(".")[0] in NETWORK_ROOTS}
        self.assertEqual(network, SERVER_NETWORK)


class RefusalTest(unittest.TestCase):
    def test_a_missing_store_stops_it_before_it_listens(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            data.mkdir(mode=0o550)
            try:
                with mock.patch.object(ui, "UIServer", side_effect=AssertionError("listened")), \
                        self.assertRaises(SystemExit) as caught:
                    ui_main.main(["--data-dir", str(data), "--configs-dir", tmp])
            finally:
                data.chmod(0o750)
        self.assertIn("collect.db unreadable", str(caught.exception))
        self.assertIn("the writer creates it when it starts", str(caught.exception))
        self.assertNotIn("crawler", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
