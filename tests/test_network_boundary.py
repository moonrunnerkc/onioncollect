"""Code boundaries, automated.

Section 17's leak and boundary tests, by where they run:
  Tor leak tests 1 to 3           live, in the guest, `make leak-test`
  Tor leak test 4, redirect trap  test_fetcher.RedirectTrapTest
  1 approval gate                 test_crawler.ApprovalGateTest
  2 frontier containment          test_crawler.FrontierContainmentTest
  3 redaction gate                test_crawler.RedactionGateTest, the top-priority health item included
  4 storage refusal               test_records.StorageRefusalTest
  5 auth containment              AuthContainmentTest, below, for the code; and for behaviour,
                                  test_fetcher_auth (any other source id raises before a request is built, a source
                                  not live or degraded is refused, the jar is empty after every response) and
                                  test_session (one login a run, the session gone after the run and after a crash,
                                  the credential nowhere under the data dir through the redaction gate and through
                                  a storage refusal)
  the search UI reads, never fetches  UIContainmentTest, below; test_ui for the read-only connection
"""
import ast
import re
import subprocess
import sys
import unittest
from pathlib import Path

from onioncollect import source_config

PACKAGE = Path(__file__).resolve().parent.parent / "onioncollect"

ALLOWED_ONLY_IN = {
    "httpx": {"fetcher.py"},
    "httpx_socks": {"fetcher.py"},
    "python_socks": {"fetcher.py"},
    "stem": {"tor_pool.py"},
    "socket": {"config.py"},
}
FORBIDDEN = {"urllib.request", "urllib3", "requests", "aiohttp", "http.client", "ssl", "asyncio.open_connection"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}
SENDING_CALLS = {"post", "put", "patch", "delete", "options", "head", "send"}
REQUEST_CALLS = {"stream", "request", "build_request"}
BODY_KEYWORDS = {"data", "files", "json", "content", "auth", "cookies"}
AUTH_WORDS = re.compile(r"log ?in|sign ?in|sign ?up|register|submit|captcha|password=|passwd=", re.IGNORECASE)
NETWORK_MODULES = ("fetcher.py",)
# Section 15's auth step, and what each does when the source is off AUTH_ALLOWLIST: its first statement.
AUTH_STEP = {"Fetcher.log_in": "raise AuthRefused", "Fetcher._post_form": "raise AuthRefused",
             "Fetcher._session_for": "return {}"}


def tree_of(path: Path) -> ast.AST:
    return ast.parse(path.read_text())


def imports_of(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(tree_of(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def attribute_uses(path: Path) -> set[str]:
    uses = set()
    for node in ast.walk(tree_of(path)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            uses.add(f"{node.value.id}.{node.attr}")
    return uses


def package_modules_reached_from(name: str) -> set[str]:
    seen, todo = set(), [name]
    while todo:
        module = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        for imported in imports_of(PACKAGE / f"{module}.py"):
            parts = imported.split(".")
            if parts[0] == "onioncollect" and len(parts) > 1 and (PACKAGE / f"{parts[1]}.py").exists():
                todo.append(parts[1])
    return seen


class NetworkBoundaryTest(unittest.TestCase):
    def modules(self):
        files = sorted(PACKAGE.glob("*.py"))
        self.assertTrue(files)
        return files

    def test_network_libraries_confined(self):
        for path in self.modules():
            for name in imports_of(path):
                root = name.split(".")[0]
                if root in ALLOWED_ONLY_IN:
                    self.assertIn(path.name, ALLOWED_ONLY_IN[root], f"{path.name} imports {name}")

    def test_forbidden_libraries_absent(self):
        for path in self.modules():
            used = imports_of(path) | attribute_uses(path)
            self.assertFalse(used & FORBIDDEN, f"{path.name} uses {used & FORBIDDEN}")

    def test_no_environment_config(self):
        for path in self.modules():
            used = imports_of(path) | attribute_uses(path)
            self.assertFalse(used & {"os.environ", "os.getenv", "os.environ.get"}, path.name)

    def test_the_fetcher_takes_a_source_id_and_a_path_never_a_url(self):
        tree = tree_of(PACKAGE / "fetcher.py")
        fetch = next(node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == "fetch")
        self.assertEqual([arg.arg for arg in fetch.args.args], ["self", "source_id", "path"])

    def test_every_fetcher_is_built_for_collecting_or_under_test_only(self):
        # Sibling probes and the fixed and mirror-swapped checks build fetchers too; each takes one of the two
        # state sets, and only golive's own check takes the approved one.
        built = []
        for path in sorted(PACKAGE.glob("*.py")):
            for node in ast.walk(tree_of(path)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for call in ast.walk(node):
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Fetcher":
                            built.append((path.name, node.name, ast.unparse(call.args[-1])))
        self.assertEqual(sorted(built), [
            ("crawler.py", "worker", "lifecycle.COLLECTING"),
            ("golive.py", "go_live", "lifecycle.UNDER_TEST"),
            ("golive.py", "recheck", "lifecycle.COLLECTING"),
            ("probes.py", "probe", "lifecycle.COLLECTING"),
        ])

    def test_requests_are_built_in_the_fetcher_only(self):
        sites = [(name, call.lineno) for name, call in calls() if call.func.attr in REQUEST_CALLS | SENDING_CALLS]
        self.assertEqual({name for name, _ in sites}, {"fetcher.py"}, sites)


def calls():
    for path in sorted(PACKAGE.glob("*.py")):
        for node in ast.walk(tree_of(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                yield path.name, node


def owned_nodes():
    for path in sorted(PACKAGE.glob("*.py")):
        yield from owned_nodes_of(path, tree_of(path))


def owned_nodes_of(path: Path, tree: ast.AST):
    """Every node of a module with the qualified name of the function or class around it, docstrings left out."""
    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
                  and isinstance(node.body[0].value.value, str)}
    todo = [(tree, "")]
    while todo:
        node, owner = todo.pop()
        for child in ast.iter_child_nodes(node):
            name = owner
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{owner}.{child.name}" if owner else child.name
            if id(child) not in docstrings:
                yield path.name, child, name
            todo.append((child, name))


def in_auth_step(module: str, owner: str) -> bool:
    return module == "fetcher.py" and owner in AUTH_STEP


def method_name(call: ast.Call) -> str | None:
    return call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) else None


class AuthContainmentTest(unittest.TestCase):
    """Section 17, test 5. Section 15's auth step is three methods of Fetcher. Anything that sends a body, names
    a method other than GET, submits a form, or reads or holds a cookie anywhere else fails the build, and so
    does an auth step that does not test AUTH_ALLOWLIST before anything else."""

    def test_the_allowlist_is_the_self_hosted_onion_alone_and_is_never_changed(self):
        self.assertEqual(source_config.AUTH_ALLOWLIST, frozenset({"testonion"}))
        bound = []
        for module, node, owner in owned_nodes():
            targets = (node.targets if isinstance(node, ast.Assign) else [node.target]
                       if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
            bound += [(module, owner) for target in targets
                      if isinstance(target, ast.Name) and target.id == "AUTH_ALLOWLIST"]
            if isinstance(node, ast.Attribute) and ast.unparse(node.value) == "AUTH_ALLOWLIST":
                self.fail(f"{module}:{node.lineno} AUTH_ALLOWLIST.{node.attr}")
        self.assertEqual(bound, [("source_config.py", "")])

    def test_each_auth_step_tests_the_allowlist_before_anything_else(self):
        methods = {owner: node for module, node, owner in owned_nodes() if module == "fetcher.py"
                   and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and owner.startswith("Fetcher.")}
        for name, refusal in AUTH_STEP.items():
            body = methods[name].body
            first = body[1] if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) else body[0]
            self.assertIsInstance(first, ast.If, name)
            test = first.test
            self.assertTrue(isinstance(test, ast.Compare) and isinstance(test.ops[0], ast.NotIn)
                            and isinstance(test.comparators[0], ast.Name) and test.comparators[0].id == "AUTH_ALLOWLIST"
                            and ast.unparse(test.left) in ("source_id", "result.source_id"), f"{name}: {ast.unparse(test)}")
            self.assertEqual((len(first.body), first.orelse), (1, []), name)
            self.assertEqual(ast.unparse(first.body[0]).split("(")[0], refusal, name)

    def test_requests_other_than_get_only_in_the_auth_step(self):
        sites = []
        for module, node, owner in owned_nodes():
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, SENDING_CALLS, f"{module}:{node.lineno} .{node.func.attr}()")
                if node.func.attr in REQUEST_CALLS:
                    sites.append((module, owner, method_name(node)))
        self.assertEqual(sorted(sites), [("fetcher.py", "Fetcher._get", "GET"), ("fetcher.py", "Fetcher._post_form", "POST")])

    def test_request_bodies_only_in_the_auth_step(self):
        for module, node, owner in owned_nodes():
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in REQUEST_CALLS | {"get", "AsyncClient"}:
                sent = {keyword.arg for keyword in node.keywords} & BODY_KEYWORDS
                allowed = {"data"} if in_auth_step(module, owner) and method_name(node) == "POST" else set()
                self.assertLessEqual(sent, allowed, f"{module}:{node.lineno} sends {sent}")

    def test_write_methods_named_only_in_the_auth_step(self):
        for module, node, owner in owned_nodes():
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.upper() in WRITE_METHODS:
                self.assertTrue(in_auth_step(module, owner) and node.value == "POST", f"{module}:{node.lineno}")

    def test_no_cookie_named_and_no_session_held_outside_the_auth_step(self):
        for module, node, owner in owned_nodes():
            if in_auth_step(module, owner):
                continue
            where = f"{module}:{getattr(node, 'lineno', '?')} in {owner or 'the module'}"
            if module in NETWORK_MODULES and isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertNotIn("cookie", node.value.lower(), where)
            if isinstance(node, ast.Attribute) and node.attr == "_cookies":
                self.assertTrue(module == "fetcher.py" and owner.startswith("Sessions."), where)

    def test_the_cookie_jar_is_only_ever_cleared_outside_the_auth_step(self):
        for path in sorted(PACKAGE.glob("*.py")):
            tree = tree_of(path)
            cleared = {id(node.func.value) for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == "clear"}
            for module, node, owner in owned_nodes_of(path, tree):
                if isinstance(node, ast.Attribute) and node.attr == "cookies" and not in_auth_step(module, owner):
                    self.assertIn(id(node), cleared, f"{module}:{node.lineno} uses the cookie jar")

    def test_the_session_store_can_only_end_sessions(self):
        store = [(owner, node) for module, node, owner in owned_nodes() if module == "fetcher.py"
                 and owner.startswith("Sessions.")]
        self.assertEqual({owner for owner, node in store if isinstance(node, ast.FunctionDef)},
                         {"Sessions.__init__", "Sessions.holds", "Sessions.end", "Sessions.end_all"})
        called = {node.func.attr for _, node in store
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertLessEqual(called, {"pop", "clear"})

    def test_no_login_or_form_flow_in_the_network_modules_outside_the_auth_step(self):
        for module, node, owner in owned_nodes():
            if module in NETWORK_MODULES and not in_auth_step(module, owner) \
                    and isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertIsNone(AUTH_WORDS.search(node.value), f"{module}:{node.lineno} {node.value!r}")

    def test_only_the_session_module_logs_in_and_only_the_crawler_and_recheck_hold_sessions(self):
        logins = [(module, owner) for module, node, owner in owned_nodes() if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute) and node.func.attr == "log_in"]
        self.assertEqual(logins, [("session.py", "Logins.sign_in")])
        built = sorted((module, owner) for module, node, owner in owned_nodes() if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Name) and node.func.id == "Logins")
        self.assertEqual(built, [("crawler.py", "Crawler.open"), ("golive.py", "recheck")])


if __name__ == "__main__":
    unittest.main()


class UIContainmentTest(unittest.TestCase):
    """The search UI reads the stores and serves one listener on 127.0.0.1. It can reach neither the fetcher nor
    the Tor pool nor a session, and nothing in it opens a socket but that listener."""

    UI = PACKAGE / "ui.py"
    NETWORK = {"fetcher", "tor_pool", "session", "probes", "crawler", "golive", "crawl_cli", "health_cli", "cli"}
    OUTSIDE = ("httpx", "httpx_socks", "python_socks", "stem", "aiosqlite")

    def test_ui_imports_exactly_these(self):
        modules = set()
        for node in ast.walk(tree_of(self.UI)):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module if node.module != "onioncollect" else "onioncollect.*")
        self.assertEqual(modules, {"argparse", "json", "logging", "os", "pwd", "re", "sqlite3", "sys", "time",
                                   "datetime", "http.server", "logging.handlers", "pathlib", "urllib.parse",
                                   "onioncollect.*", "onioncollect.config"})
        self.assertEqual({name for name in imports_of(self.UI) if name.startswith("onioncollect.")} - {
            "onioncollect.config"}, {"onioncollect.lifecycle", "onioncollect.search", "onioncollect.views",
                                     "onioncollect.config.Settings", "onioncollect.config.config_path"})

    def test_nothing_the_ui_reaches_can_fetch(self):
        reached = package_modules_reached_from("ui")
        self.assertEqual(reached & self.NETWORK, set(), reached)
        for module in reached:
            found = {name.split(".")[0] for name in imports_of(PACKAGE / f"{module}.py")} & set(self.OUTSIDE)
            self.assertEqual(found, set(), module)

    def test_importing_the_ui_loads_no_network_code(self):
        loaded = subprocess.run(
            [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import onioncollect.ui;"
             " print(' '.join(sorted(sys.modules)))", str(PACKAGE.parent)],
            capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual([m for m in loaded if m.split(".")[0] in self.OUTSIDE + ("http.client", "urllib.request")
                          or m in {f"onioncollect.{name}" for name in self.NETWORK}], [])

    def test_its_only_socket_is_its_own_listener_on_the_literal_loopback_address(self):
        tree = tree_of(self.UI)
        (address,) = [node.value.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "ADDRESS" for t in node.targets)]
        self.assertEqual(address, "127.0.0.1")
        servers = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
                   and any(isinstance(b, ast.Name) and b.id.endswith("HTTPServer") for b in node.bases)]
        self.assertEqual([node.name for node in servers], ["UIServer"])
        binds = [node for node in ast.walk(servers[0]) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "__init__"]
        self.assertEqual([ast.unparse(node.args[0]) for node in binds], ["(ADDRESS, port)"])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                self.assertNotRegex(name, r"(?i)socket|create_connection|getaddrinfo|urlopen|sendto|"
                                          r"\.request\b|HTTPConnection", name)
                if name.endswith("connect"):
                    self.assertEqual(name, "sqlite3.connect", f"ui.py:{node.lineno}")
            if isinstance(node, ast.Name) and node.id.endswith(("HTTPServer", "TCPServer", "UDPServer")):
                self.assertIn(node.id, {"ThreadingHTTPServer"}, f"ui.py:{node.lineno}")
