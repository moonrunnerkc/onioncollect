"""Section 15 code checklist, automated: only fetcher.py may touch the network."""
import ast
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "onioncrawl"

ALLOWED_ONLY_IN = {
    "httpx": {"fetcher.py"},
    "httpx_socks": {"fetcher.py"},
    "python_socks": {"fetcher.py"},
    "stem": {"tor_pool.py"},
    "socket": {"config.py"},
}
FORBIDDEN = {"urllib.request", "urllib3", "requests", "aiohttp", "http.client", "ssl", "asyncio.open_connection"}


def imports_of(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def attribute_uses(path: Path) -> set[str]:
    uses = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            uses.add(f"{node.value.id}.{node.attr}")
    return uses


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


if __name__ == "__main__":
    unittest.main()
