import dataclasses
import tempfile
import unittest
from pathlib import Path

from onioncrawl.config import Settings


def always_listening(port: int) -> bool:
    return True


class SettingsLoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.password = self.dir / "control-password"
        self.password.write_text("correct horse battery staple\n")
        self.password.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def write_settings(self, body: str = "") -> Path:
        path = self.dir / "settings.toml"
        path.write_text(f'control_password_file = "{self.password}"\n{body}')
        return path

    def test_minimal_file_gives_guide_defaults(self):
        settings = Settings.load(self.write_settings(), port_check=always_listening)
        self.assertEqual(settings.control_password, "correct horse battery staple")
        self.assertEqual(settings.tor_instances[0], (10051, 11051))
        self.assertEqual(settings.tor_instances[-1], (10056, 11056))
        self.assertEqual(settings.workers_per_instance, 3)
        self.assertEqual(settings.max_body_bytes, 2_000_000)
        self.assertEqual(settings.jitter_seconds, (1.0, 4.0))
        self.assertIn("Firefox/153.0", settings.user_agent)

    def test_overrides_are_converted(self):
        path = self.write_settings(
            'tor_instances = [[10051, 11051], [10052, 11052]]\n'
            'jitter_seconds = [2, 5]\n'
            'data_dir = "/home/crawler/data"\n'
            'max_depth = 4\n'
        )
        settings = Settings.load(path, port_check=always_listening)
        self.assertEqual(settings.tor_instances, ((10051, 11051), (10052, 11052)))
        self.assertEqual(settings.jitter_seconds, (2.0, 5.0))
        self.assertEqual(settings.data_dir, Path("/home/crawler/data"))
        self.assertEqual(settings.max_depth, 4)

    def test_every_port_is_checked_and_dead_ones_named(self):
        checked = []

        def only_socks_ports(port):
            checked.append(port)
            return port < 11000

        with self.assertRaises(RuntimeError) as ctx:
            Settings.load(self.write_settings(), port_check=only_socks_ports)
        self.assertEqual(len(checked), 12)
        self.assertIn("11051", str(ctx.exception))
        self.assertNotIn("10051", str(ctx.exception))

    def test_password_file_required(self):
        path = self.dir / "settings.toml"
        path.write_text("max_depth = 4\n")
        with self.assertRaises(ValueError):
            Settings.load(path, port_check=always_listening)

    def test_plaintext_password_key_rejected(self):
        with self.assertRaises(ValueError):
            Settings.load(self.write_settings('control_password = "inline"\n'), port_check=always_listening)

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            Settings.load(self.write_settings("max_dpeth = 4\n"), port_check=always_listening)
        self.assertIn("max_dpeth", str(ctx.exception))

    def test_password_file_readable_by_others_rejected(self):
        self.password.chmod(0o644)
        with self.assertRaises(PermissionError):
            Settings.load(self.write_settings(), port_check=always_listening)

    def test_empty_password_rejected(self):
        self.password.write_text("\n")
        with self.assertRaises(ValueError):
            Settings.load(self.write_settings(), port_check=always_listening)

    def test_password_never_in_repr(self):
        settings = Settings.load(self.write_settings(), port_check=always_listening)
        self.assertNotIn("staple", repr(settings))

    def test_frozen(self):
        settings = Settings.load(self.write_settings(), port_check=always_listening)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            settings.max_depth = 99


if __name__ == "__main__":
    unittest.main()
