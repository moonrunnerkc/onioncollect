import dataclasses
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from onioncollect.config import Settings, config_path, load_config, load_configs, load_credential
from onioncollect.source_config import ConfigError
from tests.fixtures import (NEWS_CONFIG, TESTONION_CONFIG, TESTONION_PASSWORD, TESTONION_USER, throwaway_settings,
                            write_credential)
from tests.test_onion import AHMIA

PATTERNS = "child_exploitation \\bforbiddenterm\\b\n"


def always_listening(port: int) -> bool:
    return True


class SettingsLoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.password = self.secret("control-password", "correct horse battery staple\n")
        self.salt = self.secret("redaction-salt", "s" * 40 + "\n")
        self.exclusions = self.dir / "exclusions.txt"
        self.exclusions.write_text(f"# listed\n{AHMIA}\n")
        self.patterns = self.dir / "safety-patterns.txt"
        self.patterns.write_text(PATTERNS)

    def tearDown(self):
        self.tmp.cleanup()

    def secret(self, name: str, text: str) -> Path:
        path = self.dir / name
        path.write_text(text)
        path.chmod(0o600)
        return path

    def write_settings(self, body: str = "", crawl_files: bool = True) -> Path:
        path = self.dir / "settings.toml"
        lines = [f'redaction_salt_file = "{self.salt}"', f'exclusions_file = "{self.exclusions}"']
        if crawl_files:
            lines += [f'control_password_file = "{self.password}"', f'safety_patterns_file = "{self.patterns}"']
        path.write_text("\n".join(lines) + f"\n{body}")
        return path

    def load_crawl(self, body: str = "") -> Settings:
        return Settings.load(self.write_settings(body), crawl=True, port_check=always_listening)

    def test_minimal_file_gives_guide_defaults(self):
        settings = self.load_crawl()
        self.assertEqual(settings.control_password, "correct horse battery staple")
        self.assertEqual(settings.tor_instances[0], (10051, 11051))
        self.assertEqual(settings.tor_instances[-1], (10056, 11056))
        self.assertEqual(settings.workers_per_instance, 3)
        self.assertEqual(settings.max_body_bytes, 2_000_000)
        self.assertEqual(settings.per_source_concurrency, 2)
        self.assertEqual(settings.jitter_seconds, (1.0, 4.0))
        self.assertEqual((settings.record_retention_days, settings.snapshot_retention_days), (180, 30))
        self.assertEqual((settings.data_dir, settings.configs_dir), (Path("./data"), Path("./configs")))
        self.assertIn("Firefox/153.0", settings.user_agent)

    def test_overrides_are_converted(self):
        settings = self.load_crawl(
            'tor_instances = [[10051, 11051], [10052, 11052]]\njitter_seconds = [2, 5]\n'
            'data_dir = "/home/crawler/data"\nconfigs_dir = "/srv/configs"\nsnapshot_retention_days = 7\n'
        )
        self.assertEqual(settings.tor_instances, ((10051, 11051), (10052, 11052)))
        self.assertEqual(settings.jitter_seconds, (2.0, 5.0))
        self.assertEqual(settings.data_dir, Path("/home/crawler/data"))
        self.assertEqual(settings.configs_dir, Path("/srv/configs"))
        self.assertEqual(settings.snapshot_retention_days, 7)

    def test_salt_loaded(self):
        self.assertEqual(self.load_crawl().redaction_salt, b"s" * 40)

    def test_retired_settings_are_unknown(self):
        for line in ('watchlist_dir = "/x"', 'findings_dir = "/x"', "max_depth = 2", "finding_retention_days = 1",
                     'hibp_api_key_file = "/x"'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.load_crawl(line + "\n")

    def test_short_salt_rejected(self):
        self.salt.write_text("short\n")
        with self.assertRaisesRegex(ValueError, "at least 32"):
            self.load_crawl()

    def test_salt_readable_by_others_rejected(self):
        self.salt.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.load_crawl()

    def test_every_port_is_checked_and_dead_ones_named(self):
        checked = []

        def only_socks_ports(port):
            checked.append(port)
            return port < 11000

        with self.assertRaises(RuntimeError) as ctx:
            Settings.load(self.write_settings(), crawl=True, port_check=only_socks_ports)
        self.assertEqual(len(checked), 12)
        self.assertIn("11051", str(ctx.exception))
        self.assertNotIn("10051", str(ctx.exception))

    def test_crawl_needs_every_crawl_file(self):
        path = self.write_settings(crawl_files=False)
        with self.assertRaisesRegex(ValueError, "control_password_file, safety_patterns_file required"):
            Settings.load(path, crawl=True, port_check=always_listening)

    def test_analyst_needs_no_tor_files_and_checks_no_ports(self):
        def no_ports(port):
            raise AssertionError("checked a Tor port")

        settings = Settings.load(self.write_settings(crawl_files=False), port_check=no_ports)
        self.assertIsNone(settings.control_password)
        self.assertEqual(settings.safety_patterns, ())
        # Triage refuses to approve an excluded host, so the analyst loads the list too.
        self.assertEqual(settings.exclusions, frozenset({AHMIA}))

    def test_salt_always_required(self):
        path = self.dir / "settings.toml"
        path.write_text('data_dir = "/tmp/x"\n')
        with self.assertRaisesRegex(ValueError, "redaction_salt_file, exclusions_file required"):
            Settings.load(path, port_check=always_listening)

    def test_safety_files_are_parsed_into_settings(self):
        settings = self.load_crawl()
        self.assertEqual(settings.exclusions, frozenset({AHMIA}))
        self.assertEqual(len(settings.safety_patterns), 1)

    def test_missing_safety_file_stops_startup(self):
        for path in (self.exclusions, self.patterns):
            with self.subTest(path=path.name):
                text = path.read_text()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    self.load_crawl()
                path.write_text(text)

    def test_empty_safety_file_stops_startup(self):
        for path in (self.exclusions, self.patterns):
            with self.subTest(path=path.name):
                text = path.read_text()
                path.write_text("# comments only\n")
                with self.assertRaisesRegex(ValueError, path.name):
                    self.load_crawl()
                path.write_text(text)

    def test_bad_safety_entry_names_file_and_line(self):
        self.exclusions.write_text(f"{AHMIA}\nexample.com\n")
        with self.assertRaisesRegex(ValueError, "exclusions.txt: line 2"):
            self.load_crawl()

    def test_inline_secrets_rejected(self):
        for key in ("control_password", "redaction_salt", "exclusions", "safety_patterns"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load_crawl(f'{key} = "inline"\n')

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.load_crawl("max_dpeth = 4\n")
        self.assertIn("max_dpeth", str(ctx.exception))

    def test_password_file_readable_by_others_rejected(self):
        self.password.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.load_crawl()

    def test_empty_password_rejected(self):
        self.password.write_text("\n")
        with self.assertRaises(ValueError):
            self.load_crawl()

    def test_secrets_and_lists_never_in_repr(self):
        settings = self.load_crawl()
        for secret in ("staple", AHMIA, "forbiddenterm", "s" * 40):
            self.assertNotIn(secret, repr(settings))

    def test_frozen(self):
        settings = self.load_crawl()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            settings.max_retries = 99


class LoadConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_path_is_the_id_dot_toml(self):
        self.assertEqual(config_path(self.dir, "news"), self.dir / "news.toml")

    def test_loads_a_valid_file(self):
        config_path(self.dir, "news").write_text(NEWS_CONFIG)
        self.assertEqual(load_config(self.dir, "news").id, "news")

    def test_missing_file_names_the_path(self):
        with self.assertRaisesRegex(ConfigError, f"{self.dir / 'news.toml'}: no config file"):
            load_config(self.dir, "news")

    def test_bad_file_names_the_path_and_the_problem(self):
        config_path(self.dir, "news").write_text(NEWS_CONFIG.replace('cadence = "6h"', 'cadence = "soon"'))
        with self.assertRaisesRegex(ConfigError, "news.toml: cadence"):
            load_config(self.dir, "news")

    def test_one_bad_file_does_not_stop_the_others(self):
        config_path(self.dir, "news").write_text(NEWS_CONFIG)
        config_path(self.dir, "broken").write_text("id = [")
        configs, errors = load_configs(self.dir, ["news", "broken", "absent"])
        self.assertEqual(list(configs), ["news"])
        self.assertEqual(sorted(errors), ["absent", "broken"])
        self.assertIn("not valid TOML", errors["broken"])
        self.assertIn("no config file", errors["absent"])


class LoadCredentialTest(unittest.TestCase):
    """Section 15's secrets file. Every refusal names the file and never a value."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.settings = throwaway_settings(credentials_dir=root / "etc", configs_dir=root / "configs",
                                           data_dir=root / "data")
        self.settings.configs_dir.mkdir()
        config_path(self.settings.configs_dir, "testonion").write_text(TESTONION_CONFIG)

    def tearDown(self):
        self.tmp.cleanup()

    def load(self):
        return load_credential(self.settings, "testonion", "testonion")

    def refused(self, error=ValueError) -> str:
        with self.assertRaises(error) as caught:
            self.load()
        message = str(caught.exception)
        self.assertNotIn(TESTONION_PASSWORD, message)
        self.assertNotIn(TESTONION_USER, message)
        return message

    def test_reads_both_values_and_never_shows_them(self):
        write_credential(self.settings)
        credential = self.load()
        self.assertEqual((credential.username, credential.password), (TESTONION_USER, TESTONION_PASSWORD))
        self.assertNotIn(TESTONION_PASSWORD, repr(credential))
        self.assertNotIn(TESTONION_USER, repr(credential))

    def test_readable_by_anyone_else_is_refused(self):
        for mode in (0o640, 0o604, 0o644):
            write_credential(self.settings, mode=mode)
            self.assertIn("mode 600", self.refused(PermissionError))

    def test_owned_by_another_user_is_refused(self):
        write_credential(self.settings)
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertIn("owned by this user", self.refused(PermissionError))

    def test_a_symlink_is_refused(self):
        target = write_credential(self.settings)
        target.rename(target.with_suffix(".real"))
        target.symlink_to(target.with_suffix(".real"))
        self.assertIn("regular file", self.refused(PermissionError))

    def test_inside_the_configs_or_the_data_dir_is_refused(self):
        for inside in (self.settings.configs_dir, self.settings.data_dir):
            self.settings = dataclasses.replace(self.settings, credentials_dir=inside / "secrets")
            write_credential(self.settings)
            self.assertIn("outside the configs and the data", self.refused(PermissionError))

    def test_anything_but_one_username_and_one_password_line(self):
        for text in (f"username={TESTONION_USER}\n", f"password={TESTONION_PASSWORD}\n",
                     f"username={TESTONION_USER}\npassword={TESTONION_PASSWORD}\ntoken=x\n",
                     f"username={TESTONION_USER}\nusername=x\npassword={TESTONION_PASSWORD}\n",
                     f"username=\npassword={TESTONION_PASSWORD}\n", f"{TESTONION_USER}\n{TESTONION_PASSWORD}\n"):
            write_credential(self.settings, text)
            self.assertIn("one username= line and one password= line", self.refused(), text)

    def test_a_value_also_written_in_the_config_is_refused_as_inline(self):
        write_credential(self.settings)
        for value in (TESTONION_USER, TESTONION_PASSWORD):
            config_path(self.settings.configs_dir, "testonion").write_text(TESTONION_CONFIG + f"# {value}\n")
            self.assertIn("holds a credential inline", self.refused())

    def test_missing_file(self):
        self.refused(FileNotFoundError)


if __name__ == "__main__":
    unittest.main()
