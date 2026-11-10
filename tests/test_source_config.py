import unittest
from datetime import timedelta

from onioncollect import source_config
from onioncollect.source_config import ConfigError, Selector, parse, scaffold, with_hosts
from tests.fixtures import (NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, TESTONION, TESTONION_CONFIG, news_config,
                            testonion_config)
from tests.test_onion import AHMIA, flip_char


def edited(old: str, new: str) -> str:
    assert old in NEWS_CONFIG, old
    return NEWS_CONFIG.replace(old, new)


class ValidConfigTest(unittest.TestCase):
    def test_guide_example_shape(self):
        config = news_config()
        self.assertEqual((config.id, config.hosts, config.category), ("news", (NEWS,), "journalism-publishing"))
        self.assertEqual((config.cadence, config.scheme, config.seeds), (timedelta(hours=6), "http", ("/articles/",)))
        self.assertEqual((config.next_page, config.max_pages), (Selector("a.next", "href"), 3))
        self.assertEqual(config.fields["url"], Selector("h2 a", "href"))
        self.assertEqual(config.fields["title"], Selector("h2 a", None))
        self.assertEqual((config.follow, config.detail_fields), ("url", {"body": Selector("div.body", None)}))
        self.assertEqual((config.min_items_per_page, config.required_fields), (2, ("title", "url")))

    def test_optional_tables_default(self):
        text = edited('[pagination]\nnext = "a.next"\nmax_pages = 3\n', "")
        text = text.replace('[detail]\nfollow = "url"\n\n[detail.fields]\nbody = "div.body"\n', "")
        config = parse(text, "news")
        self.assertEqual((config.next_page, config.max_pages, config.follow, config.detail_fields), (None, 1, None, {}))

    def test_https_and_hosts_lowercased_and_deduplicated(self):
        config = parse(edited(f'hosts = ["{NEWS}"]', f'hosts = ["{NEWS.upper()}", "{NEWS}", "{NEWS_MIRROR}"]\nscheme = "https"'), "news")
        self.assertEqual((config.hosts, config.scheme), ((NEWS, NEWS_MIRROR), "https"))

    def test_cadence_units(self):
        for text, expected in (("30m", timedelta(minutes=30)), ("12h", timedelta(hours=12)), ("2d", timedelta(days=2))):
            self.assertEqual(parse(edited('cadence = "6h"', f'cadence = "{text}"'), "news").cadence, expected)

    def test_pagination_next_keeps_an_explicit_attribute(self):
        config = parse(edited('next = "a.next"', 'next = "link[rel=next]@href"'), "news")
        self.assertEqual(config.next_page, Selector("link[rel=next]", "href"))


class RefusedConfigTest(unittest.TestCase):
    def refused(self, text: str, expected_id: str = "news") -> str:
        with self.assertRaises(ConfigError) as caught:
            parse(text, expected_id)
        return str(caught.exception)

    def test_not_toml(self):
        self.assertIn("TOML", self.refused("id = "))

    def test_id_must_match_the_file_name(self):
        self.assertIn("file name", self.refused(NEWS_CONFIG, "other"))

    def test_hosts_must_be_v3(self):
        for host in (flip_char(AHMIA, 5), "expyuzz4wqqyqhjn.onion", "example.com", AHMIA.removesuffix(".onion")):
            self.assertIn("v3", self.refused(edited(f'hosts = ["{NEWS}"]', f'hosts = ["{host}"]')), host)
        self.assertIn("at least one", self.refused(edited(f'hosts = ["{NEWS}"]', "hosts = []")))

    def test_category_outside_the_policy(self):
        self.assertIn("policy", self.refused(edited('"journalism-publishing"', '"market"')))

    def test_auth_none_takes_nothing_else(self):
        self.assertIn('auth.type must be "none" or "form-session"', self.refused(edited('type = "none"', 'type = "basic"')))
        self.assertIn("unknown", self.refused(edited('type = "none"', 'type = "none"\nretries = 3')))

    def test_unknown_keys_at_every_level(self):
        self.assertIn("unknown", self.refused(NEWS_CONFIG + '\nscript = "x"\n'))
        self.assertIn("listing", self.refused(edited('item = "article"', 'item = "article"\nxpath = "//a"')))
        self.assertIn("expect", self.refused(edited("min_items_per_page = 2", "min_items_per_page = 2\nmax = 9")))

    def test_a_config_without_expectations_or_auth_is_refused(self):
        self.assertIn("missing expect", self.refused(edited("[expect]\nmin_items_per_page = 2\n"
                                                             'required_fields = ["title", "url"]\n', "")))
        self.assertIn("missing auth", self.refused(edited('[auth]\ntype = "none"\n', "")))

    def test_expectations_are_required_and_sane(self):
        self.assertIn("min_items", self.refused(edited("min_items_per_page = 2", "min_items_per_page = 0")))
        self.assertIn("min_items", self.refused(edited("min_items_per_page = 2", "min_items_per_page = true")))
        self.assertIn("required_fields", self.refused(edited('["title", "url"]', "[]")))
        self.assertIn("required_fields", self.refused(edited('["title", "url"]', '["title", "author"]')))

    def test_selectors_are_css_only(self):
        for bad in ("//div[@class='x']", "/html/body", "div >", "a[[", ""):
            self.assertIn("CSS", self.refused(edited('item = "article"', f'item = "{bad}"')), bad)

    def test_attribute_suffix_must_be_an_attribute_name(self):
        self.assertIn("attribute", self.refused(edited('"h2 a@href"', '"h2 a@hr ef"')))

    def test_follow_must_name_a_link_field(self):
        self.assertIn("follow", self.refused(edited('follow = "url"', 'follow = "title"')))
        self.assertIn("follow", self.refused(edited('follow = "url"', 'follow = "missing"')))
        self.assertIn("follow", self.refused(edited('follow = "url"', 'follow = "published"')))

    def test_cadence(self):
        self.assertIn("at least", self.refused(edited('cadence = "6h"', 'cadence = "10m"')))
        for bad in ("6 hours", "6", "h", "1w"):
            self.assertIn("cadence", self.refused(edited('cadence = "6h"', f'cadence = "{bad}"')), bad)

    def test_seeds_are_paths(self):
        for bad in (f"http://{NEWS}/", "articles/", "//evil.example/", f"http://{OFF_SOURCE}/x"):
            self.assertIn("seeds", self.refused(edited('seeds = ["/articles/"]', f'seeds = ["{bad}"]')), bad)
        self.assertIn("seeds", self.refused(edited('seeds = ["/articles/"]', "seeds = []")))

    def test_max_pages_bounds(self):
        for bad in ("0", str(source_config.MAX_PAGES + 1), '"3"'):
            self.assertIn("max_pages", self.refused(edited("max_pages = 3", f"max_pages = {bad}")), bad)

    def test_field_names(self):
        self.assertIn("field name", self.refused(edited('title = "h2 a"', 'Title = "h2 a"')))

    def test_bad_scheme(self):
        self.assertIn("scheme", self.refused(NEWS_CONFIG.replace('cadence = "6h"', 'cadence = "6h"\nscheme = "ftp"')))


class PathForTest(unittest.TestCase):
    def test_paths_on_any_source_host(self):
        config = parse(edited(f'hosts = ["{NEWS}"]', f'hosts = ["{NEWS}", "{NEWS_MIRROR}"]'), "news")
        self.assertEqual(config.path_for(f"http://{NEWS}/a?b=1#c"), "/a?b=1")
        self.assertEqual(config.path_for(f"http://{NEWS_MIRROR}/a"), "/a")

    def test_off_source_and_clearnet_are_none(self):
        config = news_config()
        for url in (f"http://{OFF_SOURCE}/a", "https://example.com/a", "/relative", "garbage"):
            self.assertIsNone(config.path_for(url), url)


class HostPrefixTest(unittest.TestCase):
    WWW = edited('cadence = "6h"', 'cadence = "6h"\nhost_prefix = "www"')

    def test_www_is_the_only_value_the_schema_takes(self):
        self.assertEqual(parse(self.WWW, "news").host_prefix, "www")
        self.assertIsNone(news_config().host_prefix)
        self.assertEqual(parse(self.WWW, "news").hosts, (NEWS,), "the host set is still the bare address")
        for value in ('"m"', '"WWW"', '"www."', '"www2"', '""', '"www.cdn"', '" www"', "1", "true", '["www"]',
                      f'"{OFF_SOURCE}"'):
            with self.subTest(value=value), self.assertRaisesRegex(ConfigError, "host_prefix can only be"):
                parse(edited('cadence = "6h"', f'cadence = "6h"\nhost_prefix = {value}'), "news")

    def test_never_on_the_source_that_logs_in(self):
        with self.assertRaisesRegex(ConfigError, "never on a form-session source"):
            testonion_config(TESTONION_CONFIG.replace('cadence = "6h"', 'cadence = "6h"\nhost_prefix = "www"'))

    def test_a_prefixed_link_is_a_path_only_on_the_sources_own_address(self):
        config = parse(self.WWW, "news")
        self.assertEqual(config.path_for(f"https://www.{NEWS}/a?b=1#c"), "/a?b=1")
        self.assertEqual(config.path_for(f"http://{NEWS}/a"), "/a")
        for url in (f"http://www.{OFF_SOURCE}/a", f"http://www.www.{NEWS}/a", f"http://m.{NEWS}/a",
                    f"http://www.{NEWS}.example.com/a", f"http://www.{NEWS}@example.com/a", "https://www.example.com/"):
            with self.subTest(url=url):
                self.assertIsNone(config.path_for(url))
        self.assertIsNone(news_config().path_for(f"http://www.{NEWS}/a"), "no prefix in the config, no www links")


class ScaffoldTest(unittest.TestCase):
    def test_scaffold_fails_until_filled_in(self):
        text = scaffold("new-source", NEWS, "directories")
        with self.assertRaises(ConfigError):
            parse(text, "new-source")
        filled = text.replace('item = ""', 'item = "li"').replace('title = ""', 'title = "a"').replace(
            'url = "@href"', 'url = "a@href"')
        config = parse(filled, "new-source")
        self.assertEqual((config.hosts, config.category, config.seeds), ((NEWS,), "directories", ("/",)))


class WithHostsTest(unittest.TestCase):
    def test_appends_to_the_hosts_array_and_changes_nothing_else(self):
        text = with_hosts(NEWS_CONFIG, [NEWS_MIRROR.upper()[:-6] + ".onion"])
        self.assertEqual(text, NEWS_CONFIG.replace(f'hosts = ["{NEWS}"]', f'hosts = ["{NEWS}", "{NEWS_MIRROR}"]'))
        self.assertEqual(parse(text, "news").hosts, (NEWS, NEWS_MIRROR))
        self.assertEqual(with_hosts(text, [NEWS]), text)

    def test_works_on_an_unfilled_scaffold_and_a_multiline_array(self):
        self.assertIn(f'hosts = ["{NEWS}", "{OFF_SOURCE}"]', with_hosts(scaffold("docs", NEWS, "directories"), [OFF_SOURCE]))
        multiline = edited(f'hosts = ["{NEWS}"]', f'hosts = [\n  "{NEWS}",  # main\n]')
        self.assertEqual(parse(with_hosts(multiline, [OFF_SOURCE]), "news").hosts, (NEWS, OFF_SOURCE))

    def test_refuses_what_it_cannot_edit_safely(self):
        for text, why in (
            (edited(f'hosts = ["{NEWS}"]', f'hosts = [\n  "{NEWS}",  # [old]\n]'), "by hand"),
            (edited(f'hosts = ["{NEWS}"]', f'hosts = ["{NEWS}"]\n[x]\nhosts = []'), "single array"),
            (edited(f'hosts = ["{NEWS}"]', 'hosts = "nope"'), "hosts must list"),
            ("hosts = [", "not valid TOML"),
        ):
            with self.assertRaises(ConfigError) as caught:
                with_hosts(text, [OFF_SOURCE])
            self.assertIn(why, str(caught.exception))
        with self.assertRaises(ConfigError):
            with_hosts(NEWS_CONFIG, ["example.onion"])


def auth_edited(old: str, new: str) -> str:
    assert old in TESTONION_CONFIG, old
    return TESTONION_CONFIG.replace(old, new)


class FormSessionConfigTest(unittest.TestCase):
    """Section 15's schema: bound to AUTH_ALLOWLIST, and never a credential in the config."""

    def refused(self, text: str, source_id: str = "testonion") -> str:
        with self.assertRaises(ConfigError) as caught:
            parse(text, source_id)
        return str(caught.exception)

    def test_the_self_hosted_onion_parses(self):
        auth = testonion_config().auth
        self.assertEqual((auth.login_path, auth.username_field, auth.password_field, auth.success_selector,
                          auth.credential_ref), ("/login", "username", "password", "#signed-in", "testonion"))
        self.assertIsNone(news_config().auth)

    def test_any_source_off_the_allowlist_is_refused(self):
        text = TESTONION_CONFIG.replace('"testonion"\nhosts', '"news"\nhosts')
        self.assertIn("AUTH_ALLOWLIST", self.refused(text, "news"))
        self.assertIn("AUTH_ALLOWLIST", self.refused(edited('type = "none"', 'type = "form-session"'), "news"))

    def test_credentials_inline_are_refused_whatever_the_type(self):
        for extra in ('password = "hunter22"', 'username = "tester"', 'session_cookie = "sid=1"',
                      'api_token = "x"', '[auth.credentials]\nuser = "x"'):
            self.assertIn("look like credentials", self.refused(TESTONION_CONFIG + extra + "\n"), extra)
            self.assertIn("look like credentials",
                          self.refused(edited('type = "none"', 'type = "none"\n' + extra), "news"), extra)

    def test_a_credential_shaped_value_is_refused(self):
        for key, value in (("credential_ref", "tester:Hunter2-pass"), ("success_selector", "aB3dE5fG7hJ9kL1mN3pQ5rS7"),
                           ("login_path", "/login?u=tester@example.org:Hunter2")):
            line = next(line for line in TESTONION_CONFIG.splitlines() if line.startswith(f"{key} ="))
            text = auth_edited(line, f'{key} = "{value}"')
            self.assertIn(f"auth.{key} must be a string, and never a credential", self.refused(text), key)

    def test_every_form_session_key_is_required(self):
        for key in ("login_path", "username_field", "password_field", "success_selector", "credential_ref"):
            line = next(line for line in TESTONION_CONFIG.splitlines() if line.startswith(f"{key} ="))
            self.assertIn(f"auth.{key} must be a string", self.refused(auth_edited(line + "\n", "")), key)

    def test_field_names_reference_and_path_are_checked(self):
        for old, new, why in (('password_field = "password"', 'password_field = "username"', "two different"),
                              ('username_field = "username"', 'username_field = "user name"', "form field names"),
                              ('credential_ref = "testonion"', 'credential_ref = "../etc/passwd"', "credential_ref"),
                              ('login_path = "/login"', f'login_path = "http://{TESTONION}/login"', "auth.login_path"),
                              ('success_selector = "#signed-in"', 'success_selector = "//div"', "success_selector")):
            self.assertIn(why, self.refused(auth_edited(old, new)), new)


if __name__ == "__main__":
    unittest.main()
