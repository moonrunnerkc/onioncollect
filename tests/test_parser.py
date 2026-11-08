import random
import unittest

from selectolax.lexbor import LexborHTMLParser

from onioncollect.parser import detect_gate, extract_links, onion_hosts, visible_text
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT

BASE = f"http://{AHMIA}/dir/page"


def tree(html: str) -> LexborHTMLParser:
    return LexborHTMLParser(html)


def prose(words: int, seed: int = 1) -> str:
    rng = random.Random(seed)
    return " ".join(rng.choice(["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]) + str(rng.randint(0, 50)) for _ in range(words))


class LinksTest(unittest.TestCase):
    def test_sources_and_resolution(self):
        html = f"""
            <a href="other">rel</a> <a href="/root?q=1#frag">abs</a>
            <a href="http://{DUCKDUCKGO}/x">onion</a> <a href="https://example.com/">clearnet</a>
            <link rel="alternate" href="http://{TORPROJECT}/feed">
            <map><area href="/area"></map>
            <form action="http://{TORPROJECT}/login"></form>
        """
        self.assertEqual(extract_links(tree(html), BASE), {
            f"http://{AHMIA}/dir/other", f"http://{AHMIA}/root?q=1", f"http://{DUCKDUCKGO}/x",
            f"http://{TORPROJECT}/feed", f"http://{AHMIA}/area",
        })

    def test_form_actions_are_never_links(self):
        html = f'<form action="/search"><input name=q></form><form method=post action="http://{TORPROJECT}/x"></form>'
        self.assertEqual(extract_links(tree(html), BASE), set())

    def test_skipped_schemes(self):
        html = '<a href="mailto:x@y.onion">m</a><a href=" JavaScript:alert(1)">j</a><a href="data:text/html,hi">d</a><a href="">e</a>'
        self.assertEqual(extract_links(tree(html), BASE), set())

    def test_other_link_rels_ignored(self):
        self.assertEqual(extract_links(tree(f'<link rel="stylesheet" href="http://{DUCKDUCKGO}/s.css">'), BASE), set())


class GateTest(unittest.TestCase):
    def gated(self, html: str, status: int = 200) -> bool:
        page = tree(html)
        visible_text(page)
        return detect_gate(page, status)

    def test_login_wall(self):
        self.assertTrue(self.gated('<form><input name=u><input type="password" name=p></form>'))

    def test_login_form_on_a_long_page_is_not_a_gate(self):
        self.assertFalse(self.gated(f'<p>{prose(400)}</p><form><input type="password"></form>'))

    def test_captcha_image(self):
        self.assertTrue(self.gated(f'<p>{prose(500)}</p><img src="/img/CAPTCHA.png">'))
        self.assertTrue(self.gated('<img src="/x.png" alt="Captcha code">'))

    def test_interstitial_title_and_body(self):
        self.assertTrue(self.gated("<title>DDoS protection</title><p>wait</p>"))
        self.assertTrue(self.gated("<p>Checking your browser before accessing</p>"))
        self.assertTrue(self.gated("<p>You are in the queue, position 4</p>"))

    def test_script_heavy_interstitial(self):
        script = "<script>" + "var a = 1; " * 2000 + "</script>"
        self.assertTrue(self.gated(f"{script}<p>Checking your browser</p>"))

    def test_queue_in_ordinary_prose_is_not_a_gate(self):
        self.assertFalse(self.gated(f"<p>{prose(400)} the print queue was long {prose(10, 2)}</p>"))

    def test_status_with_tiny_body(self):
        self.assertTrue(self.gated("<p>Forbidden</p>", status=403))
        self.assertTrue(self.gated("", status=429))
        self.assertFalse(self.gated(f"<p>{prose(100)}</p>", status=403))

    def test_ordinary_page(self):
        self.assertFalse(self.gated(f"<title>Forum</title><h1>Welcome</h1><p>{prose(50)}</p>"))


class VisibleTextTest(unittest.TestCase):
    def test_strips_invisible_nodes_and_keeps_one_line_per_text_node(self):
        html = "<style>p{}</style><script>x()</script><p>a\n\n b</p><noscript>n</noscript><template>t</template>  <div>c   d</div>"
        self.assertEqual(visible_text(tree(html)), "a\nb\nc d")

    def test_plain_text_lines_survive(self):
        self.assertEqual(visible_text(tree("bob@acme.com:pw\n\n  root:toor  \n")), "bob@acme.com:pw\nroot:toor")


class OnionHostsTest(unittest.TestCase):
    def test_hosts_from_links_and_text(self):
        raw = f"<a href='/x'>x</a><a href='http://{DUCKDUCKGO}/y'>y</a><!-- {TORPROJECT} --><p>https://example.com/</p>"
        self.assertEqual(onion_hosts(tree(raw), BASE, raw), {AHMIA, DUCKDUCKGO, TORPROJECT})

    def test_text_hosts_are_validated(self):
        mangled = "a" * 56 + ".onion"
        self.assertEqual(onion_hosts(tree(mangled), BASE, mangled), set())


if __name__ == "__main__":
    unittest.main()
