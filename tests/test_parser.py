import hashlib
import random
import unittest

from selectolax.lexbor import LexborHTMLParser

from onioncrawl.parser import (
    content_hash, detect_gate, extract_links, extract_meta, extract_text_onions, parse, simhash, visible_text,
)
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT

BASE = f"http://{AHMIA}/dir/page"


def tree(html: str) -> LexborHTMLParser:
    return LexborHTMLParser(html)


def naive_simhash(text: str) -> int:
    words = text.lower().split()
    shingles = [" ".join(words[i:i + 3]) for i in range(max(len(words) - 2, 1))]
    votes = [0] * 64
    for shingle in shingles:
        value = int.from_bytes(hashlib.blake2b(shingle.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            votes[bit] += 1 if value >> bit & 1 else -1
    return sum(1 << bit for bit in range(64) if votes[bit] > 0)


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
            f"http://{TORPROJECT}/feed", f"http://{AHMIA}/area", f"http://{TORPROJECT}/login",
        })

    def test_skipped_schemes(self):
        html = '<a href="mailto:x@y.onion">m</a><a href=" JavaScript:alert(1)">j</a><a href="data:text/html,hi">d</a><a href="">e</a>'
        self.assertEqual(extract_links(tree(html), BASE), set())

    def test_other_link_rels_ignored(self):
        self.assertEqual(extract_links(tree(f'<link rel="stylesheet" href="http://{DUCKDUCKGO}/s.css">'), BASE), set())


class TextOnionsTest(unittest.TestCase):
    def test_finds_hosts_in_comments_scripts_and_broken_markup(self):
        raw = f"<!-- mirror {DUCKDUCKGO} --><script>var u='{TORPROJECT.upper()}'</script><p>{AHMIA[:-6]}</p>"
        self.assertEqual(extract_text_onions(raw), {DUCKDUCKGO, TORPROJECT})


class MetaTest(unittest.TestCase):
    def test_title_and_headings_trimmed(self):
        heads = "".join(f"<h{1 + n % 2}>  head {n} {'x' * 200}</h{1 + n % 2}>" for n in range(12))
        title, headings = extract_meta(tree(f"<title>\n  {'t' * 300} </title><h1>  </h1>{heads}"))
        self.assertEqual(title, "t" * 200)
        self.assertEqual(len(headings), 10)
        self.assertTrue(all(len(h) == 120 for h in headings))
        self.assertTrue(headings[0].startswith("head 0 "))

    def test_missing_title(self):
        self.assertEqual(extract_meta(tree("<p>hi</p>")), ("", []))


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


class SimhashTest(unittest.TestCase):
    def test_matches_the_bit_by_bit_definition(self):
        for text in (prose(500), prose(3), "one two", "single", "a b c d"):
            self.assertEqual(simhash(text), naive_simhash(text), text[:20])

    def test_near_duplicate_is_within_three_bits(self):
        text = prose(600)
        edited = text.replace(text.split()[300], "changed", 1)
        self.assertLessEqual(bin(simhash(text) ^ simhash(edited)).count("1"), 3)

    def test_different_texts_are_far_apart(self):
        self.assertGreater(bin(simhash(prose(600, 1)) ^ simhash(prose(600, 2))).count("1"), 10)

    def test_case_and_whitespace_do_not_matter(self):
        self.assertEqual(simhash("Hello   World\nAgain friend"), simhash("hello world again friend"))

    def test_empty(self):
        self.assertEqual(simhash(""), 0)


class VisibleTextTest(unittest.TestCase):
    def test_strips_invisible_nodes_and_collapses_space(self):
        html = "<style>p{}</style><script>x()</script><p>a\n\n b</p><noscript>n</noscript><template>t</template>  <div>c</div>"
        self.assertEqual(visible_text(tree(html)), "a b c")


class ParseTest(unittest.TestCase):
    def test_parse_fills_every_field(self):
        body = f"<title>T</title><h1>H</h1><p>one two three four</p><a href='/x'>x</a><!-- {DUCKDUCKGO} -->".encode()
        info = parse(BASE, 200, body, {"server": "nginx", "content-type": "text/html"})
        self.assertEqual((info.title, info.headings), ("T", ["H"]))
        self.assertEqual(info.links, {f"http://{AHMIA}/x"})
        self.assertEqual(info.text_onions, {DUCKDUCKGO})
        self.assertEqual((info.sha256, info.server, info.gated), (content_hash(body), "nginx", False))
        self.assertEqual((info.word_count, info.http_code, info.size), (6, 200, len(body)))
        self.assertEqual(info.simhash, simhash("T H one two three four x".replace("T ", "", 1)))

    def test_bad_bytes_and_plain_text(self):
        info = parse(BASE, 200, b"\xff\xfe plain text \x80 with " + DUCKDUCKGO.encode(), {})
        self.assertEqual(info.text_onions, {DUCKDUCKGO})
        self.assertIsNone(info.server)

    def test_content_hash(self):
        self.assertEqual(content_hash(b"abc"), hashlib.sha256(b"abc").hexdigest())


if __name__ == "__main__":
    unittest.main()
