import hashlib
import re
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser

from onioncrawl import onion
from onioncrawl.db import PageInfo

SKIPPED_SCHEMES = ("mailto:", "javascript:", "data:")
LINK_SOURCES = (("a[href]", "href"), ("link[rel=alternate][href]", "href"), ("area[href]", "href"), ("form[action]", "action"))
INVISIBLE = "script, style, noscript, template"
GATE_TEXT = re.compile(r"ddos|checking your browser|queue", re.IGNORECASE)
GATE_MAX_WORDS = 300
TINY_PAGE_WORDS = 50


def parse(url: str, status: int, body: bytes, headers: dict[str, str]) -> PageInfo:
    raw_text = body.decode("utf-8", errors="replace")
    tree = LexborHTMLParser(raw_text)
    links = extract_links(tree, url)
    title, headings = extract_meta(tree)
    text = visible_text(tree)
    gated = detect_gate(tree, status)
    return PageInfo(
        title=title, headings=headings, links=links, text_onions=extract_text_onions(raw_text),
        sha256=content_hash(body), simhash=simhash(text), server=headers.get("server"), gated=gated,
        word_count=len(text.split()), http_code=status, size=len(body),
    )


def extract_links(tree: LexborHTMLParser, base_url: str) -> set[str]:
    links = set()
    for selector, attribute in LINK_SOURCES:
        for node in tree.css(selector):
            target = (node.attributes.get(attribute) or "").strip()
            if not target or target.lower().startswith(SKIPPED_SCHEMES):
                continue
            url = onion.normalize(urljoin(base_url, target))
            if url:
                links.add(url)
    return links


def extract_text_onions(raw_text: str) -> set[str]:
    return onion.find_onions_in_text(raw_text)


def extract_meta(tree: LexborHTMLParser) -> tuple[str, list[str]]:
    title_node = tree.css_first("title")
    title = " ".join(title_node.text().split())[:200] if title_node else ""
    headings = [" ".join(node.text().split())[:120] for node in tree.css("h1, h2")]
    return title, [heading for heading in headings if heading][:10]


def detect_gate(tree: LexborHTMLParser, status: int) -> bool:
    body_text = tree.body.text(separator=" ") if tree.body else ""
    words = len(body_text.split())
    if status in (403, 429) and words < TINY_PAGE_WORDS:
        return True
    if words < GATE_MAX_WORDS and tree.css_first("form input[type=password]") is not None:
        return True
    for image in tree.css("img"):
        if "captcha" in f"{image.attributes.get('src') or ''} {image.attributes.get('alt') or ''}".lower():
            return True
    title_node = tree.css_first("title")
    if title_node and GATE_TEXT.search(title_node.text()):
        return True
    # On a full page "queue" or "DDoS" is ordinary prose; only an interstitial is short enough to be one.
    return words < GATE_MAX_WORDS and bool(GATE_TEXT.search(body_text))


def content_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def simhash(text: str) -> int:
    words = text.lower().split()
    shingles = [" ".join(words[i:i + 3]) for i in range(max(len(words) - 2, 1))] if words else []
    if not shingles:
        return 0
    # Each shingle votes +1 on the bits set in its 64-bit hash and -1 on the rest; a bit of the result
    # is 1 when it won more than half the votes. Similar texts share most shingles, so most votes, so
    # most bits. Counting with one binary string per hash keeps the 64-way tally in C, not a Python loop.
    rows = [format(int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest()), "064b") for s in shingles]
    half = len(rows) / 2
    result = 0
    for column in zip(*rows):
        result = (result << 1) | (column.count("1") > half)
    return result


def visible_text(tree: LexborHTMLParser) -> str:
    for node in tree.css(INVISIBLE):
        node.decompose()
    return " ".join(tree.body.text(separator=" ").split()) if tree.body else ""
