import re
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser

from onioncollect import onion

SKIPPED_SCHEMES = ("mailto:", "javascript:", "data:")
# No form actions: a form is how a site asks for input, and nothing here ever gives it any.
LINK_SOURCES = (("a[href]", "href"), ("link[rel=alternate][href]", "href"), ("area[href]", "href"))
INVISIBLE_TAGS = ("script", "style", "noscript", "template")
INVISIBLE = ", ".join(INVISIBLE_TAGS)
GATE_TEXT = re.compile(r"ddos|checking your browser|queue", re.IGNORECASE)
GATE_MAX_WORDS = 300
TINY_PAGE_WORDS = 50


def onion_hosts(tree: LexborHTMLParser, base_url: str, raw_text: str) -> set[str]:
    """Every v3 host a page names, by link or in its text. Discovery's whole input."""
    return {onion.host_of(url) for url in extract_links(tree, base_url)} | onion.find_onions_in_text(raw_text)


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


def visible_text(tree: LexborHTMLParser) -> str:
    # One line per text node, whitespace collapsed inside each. The redaction gate keeps evidence by the
    # line, so a page that is one long line would hand it everything or nothing.
    for node in tree.css(INVISIBLE):
        node.decompose()
    if not tree.body:
        return ""
    lines = (" ".join(line.split()) for line in tree.body.text(separator="\n").splitlines())
    return "\n".join(line for line in lines if line)
