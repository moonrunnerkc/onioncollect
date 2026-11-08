"""Page fingerprints. matching.py compares them and clusters mirrors.

Two 64-bit simhashes per page. Content: word shingles of the visible text, case folded, with any run of
whitespace one break. Structure: shingles of the element names in document order, each subtree closed by a
marker, with attributes, text, comments and invisible elements dropped. The parser already lowercases tag
names. Nothing else about a page reaches either hash, so whitespace, tag case and attribute order cannot.
"""
import hashlib

from selectolax.lexbor import LexborHTMLParser

from onioncollect.matching import Fingerprint
from onioncollect.parser import INVISIBLE_TAGS

CONTENT_SHINGLE = 3
STRUCTURE_SHINGLE = 4
# Mirrors agree from the first word, so the start of a page decides, and a hostile 2 MB body costs no more
# than a long article.
MAX_TOKENS = 20_000
CLOSE = "/"


def of_page(visible_text: str, tree: LexborHTMLParser) -> Fingerprint:
    words = normalized_words(visible_text)
    return Fingerprint(simhash(shingles(words, CONTENT_SHINGLE)), simhash(shingles(tag_shape(tree), STRUCTURE_SHINGLE)),
                       len(words))


def normalized_words(text: str) -> list[str]:
    return text.casefold().split()[:MAX_TOKENS]


def tag_shape(tree: LexborHTMLParser) -> list[str]:
    root = tree.root
    if root is None:
        return []
    shape, stack = [root.tag], [root.iter()]
    # A stack of child iterators rather than recursion: a hostile page can nest far past Python's limit.
    while stack and len(shape) < MAX_TOKENS:
        node = next(stack[-1], None)
        if node is None:
            stack.pop()
            shape.append(CLOSE)
        elif not node.tag.startswith("-") and node.tag not in INVISIBLE_TAGS:
            shape.append(node.tag)
            stack.append(node.iter())
    return shape


def shingles(tokens: list[str], size: int) -> list[bytes]:
    if len(tokens) <= size:
        return [" ".join(tokens).encode()] if tokens else []
    return [" ".join(tokens[n:n + size]).encode() for n in range(len(tokens) - size + 1)]


def simhash(features: list[bytes]) -> int:
    # Each feature's hash votes on all 64 bits. Tallying how often each byte value lands in each of the 8
    # byte positions, then expanding the tallies once, is 8 steps a feature instead of 64.
    tallies = [[0] * 256 for _ in range(8)]
    for feature in features:
        for position, value in enumerate(hashlib.blake2b(feature, digest_size=8).digest()):
            tallies[position][value] += 1
    result = 0
    for position, tally in enumerate(tallies):
        for bit in range(8):
            ones = sum(count for value, count in enumerate(tally) if value >> bit & 1)
            if 2 * ones > len(features):
                result |= 1 << (position * 8 + bit)
    return result
