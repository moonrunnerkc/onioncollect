"""Page fingerprints and mirror clusters.

Two 64-bit simhashes per page. Content: word shingles of the visible text, case folded, with any run of
whitespace one break. Structure: shingles of the element names in document order, each subtree closed by a
marker, with attributes, text, comments and invisible elements dropped. The parser already lowercases tag
names. Nothing else about a page reaches either hash, so whitespace, tag case and attribute order cannot.
"""
import hashlib
from collections import Counter
from dataclasses import dataclass

from selectolax.lexbor import LexborHTMLParser

from onioncollect.parser import INVISIBLE_TAGS

# Bits that may differ on each hash, of 64. Manku, Jain and Das Sarma (WWW 2007) used 3 for web-scale
# near-duplicates, but two mirrors are fetched hours apart on their cadences, and on synthetic 20-story
# front pages one story changing between fetches moved the content hash a median 6 bits (p95 11), while
# unrelated text on the same template sat near 32 (minimum 15 in 200 trials). Two unrelated hashes fall
# within 8 bits with odds of 3e-10 a pair. Both hashes have to clear it: structure alone matches every
# site built on one template, and SecureDrop instances share theirs.
MIRROR_MAX_BITS = 8
# Error pages, default server pages and interstitials are this short, and they match across unrelated sites.
MIN_WORDS = 50
CONTENT_SHINGLE = 3
STRUCTURE_SHINGLE = 4
# Mirrors agree from the first word, so the start of a page decides, and a hostile 2 MB body costs no more
# than a long article.
MAX_TOKENS = 20_000
CLOSE = "/"

Distance = tuple[int, int]


@dataclass(frozen=True)
class Fingerprint:
    content: int
    structure: int
    words: int

    @property
    def comparable(self) -> bool:
        return self.words >= MIN_WORDS


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


def distance(a: Fingerprint, b: Fingerprint) -> Distance:
    return (a.content ^ b.content).bit_count(), (a.structure ^ b.structure).bit_count()


def is_match(found: Distance) -> bool:
    return max(found) <= MIRROR_MAX_BITS


def closest(ours: list[Fingerprint], theirs: list[Fingerprint]) -> Distance | None:
    """The nearest pair of comparable pages, a matching pair ahead of any that doesn't match."""
    pairs = [distance(a, b) for a in ours if a.comparable for b in theirs if b.comparable]
    return min(pairs, key=lambda found: (not is_match(found), sum(found)), default=None)


def matches(ours: list[Fingerprint], groups: dict[str, list[Fingerprint]]) -> list[tuple[str, Distance]]:
    found = [(key, near) for key, theirs in groups.items() if (near := closest(ours, theirs)) and is_match(near)]
    return sorted(found, key=lambda item: (sum(item[1]), item[0]))


def clusters(groups: dict[str, list[Fingerprint]]) -> dict[str, str]:
    """Single linkage: two groups join when any pair of their pages match. A cluster is named by its first
    key in sort order; a group that matches no other is in no cluster and is left out."""
    parent = {key: key for key in groups}

    def root(key: str) -> str:
        while parent[key] != key:
            key = parent[key]
        return key

    keys = sorted(groups)
    for n, a in enumerate(keys):
        for b in keys[n + 1:]:
            near = closest(groups[a], groups[b])
            if near and is_match(near):
                first, second = sorted((root(a), root(b)))
                parent[second] = first
    named = {key: root(key) for key in keys}
    sizes = Counter(named.values())
    return {key: name for key, name in named.items() if sizes[name] > 1}


def describe(near: Distance) -> str:
    return f"content {near[0]}, structure {near[1]} bits apart"


def to_hex(value: int) -> str:
    return f"{value:016x}"
