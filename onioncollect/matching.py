"""Fingerprints compared: distances, the mirror threshold and single-linkage clusters. Pure and standard
library only, so the writer can cluster stored fingerprints without the page parser."""
from collections import Counter
from dataclasses import dataclass

# Bits that may differ on each hash, of 64. Manku, Jain and Das Sarma (WWW 2007) used 3 for web-scale
# near-duplicates, but two mirrors are fetched hours apart on their cadences, and on synthetic 20-story
# front pages one story changing between fetches moved the content hash a median 6 bits (p95 11), while
# unrelated text on the same template sat near 32 (minimum 15 in 200 trials). Two unrelated hashes fall
# within 8 bits with odds of 3e-10 a pair. Both hashes have to clear it: structure alone matches every
# site built on one template, and SecureDrop instances share theirs.
MIRROR_MAX_BITS = 8
# Error pages, default server pages and interstitials are this short, and they match across unrelated sites.
MIN_WORDS = 50
Distance = tuple[int, int]


@dataclass(frozen=True)
class Fingerprint:
    content: int
    structure: int
    words: int

    @property
    def comparable(self) -> bool:
        return self.words >= MIN_WORDS


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
