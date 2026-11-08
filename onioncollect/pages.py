"""The whole life of a body. Every fetched page is read here and nowhere else: `inspect` for a page of a
run, `signed_in` for the page a login lands on. What comes back out is redacted, counted or a yes or no."""
import re
from dataclasses import dataclass, field

from selectolax.lexbor import LexborHTMLParser

from onioncollect import extractor, fingerprint, parser, redact, safety
from onioncollect.db import LISTING
from onioncollect.fetcher import FetchResult
from onioncollect.matching import Fingerprint
from onioncollect.redact import Redacted
from onioncollect.source_config import SourceConfig


@dataclass
class Record:
    content_hash: str
    follow_path: str | None
    fields: dict[str, str]
    summary: Redacted


@dataclass
class Inspection:
    discovered: set[str] = field(default_factory=set)
    excluded: str | None = None
    refused: bool = False
    gated: bool = False
    extraction: extractor.Extraction = field(default_factory=extractor.Extraction)
    records: list[Record] = field(default_factory=list)
    next_page: str | None = None
    follows: list[str] = field(default_factory=list)
    snapshot: str | None = None
    fingerprint: Fingerprint | None = None
    events: int = 0


def inspect(result: FetchResult, kind: str, config: SourceConfig, patterns: tuple[re.Pattern, ...],
            salt: bytes) -> Inspection:
    # The whole life of a body: checked, mined for hosts, extracted and redacted here, then dropped with
    # this frame. Only redacted records, a redacted snapshot and host names come back out.
    text = result.body.decode("utf-8", errors="replace")
    category = safety.body_triggers_exclusion(text, patterns)
    if category:
        return Inspection(excluded=category)
    if extractor.too_many_tags(text):
        return Inspection(refused=True)
    tree = LexborHTMLParser(text)
    out = Inspection(discovered=parser.onion_hosts(tree, result.url, text) - set(config.hosts))
    if parser.detect_gate(tree, result.status):
        out.gated = True
        return out
    out.extraction = (extractor.listing if kind == LISTING else extractor.detail)(tree, result.url, config)
    for values in out.extraction.records:
        fields, summary = redact.redact_fields(values, salt)
        follow = values.get(config.follow) if kind == LISTING and config.follow else None
        out.records.append(Record(extractor.content_hash(fields, config), follow and config.path_for(follow), fields, summary))
    out.follows = [path for path in map(config.path_for, out.extraction.follows) if path]
    out.next_page = out.extraction.next_page and config.path_for(out.extraction.next_page)
    # Counted on what a reader sees and what was extracted; markup is redacted whole but never counted,
    # since asset hashes in attributes would raise an event on every page. The fingerprint is taken from
    # the same redacted text, so nothing read from the raw body leaves here.
    visible = redact.redact(parser.visible_text(tree), salt)
    out.fingerprint = fingerprint.of_page(visible.text, tree)
    out.events = max(visible.events, sum(record.summary.events for record in out.records))
    out.snapshot = redact.redact(text, salt).text
    return out


def signed_in(result: FetchResult, success_selector: str, patterns: tuple[re.Pattern, ...]) -> tuple[str | None, bool]:
    """Section 15's login check: the safety category the page tripped, if any, and whether the success selector
    matched. Nothing of the page is extracted, fingerprinted or kept."""
    text = result.body.decode("utf-8", errors="replace")
    category = safety.body_triggers_exclusion(text, patterns)
    if category or extractor.too_many_tags(text):
        return category, False
    return None, LexborHTMLParser(text).css_first(success_selector) is not None
