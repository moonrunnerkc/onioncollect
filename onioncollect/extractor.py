import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser, LexborNode

from onioncollect.source_config import Selector, SourceConfig

MAX_FIELD_CHARS = 100_000
# A hostile page can match an item selector hundreds of thousands of times; a real listing never does.
MAX_ITEMS = 1_000
# Lexbor took 30 s on 200k nested divs in one 1 MB body. Real listing pages carry a few thousand tags, so a
# body over this is refused before it is parsed. Counting '<' over-counts (comments, '<' in scripts), which
# only ever refuses early.
MAX_TAGS = 50_000


@dataclass
class Extraction:
    records: list[dict[str, str]] = field(default_factory=list)
    items: int = 0
    incomplete: int = 0
    fields_resolved: int = 0
    fields_declared: int = 0
    next_page: str | None = None
    follows: list[str] = field(default_factory=list)
    # Per declared field, how many of `field_items` resolved it: a listing's items, or the one detail page.
    field_hits: Counter = field(default_factory=Counter)
    field_items: int = 0

    @property
    def hit_rate(self) -> float:
        return self.fields_resolved / self.fields_declared if self.fields_declared else 0.0


def too_many_tags(text: str) -> bool:
    return text.count("<") > MAX_TAGS


def listing(tree: LexborHTMLParser, page_url: str, config: SourceConfig) -> Extraction:
    out = Extraction(field_hits=Counter(dict.fromkeys(config.fields, 0)))
    for item in tree.css(config.item)[:MAX_ITEMS]:
        out.items += 1
        out.field_items += 1
        values = resolve(item, config.fields, page_url)
        out.fields_declared += len(config.fields)
        out.fields_resolved += len(values)
        out.field_hits.update(values.keys())
        # An incomplete record is counted for the hit rate and never stored.
        if any(name not in values for name in config.required_fields):
            out.incomplete += 1
            continue
        out.records.append(values)
        if config.follow and config.follow in values:
            out.follows.append(values[config.follow])
    if config.next_page is not None:
        node = tree.css_first(config.next_page.css)
        target = value_of(node, config.next_page, page_url) if node is not None else None
        out.next_page = target or None
    return out


def detail(tree: LexborHTMLParser, page_url: str, config: SourceConfig) -> Extraction:
    root = tree.root
    values = resolve(root, config.detail_fields, page_url) if root is not None else {}
    hits = Counter(dict.fromkeys(config.detail_fields, 0))
    hits.update(values.keys())
    return Extraction(
        records=[values] if values else [], items=1 if values else 0,
        fields_resolved=len(values), fields_declared=len(config.detail_fields), field_hits=hits, field_items=1,
    )


def resolve(scope: LexborNode, fields: dict[str, Selector], page_url: str) -> dict[str, str]:
    values = {}
    for name, selector in fields.items():
        node = scope.css_first(selector.css)
        value = value_of(node, selector, page_url) if node is not None else None
        if value:
            values[name] = value[:MAX_FIELD_CHARS]
    return values


def value_of(node: LexborNode, selector: Selector, page_url: str) -> str | None:
    if selector.attribute is None:
        return " ".join(node.text(separator=" ").split())
    raw = (node.attributes.get(selector.attribute) or "").strip()
    if not raw:
        return None
    # Links come back absolute, so a stored record and a follow both name the page unambiguously.
    return urljoin(page_url, raw) if selector.is_link else raw


def content_hash(values: dict[str, str], config: SourceConfig) -> str:
    # Links are reduced to their path, so one record read from two mirrors of a source is one record.
    links = {name for name, selector in config.fields.items() if selector.is_link}
    keyed = {name: (config.path_for(value) or value) if name in links else value for name, value in values.items()}
    return hashlib.sha256(json.dumps(keyed, sort_keys=True).encode()).hexdigest()
