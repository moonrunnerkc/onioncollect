"""Full-text search over records, one query for the CLI and the UI. What the analyst types is quoted down to
literal terms before it reaches FTS5, so operator syntax (OR, NOT, NEAR, a prefix *, a column filter, a stray
quote) is matched as text and never parsed; the result is always a bound parameter, never part of the SQL."""

MAX_QUERY_CHARS = 200
MAX_TERMS = 16
LIMIT = 50

SQL = (
    "SELECT r.id, r.source_id, r.category, r.fields, r.first_seen, r.last_seen, r.follow_path,"
    " (SELECT group_concat(DISTINCT h.source_id) FROM record_hosts h WHERE h.record_id = r.id) AS sources,"
    " (SELECT COUNT(*) FROM record_hosts h WHERE h.record_id = r.id) AS hosts"
    " FROM records_fts f JOIN records r ON r.id = f.rowid WHERE records_fts MATCH :match"
    " AND (:source IS NULL OR r.id IN (SELECT record_id FROM record_hosts WHERE source_id = :source))"
    " AND (:category IS NULL OR r.category = :category)"
    " AND (:since IS NULL OR r.last_seen >= :since) AND (:until IS NULL OR r.first_seen <= :until)"
    " ORDER BY rank LIMIT :limit"
)


def literal_query(text: str) -> str:
    """Each whitespace-separated term as an FTS5 string, every one required. Raises ValueError for a query
    with nothing to match or more than the limits allow."""
    terms = text.split()
    if not terms:
        raise ValueError("search query: nothing to search for")
    if len(text) > MAX_QUERY_CHARS or len(terms) > MAX_TERMS:
        raise ValueError(f"search query: at most {MAX_TERMS} terms and {MAX_QUERY_CHARS} characters")
    if not all(term.isprintable() for term in terms):
        raise ValueError("search query: control characters")
    return " ".join('"' + term.replace('"', '""') + '"' for term in terms)


def parameters(text: str, source: str | None, category: str | None, since: str | None, until: str | None,
               limit: int = LIMIT) -> dict:
    """The bound values for SQL. `since` and `until` are stored-timestamp strings, or None."""
    return {"match": literal_query(text), "source": source, "category": category, "since": since, "until": until,
            "limit": limit}
