"""Mirror clusters and matches, from stored seed-page fingerprints only. Nothing here fetches."""
from onioncollect import fingerprint, lifecycle
from onioncollect.fingerprint import Distance, Fingerprint
from onioncollect.records import RecordStore
from onioncollect.sources import RefusedChange, SourceTable


async def prints_by_source(sources: SourceTable, records: RecordStore) -> dict[str, list[Fingerprint]]:
    members = await sources.members()
    grouped = {}
    for host, prints in (await records.seed_fingerprints()).items():
        if host in members:
            grouped.setdefault(members[host], []).extend(prints)
    return grouped


async def refresh(sources: SourceTable, records: RecordStore) -> dict[str, str]:
    """Recomputes clusters. A cluster that gained a source has its records merged, since dedup on write
    only ever looked forward."""
    clusters = fingerprint.clusters(await prints_by_source(sources, records))
    for grown in await sources.set_clusters(clusters):
        await records.merge(tuple(sorted(source for source, cluster in clusters.items() if cluster == grown)))
    return clusters


async def source_matches(source_id: str, sources: SourceTable, records: RecordStore) -> list[tuple[str, Distance]]:
    """Every other source whose seed pages match this one's, nearest first."""
    grouped = await prints_by_source(sources, records)
    return fingerprint.matches(grouped.pop(source_id, []), grouped)


async def host_matches(hosts: list[str], sources: SourceTable,
                       records: RecordStore) -> dict[str, list[tuple[str, Distance]]]:
    """For hosts outside any source: the sources their stored seed pages match. A candidate has stored pages
    only if it was fetched before it became one, so this is usually empty."""
    grouped = await prints_by_source(sources, records)
    stored = await records.seed_fingerprints()
    return {host: found for host in hosts if (found := fingerprint.matches(stored.get(host, []), grouped))}


async def cluster_report(source_id: str, sources: SourceTable, records: RecordStore) -> tuple[str | None, list[dict]]:
    """The source's cluster and every host in it, with last-seen times and each host's distance from the
    source's active host. Clusters are recomputed from what is stored first."""
    clusters = await refresh(sources, records)
    source = await sources.get(source_id)
    if source is None:
        raise RefusedChange(f"no source {source_id}")
    cluster = set(await sources.cluster_of(source_id))
    members = {row["id"]: row for row in await sources.sources() if row["id"] in cluster}
    stored = await records.seed_fingerprints()
    reference = stored.get(source["active_host"], [])
    rows = []
    for row in await sources.hosts(lifecycle.MEMBER):
        owner = members.get(row["source_id"])
        if owner is None:
            continue
        theirs = stored.get(row["host"], [])
        rows.append(row | {
            "source_state": owner["state"], "active": row["host"] == owner["active_host"],
            "fingerprinted": bool(theirs), "distance": fingerprint.closest(reference, theirs),
        })
    rows.sort(key=lambda row: (row["source_id"] != source_id, not row["active"], row["host"]))
    return clusters.get(source_id), rows
