"""The search UI's pages. Pure: rows in, HTML out. Every value that came from a store goes through `text`, so a
record, a snapshot, a host or a health detail always reaches the browser as escaped text. The only links are the
UI's own routes, built from ids already validated; nothing here ever links to an onion or anywhere else."""
from html import escape
from urllib.parse import quote

TITLE_CHARS = 160
STYLE = (
    "body{font:15px/1.45 system-ui,sans-serif;margin:0;color:#1d2125;background:#fafaf8}"
    "header{padding:10px 16px;background:#24313a}header a{color:#fff;text-decoration:none;font-weight:600}"
    "main{max-width:1100px;margin:0 auto;padding:12px 16px}h1{font-size:20px}h2{font-size:16px;margin-top:24px}"
    "form{display:flex;flex-wrap:wrap;gap:8px;align-items:end}label{display:flex;flex-direction:column;font-size:12px}"
    "input,select,button{font:inherit;padding:4px 6px}table{border-collapse:collapse;width:100%;margin-top:12px}"
    "th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #dcdcd6;vertical-align:top}"
    "th{font-size:12px;color:#5a646c}td.n{text-align:right;font-variant-numeric:tabular-nums}"
    "dt{font-weight:600;margin-top:8px}dd{margin:0 0 0 16px;white-space:pre-wrap;overflow-wrap:anywhere}"
    "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;border:1px solid #dcdcd6;padding:8px}"
    ".bar{background:#4a7d9d;height:8px}.muted{color:#5a646c}.warn{color:#9a3412}"
)


def text(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def when(stamp: str | None) -> str:
    return text((stamp or "never")[:16])


def link(route: str, key, label) -> str:
    return f"<a href='/{route}/{quote(str(key), safe='')}'>{text(label)}</a>"


def page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>{text(title)}</title>"
            f"<style>{STYLE}</style></head><body><header><a href='/'>onioncollect search</a></header>"
            f"<main><h1>{text(title)}</h1>{body}</main></body></html>")


def table(headings: tuple[str, ...], rows: list[str]) -> str:
    if not rows:
        return "<p class='muted'>None.</p>"
    head = "".join(f"<th>{text(name)}</th>" for name in headings)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def search_form(values: dict[str, str], categories: tuple[str, ...]) -> str:
    def field(name: str, label: str, kind: str = "text") -> str:
        return f"<label>{text(label)}<input type='{kind}' name='{name}' value='{text(values.get(name, ''))}'></label>"

    options = "".join(f"<option value='{text(c)}'{' selected' if values.get('category') == c else ''}>{text(c)}"
                      f"</option>" for c in ("", *categories))
    return (f"<form method='get' action='/'>{field('q', 'words')}{field('source', 'source id')}"
            f"<label>category<select name='category'>{options}</select></label>"
            f"{field('since', 'last seen from', 'date')}{field('until', 'first seen to', 'date')}"
            f"<button>Search</button></form>")


def title_of(fields: dict[str, str]) -> str:
    return next(iter(fields.values()), "")[:TITLE_CHARS]


def results(rows: list[dict], snapshots: dict[int, str]) -> str:
    def row(record: dict) -> str:
        sources = ", ".join(link("source", source_id, source_id) for source_id in record["sources"])
        snapshot = link("snapshot", snapshots[record["id"]], "snapshot") if record["id"] in snapshots else ""
        return (f"<tr><td>{link('record', record['id'], record['id'])}</td><td>{text(title_of(record['fields']))}</td>"
                f"<td>{sources}</td><td>{text(record['category'])}</td><td>{when(record['last_seen'])}</td>"
                f"<td>{snapshot}</td></tr>")

    return f"<p>{len(rows)} records</p>" + table(("id", "title", "sources", "category", "last seen", ""),
                                                  [row(record) for record in rows])


def record_page(record: dict, fields: dict[str, str], hosts: list[dict], snapshots: list[dict]) -> str:
    listed = "".join(f"<dt>{text(name)}</dt><dd>{text(value)}</dd>" for name, value in fields.items())
    seen = [f"<tr><td>{link('source', h['source_id'], h['source_id'])}</td><td>{text(h['host'])}</td>"
            f"<td>{when(h['first_seen'])}</td><td>{when(h['last_seen'])}</td></tr>" for h in hosts]
    return (f"<p>{text(record['category'])}, first seen {when(record['first_seen'])}, last seen"
            f" {when(record['last_seen'])}, kept until {when(record['expires_at'])}."
            f" Redactions: {text(record['redactions'])}</p><dl>{listed}</dl>"
            f"<h2>Seen on</h2>{table(('source', 'host', 'first', 'last'), seen)}"
            f"<h2>Snapshots of its page</h2>{snapshot_rows(snapshots)}")


def snapshot_rows(snapshots: list[dict]) -> str:
    return table(("taken", "kind", "path", ""), [
        f"<tr><td>{when(s['taken_at'])}</td><td>{text(s['kind'])}{' (baseline)' if s['baseline'] else ''}</td>"
        f"<td>{text(s['path'])}</td><td>{link('snapshot', s['digest'], 'view')}</td></tr>" for s in snapshots])


def source_page(source: dict, config_path: str, runs: list[dict], items: list[dict], snapshots: list[dict]) -> str:
    facts = (("state", source["state"] + (f" ({source['reason']})" if source["reason"] else "")),
             ("category", source["category"]), ("active host", source["active_host"]), ("config", config_path),
             ("live since", (source["live_at"] or "never")[:16]), ("next run", (source["next_run"] or "due")[:16]),
             ("failed runs in a row", source["failed_runs"]), ("mirror cluster", source["cluster_id"] or "none"))
    history = []
    for run in runs:
        hit = run["fields_resolved"] / run["fields_declared"] if run["fields_declared"] else 0.0
        history.append(
            f"<tr><td>{text(run['id'])}</td><td>{when(run['started_at'])}</td><td class='n'>{text(run['pages'])}</td>"
            f"<td class='n'>{text(run['failures'])}</td><td class='n'>{text(run['items'] - run['incomplete'])}</td>"
            f"<td class='n'>{hit:.2f}</td><td><div class='bar' style='width:{hit * 100:.0f}%'></div></td>"
            f"<td class='n'>{text(run['records_new'])}</td><td class='n'>{text(run['redactions'])}</td>"
            f"<td>{'' if run['finished_at'] else 'open'}</td></tr>")
    open_items = [f"<tr><td>#{text(i['id'])}</td><td class='warn'>{text(i['kind'])}</td><td class='n'>"
                  f"{text(i['priority'])}</td><td>{when(i['opened_at'])}</td><td>{text(i['detail'])}</td></tr>"
                  for i in items]
    return (f"<dl>{''.join(f'<dt>{text(k)}</dt><dd>{text(v)}</dd>' for k, v in facts)}</dl>"
            f"<h2>Hit rate, newest run first</h2>"
            f"{table(('run', 'started', 'pages', 'failed', 'complete', 'hit', '', 'new', 'redacted', ''), history)}"
            f"<h2>Open health items</h2>{table(('item', 'kind', 'priority', 'opened', 'detail'), open_items)}"
            f"<h2>Latest snapshots</h2>{snapshot_rows(snapshots)}")


def snapshot_page(meta: list[dict], body: str) -> str:
    """The redacted page as text: escaped inside <pre>, never as this page's own markup."""
    taken = "".join(f"<li>{link('source', m['source_id'], m['source_id'])} {text(m['kind'])} {text(m['path'])}"
                    f" at {when(m['taken_at'])}{' (baseline)' if m['baseline'] else ''}</li>" for m in meta)
    return f"<ul>{taken}</ul><p class='muted'>{len(body)} characters, shown as text.</p><pre>{text(body)}</pre>"


def message(detail: str) -> str:
    return f"<p>{text(detail)}</p>"
