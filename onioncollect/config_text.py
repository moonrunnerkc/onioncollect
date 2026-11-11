import re
import tomllib

from onioncollect.source_config import ConfigError, parse_hosts

HOSTS_ARRAY = re.compile(r"^hosts\s*=\s*\[[^\]]*\]", re.MULTILINE)


def with_hosts(text: str, added: list[str]) -> str:
    """The config text with hosts appended to its hosts array and nothing else changed. Works on an unfilled
    scaffold too, since mirrors can be approved before a source's selectors are."""
    try:
        before = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"not valid TOML: {exc}") from None
    hosts = parse_hosts(before.get("hosts"))
    wanted = list(dict.fromkeys(hosts + tuple(parse_hosts(added))))
    if len(wanted) == len(hosts):
        return text
    if len(HOSTS_ARRAY.findall(text)) != 1:
        raise ConfigError("hosts is not a single array this can edit; add the hosts by hand")
    edited = HOSTS_ARRAY.sub(lambda _: "hosts = [" + ", ".join(f'"{host}"' for host in wanted) + "]", text)
    # The edit is a text substitution, so it is proven by reading the result back: only hosts may differ.
    try:
        unchanged = tomllib.loads(edited) == before | {"hosts": wanted}
    except tomllib.TOMLDecodeError:
        unchanged = False
    if not unchanged:
        raise ConfigError("hosts could not be edited without touching anything else; add the hosts by hand")
    return edited


def scaffold(source_id: str, host: str, category: str) -> str:
    # Written at approval. It fails validation until the analyst fills in the selectors.
    return f'''id = "{source_id}"
hosts = ["{host}"]
category = "{category}"
cadence = "6h"
seeds = ["/"]

[listing]
item = ""

[listing.fields]
title = ""
url = "@href"

[expect]
min_items_per_page = 1
required_fields = ["title", "url"]

[auth]
type = "none"
'''
