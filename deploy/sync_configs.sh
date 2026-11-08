#!/bin/bash
# sync_configs.sh STAGED GUEST: install every staged collection config into the guest's configs dir. It never
# deletes a guest config by default. With PRUNE_CONFIGS=1 it lists the guest configs this checkout lacks and
# deletes them only after a typed "yes" on stdin. DRY_RUN=1 prints what it would do and changes nothing.
# OWNER and GROUP (default crawler) own what it installs; the tests run it on a fake tree as themselves.
set -euo pipefail
staged=$1
guest=$2
owner=${OWNER:-crawler}
group=${GROUP:-crawler}

act() {
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "would run: $*"; else "$@"; fi
}

act install -d -m 700 -o "$owner" -g "$group" "$guest"
for file in "$staged"/*.toml; do
    [ -e "$file" ] || continue
    act install -m 600 -o "$owner" -g "$group" "$file" "$guest/"
    echo "config $(basename "$file") installed"
done

extra=()
for file in "$guest"/*.toml; do
    [ -e "$file" ] || continue
    [ -e "$staged/$(basename "$file")" ] || extra+=("$file")
done
[ "${#extra[@]}" = 0 ] && exit 0
echo "guest configs not in this checkout:"
printf '  %s\n' "${extra[@]}"
if [ "${PRUNE_CONFIGS:-0}" != 1 ]; then
    echo "kept; PRUNE_CONFIGS=1 make deploy deletes them after a typed yes"
    exit 0
fi
read -r -p "delete these ${#extra[@]} configs? type yes: " answer || answer=""
if [ "$answer" != yes ]; then
    echo "kept, nothing deleted"
    exit 0
fi
for file in "${extra[@]}"; do
    act rm -- "$file"
    echo "deleted $(basename "$file")"
done
