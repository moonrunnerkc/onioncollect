#!/bin/bash
# make deploy's guest half, as root, from the staging copy: the crawler's working copy, the root-owned copy the
# systemd units run, the units, the collection configs (none ever deleted without PRUNE_CONFIGS=1 and a typed
# yes) and a new deploy stamp. The crawl timer is left stopped: make deploy runs the leak tests next and starts
# it only if they pass, and a crawl refuses a leak test result older than this stamp anyway.
set -euo pipefail
STAGE=$1
APP=/home/crawler/app
OPT=/opt/onioncollect
STATE=/var/lib/onioncollect
TIMERS="onioncollect-crawl.timer onioncollect-retention.timer onioncollect-leak-test.timer"

for need in "id analyst" "test -x $OPT/venv/bin/python"; do
    $need >/dev/null 2>&1 || { echo "deploy: $need failed; run make provision first" >&2; exit 1; }
done

# SIGTERM lets the crawl finish its in-flight fetches before its code changes underneath it.
systemctl stop onioncollect-crawl.timer onioncollect-crawl.service 2>/dev/null || true

rm -rf "$APP" && install -d -m 700 -o crawler -g crawler "$APP"
cp -r "$STAGE/onioncollect" "$STAGE/tests" "$APP/"
find "$APP" -name __pycache__ -prune -exec rm -rf {} +
chown -R crawler:crawler "$APP"

# What the units run: owned by root and read-only to everyone else, so no user a unit runs as can change it.
rm -rf "$OPT/app.new" && install -d -m 755 -o root -g root "$OPT/app.new"
cp -r "$STAGE/onioncollect" "$STAGE/tests" "$STAGE/tools" "$OPT/app.new/"
find "$OPT/app.new" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$OPT/app.new" && chmod -R u=rwX,go=rX "$OPT/app.new"
rm -rf "$OPT/app" && mv "$OPT/app.new" "$OPT/app"

install -m 644 -o root -g root "$STAGE"/deploy/systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable $TIMERS onioncollect-ui.service >/dev/null
systemctl start onioncollect-retention.timer onioncollect-leak-test.timer
systemctl restart onioncollect-ui.service

if [ -d "$STAGE/configs" ]; then
    bash "$STAGE/deploy/sync_configs.sh" "$STAGE/configs" /home/crawler/configs
fi

install -d -m 755 -o root -g root "$STATE"
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')" |
    install -m 644 -o root -g root /dev/stdin "$STATE/deploy-stamp"
echo "deploy: stamp $(cat "$STATE/deploy-stamp"); crawls refuse until a leak test runs after it"
