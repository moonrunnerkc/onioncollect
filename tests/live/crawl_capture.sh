#!/bin/bash
# Build step 8 under the leak test 3 capture: `onioncrawl run` with one worker on one Tor instance,
# as crawler, for CRAWL_SECONDS (default 600) with tcpdump running the whole time. Judged with the
# same criteria as test 3, then the crawl log is audited. Run as root in the guest by `make crawl-capture`.
set -uo pipefail
source "$(dirname "$0")/capture.sh"

RUN_SECONDS=${CRAWL_SECONDS:-600}
HOME_DIR=/home/crawler
ONE_INSTANCE=$HOME_DIR/settings-one-instance.toml
SEEDS=$HOME_DIR/seeds.txt
[ -f "$SEEDS" ] || { echo "no $SEEDS: one onion URL or host per line"; exit 1; }
{ cat "$HOME_DIR/settings.toml"; echo "tor_instances = [[10051, 11051]]"; } |
    install -m 600 -o crawler -g crawler /dev/stdin "$ONE_INSTANCE"
CLI="cd $APP && exec $PY -m onioncrawl --settings $ONE_INSTANCE"

capture_start "the crawl (${RUN_SECONDS}s)"
echo "step 8: $(as_crawler bash -c "$CLI seed $SEEDS")"
# SIGINT is the Ctrl-C path: workers finish their current fetch, then the crawler closes cleanly.
as_crawler timeout --preserve-status -s INT -k 120 "$RUN_SECONDS" bash -c "$CLI run --workers 1" 2>/dev/null
CODE=$?
echo "step 8: crawler exited with $CODE after SIGINT"
[ "$CODE" = 0 ] || FAILED=1
capture_stop
capture_judge "step 8 packet capture: only tor talks to the network"

echo "step 8: crawl log audit"
if as_crawler "$PY" "$APP/tests/live/log_audit.py" "$HOME_DIR/data/crawl.log" "$HOME_DIR/data/crawl.db" | sed 's/^/      /'; then
    report "step 8 log carries hosts, codes, bytes, timings and error names only" pass
else
    report "step 8 log carries hosts, codes, bytes, timings and error names only" fail
fi
exit $FAILED
