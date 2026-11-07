#!/bin/bash
# Build steps 8 and 9 under the leak test 3 capture: `onioncrawl run` as crawler for CRAWL_SECONDS
# (default 600) with tcpdump running the whole time, then SIGINT, judged with the test 3 criteria and a
# crawl log audit. CRAWL_SCOPE=one (step 8) runs one worker on one Tor instance; CRAWL_SCOPE=full
# (step 9) runs every instance at workers_per_instance and checks each instance's SOCKS stream peak.
# Run as root in the guest by `make crawl-capture` or `make crawl-full`.
set -uo pipefail
source "$(dirname "$0")/capture.sh"

RUN_SECONDS=${CRAWL_SECONDS:-600}
SCOPE=${CRAWL_SCOPE:-one}
HOME_DIR=/home/crawler
SEEDS=$HOME_DIR/seeds.txt
[ -f "$SEEDS" ] || { echo "no $SEEDS: one onion URL or host per line"; exit 1; }
if [ "$SCOPE" = one ]; then
    STEP=8
    SETTINGS=$HOME_DIR/settings-one-instance.toml
    { cat "$HOME_DIR/settings.toml"; echo "tor_instances = [[10051, 11051]]"; } |
        install -m 600 -o crawler -g crawler /dev/stdin "$SETTINGS"
    RUN_ARGS="--workers 1"
    PER_INSTANCE=1
else
    STEP=9
    SETTINGS=$HOME_DIR/settings.toml
    RUN_ARGS=""
    PER_INSTANCE=$(sed -n 's/^workers_per_instance *= *//p' "$SETTINGS")
    PER_INSTANCE=${PER_INSTANCE:-3}
fi
CLI="cd $APP && exec $PY -m onioncrawl --settings $SETTINGS"

capture_start "the crawl (${RUN_SECONDS}s)"
echo "step $STEP: $(as_crawler bash -c "$CLI seed $SEEDS")"
# SIGINT is the Ctrl-C path: workers finish their current fetch, then the crawler closes cleanly.
as_crawler timeout --preserve-status -s INT -k 120 "$RUN_SECONDS" bash -c "$CLI run $RUN_ARGS" 2>/dev/null
CODE=$?
echo "step $STEP: crawler exited with $CODE after SIGINT"
[ "$CODE" = 0 ] || FAILED=1
capture_stop
capture_judge "step $STEP packet capture: only tor talks to the network"

echo "step $STEP: peak crawler SOCKS connections (Tor streams) per instance, from ss every second"
STREAMS=pass
while read -r port peak; do
    echo "      tor $port: $peak (workers on it: $PER_INSTANCE)"
    [ "$peak" -le "$PER_INSTANCE" ] || STREAMS=fail
done < <(socks_peaks)
report "step $STEP no instance carries more streams than its workers" "$STREAMS"

echo "step $STEP: crawl log audit"
if as_crawler "$PY" "$APP/tests/live/log_audit.py" "$HOME_DIR/data/crawl.log" "$HOME_DIR/data/crawl.db" | sed 's/^/      /'; then
    report "step $STEP log carries hosts, codes, bytes, timings and error names only" pass
else
    report "step $STEP log carries hosts, codes, bytes, timings and error names only" fail
fi
exit $FAILED
