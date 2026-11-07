#!/bin/bash
# Section 15 leak tests 1 to 4, run as root inside the guest by `make leak-test`.
# Tests 1, 2 and 4 run inside the test 3 capture window, so the capture also proves they sent nothing.
# Everything that runs crawler code or the crawler's venv runs as crawler, never as root.
set -uo pipefail

WINDOW=${LEAK_WINDOW_SECONDS:-300}
source "$(dirname "$0")/capture.sh"

# Section 15 test 1. The kill switch ends in DROP, so a blocked attempt gets no reply and curl gives up
# at -m 5: exit 28 is the expected result and only exit 0 fails here. The pass rests on evidence of the
# drop, judged once the capture closes: the DROP counter rose, the kernel logged the attempt, and no
# packet reached the target.
curl_attempt() {
    local url=$1 start code ms
    start=$(date +%s%N)
    as_crawler curl -sS -m 5 -o /dev/null "$url" 2>"$WORK/curl.err"
    code=$?
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    echo "      curl $url -> exit $code in ${ms}ms: $(head -c 120 "$WORK/curl.err")"
    [ "$code" != 0 ]
}

# Section 15 test 2: no address may come back, from the system resolver or a direct query.
dns_blocked() {
    local stub direct python
    stub=$(as_crawler dig +short +tries=1 +time=3 example.com A 2>&1)
    direct=$(as_crawler dig +short +tries=1 +time=3 @1.1.1.1 example.com A 2>&1)
    python=$(as_crawler python3 -c "import socket; socket.gethostbyname('example.com')" 2>&1 | tail -1)
    echo "      dig example.com -> ${stub:-<no answer>}"
    echo "      dig @1.1.1.1 example.com -> ${direct:-<no answer>}"
    echo "      gethostbyname -> ${python:-<returned an address>}"
    ! grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$stub$direct" && grep -q gaierror <<<"$python"
}

capture_start "${WINDOW}s"

echo "test 1: clearnet block (as crawler)"
T1=pass
T1_START=$(date +%s)
T1_DROPS_BEFORE=$(drop_count)
curl_attempt http://example.com || T1=fail
curl_attempt https://1.1.1.1 || T1=fail
sleep 1
T1_DROPS_AFTER=$(drop_count)
journalctl -k --since "@$T1_START" -o cat --no-pager | grep "onioncrawl-lt3: " > "$WORK/t1flows.txt"
echo "      judged after the capture closes"

echo "test 2: DNS block (as crawler)"
if dns_blocked; then report "test 2 DNS block" pass; else report "test 2 DNS block" fail; fi

echo "test 4: redirect trap, mocked 302 to https://example.com (as crawler, inside the capture)"
if as_crawler bash -c "cd $APP && $PY -m unittest tests.test_fetcher.RedirectTrapTest" >"$WORK/t4.txt" 2>&1; then
    report "test 4 redirect trap ($(grep -o 'Ran [0-9]* tests' "$WORK/t4.txt"))" pass
else
    cat "$WORK/t4.txt"
    report "test 4 redirect trap" fail
fi

echo "test 3: traffic during the window comes from the fetcher probe (steps 2 to 4)"
as_crawler bash -c "cd $APP && $PY -m tests.live.probe /home/crawler/settings.toml" 2>&1 | sed 's/^/      /'
REMAINING=$(( WINDOW - ($(date +%s) - STARTED) ))
if [ "$REMAINING" -gt 0 ]; then
    echo "      holding the capture open ${REMAINING}s more"
    sleep "$REMAINING"
fi
capture_stop
echo "test 1: evidence of the drop"
CRAWLER_UID=$(id -u crawler)
RESOLVER_UID=$(id -u systemd-resolve)
echo "      DROP counter across test 1: $T1_DROPS_BEFORE -> $T1_DROPS_AFTER"
[ "$T1_DROPS_AFTER" -gt "$T1_DROPS_BEFORE" ] || T1=fail
# 1.1.1.1 is an address, so curl's own SYN is what the kernel logs and the kill switch drops.
T1_DIRECT=$(grep -cE "DST=1\.1\.1\.1 .*DPT=443 .*UID=$CRAWLER_UID " "$WORK/t1flows.txt")
T1_DIRECT_WIRE=$(captured "host 1.1.1.1")
echo "      1.1.1.1: kernel log lines for uid crawler -> 1.1.1.1:443: $T1_DIRECT, captured packets to 1.1.1.1: $T1_DIRECT_WIRE"
[ "$T1_DIRECT" -gt 0 ] && [ "$T1_DIRECT_WIRE" = 0 ] || T1=fail
# example.com never gets an address. curl asks systemd-resolved over its local socket (nss-resolve),
# so the crawler UID sends no IP packet at all; the attempt that leaves the stack is the resolver's
# upstream query, which the kernel logs under the resolver's UID and the kill switch drops.
T1_LOOKUP=$(grep -cE "DPT=53 .*UID=$RESOLVER_UID " "$WORK/t1flows.txt")
T1_LOOKUP_WIRE=$(captured "port 53")
echo "      example.com: kernel log lines for uid systemd-resolve -> port 53: $T1_LOOKUP, captured DNS packets: $T1_LOOKUP_WIRE"
[ "$T1_LOOKUP" -gt 0 ] && [ "$T1_LOOKUP_WIRE" = 0 ] || T1=fail
report "test 1 clearnet block" "$T1"

capture_judge "test 3 packet capture: only tor talks to the network"
exit $FAILED
