#!/bin/bash
# Section 15 leak tests 1 to 4, run as root inside the guest by `make leak-test`.
# Tests 1, 2 and 4 run inside the test 3 capture window, so the capture also proves they sent nothing.
# Everything that runs crawler code or the crawler's venv runs as crawler, never as root.
set -uo pipefail

APP=/home/crawler/app
PY=/home/crawler/venv/bin/python
WINDOW=${LEAK_WINDOW_SECONDS:-300}
WORK=$(mktemp -d)
FAILED=0
# Non-terminating rule, present only for the capture window: the kernel logs the owning UID of every
# new outbound flow, so attribution never depends on catching a short-lived socket with ss.
LOG_RULE=(OUTPUT ! -o lo -m conntrack --ctstate NEW -j LOG --log-prefix "onioncrawl-lt3: " --log-uid)
cleanup() {
    iptables -D "${LOG_RULE[@]}" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

report() {
    if [ "$2" = pass ]; then echo "PASS  $1"; else echo "FAIL  $1"; FAILED=1; fi
}
as_crawler() { sudo -u crawler -H "$@"; }

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

# Counts packets in the finished capture that match a tcpdump filter.
captured() { tcpdump -r "$WORK/cap.pcap" -nn "$1" 2>/dev/null | wc -l; }

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

drop_count() { iptables -L OUTPUT -v -n -x | awk '$3 == "DROP" {print $1}'; }

DEV=$(ip route show default | awk '{print $5; exit}')
LOCAL_IP=$(ip -4 -o addr show dev "$DEV" | awk '{split($4, a, "/"); print a[1]; exit}')
echo "capture: tcpdump -i $DEV 'not port 22' for ${WINDOW}s, guest address $LOCAL_IP"

tcpdump -i "$DEV" -nn -Z root -w "$WORK/cap.pcap" 'not port 22' 2>"$WORK/tcpdump.err" &
TCPDUMP=$!
( while :; do ss -tnpH state established; sleep 1; done ) > "$WORK/ss.txt" &
SAMPLER=$!
iptables -I "${LOG_RULE[@]:0:1}" 1 "${LOG_RULE[@]:1}"
sleep 2
STARTED=$(date +%s)
DROPS_BEFORE=$(drop_count)

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
DROPS_AFTER=$(drop_count)
iptables -D "${LOG_RULE[@]}"
journalctl -k --since "@$((STARTED - 2))" -o cat --no-pager | grep "onioncrawl-lt3: " > "$WORK/flows.txt"
kill "$SAMPLER" 2>/dev/null
kill -INT "$TCPDUMP" && wait "$TCPDUMP" 2>/dev/null
tcpdump -r "$WORK/cap.pcap" -nn -q -tt 2>/dev/null > "$WORK/cap.txt"
chmod 755 "$WORK" && chmod 644 "$WORK/cap.txt" "$WORK/ss.txt" "$WORK/flows.txt"
echo "      kill switch DROP counter: $DROPS_BEFORE -> $DROPS_AFTER (blocked attempts never reach the wire)"
echo "      ss -tnp | grep -v 127.0.0.1, at the end of the window:"
ss -tnpH | grep -v 127.0.0.1 | awk '{print "        " $1, $4, $5, $6}' | head -12
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

if as_crawler "$PY" "$APP/tests/live/leak_analyze.py" "$WORK/cap.txt" "$WORK/ss.txt" "$WORK/flows.txt" "$LOCAL_IP" /home/crawler/control-password | sed 's/^/      /'; then
    report "test 3 packet capture: only tor talks to the network" pass
else
    report "test 3 packet capture: only tor talks to the network" fail
fi
exit $FAILED
