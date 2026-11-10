#!/bin/bash
# Section 15 leak tests 1 to 4, run as root inside the guest by `make leak-test`.
# Tests 1, 2 and 4 run inside the test 3 capture window, so the capture also proves they sent nothing.
# Everything that runs crawler code or the crawler's venv runs as crawler, never as root.
set -uo pipefail

WINDOW=${LEAK_WINDOW_SECONDS:-300}
# The probe's limit: Tor's 120 s ready wait, two NEWNYMs and six fetches fit well inside it, and the unit's
# 20 min TimeoutStartSec still covers the whole run when it is used up.
PROBE_SECONDS=${LEAK_PROBE_SECONDS:-480}
# Golive's check 3 reads this. Root writes it, mode 644, so the crawler can read it and never forge it.
RESULT_FILE=/var/lib/onioncollect/leak-test.json
# Written by make deploy. The result records the one it ran under; golive and the crawl refuse a result that
# names any other, so code deployed after a leak test never runs until the tests run again.
STAMP_FILE=/var/lib/onioncollect/deploy-stamp
source "$(dirname "$0")/capture.sh"

# Each test's outcome as a JSON object, in the order they are judged; a test never judged is missing, and
# golive refuses a result that lacks any of the four.
TESTS=""
# judged NAME COMMAND...: runs one test's reporting command and keeps its outcome under NAME.
judged() {
    local before=$FAILED passed=true
    FAILED=0
    "${@:2}"
    [ "$FAILED" = 0 ] || passed=false
    TESTS+="${TESTS:+, }{\"name\": \"$1\", \"passed\": $passed}"
    FAILED=$(( before | FAILED ))
}

# Who ran it, as a role and never a login name: the result is evidence that goes into the write-up. systemd gives
# every unit it starts an invocation id; anything else is a person running make deploy or make leak-test.
RUN_BY=operator
[ -z "${INVOCATION_ID:-}" ] || RUN_BY=unit
write_result() {
    printf '{"run_at": "%s", "run_by": "%s", "deploy_stamp": "%s", "tests": [%s]}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" "$RUN_BY" "$(tr -cd '0-9A-Za-z:. -' < "$STAMP_FILE" 2>/dev/null)" \
        "$TESTS" > "$WORK/result.json"
    install -d -m 755 -o root -g root "$(dirname "$RESULT_FILE")"
    install -m 644 -o root -g root "$WORK/result.json" "$RESULT_FILE"
    echo "result written to $RESULT_FILE"
}

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

# The kill switch's DHCP renewal rule with the crawler's uid in place of systemd-network's and no target: it decides
# nothing, and only counts packets that match the rule in every field but the owner.
dhcp_twin() {
    iptables -S OUTPUT | awk '/--sport 68 --dport 67 .*-j ACCEPT$/ {print; exit}' |
        sed -E "s/^-A OUTPUT //; s/--uid-owner [0-9]+ -j ACCEPT$/--uid-owner $(id -u crawler)/"
}

# The probe gets a capability, so it runs only from a copy nobody but root can change, never the crawler's.
roots_alone() {
    ! stat -c '%U %A' "$@" | awk '$1 != "root" || substr($2, 6, 1) == "w" || substr($2, 9, 1) == "w"' | grep -q .
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
if dns_blocked; then judged dns-block report "test 2 DNS block" pass; else judged dns-block report "test 2 DNS block" fail; fi

echo "test 4: redirect trap, mocked 302 to https://example.com (as crawler, inside the capture)"
if as_crawler bash -c "cd $APP && $PY -m unittest tests.test_fetcher.RedirectTrapTest" >"$WORK/t4.txt" 2>&1; then
    judged redirect-trap report "test 4 redirect trap ($(grep -o 'Ran [0-9]* tests' "$WORK/t4.txt"))" pass
else
    cat "$WORK/t4.txt"
    judged redirect-trap report "test 4 redirect trap" fail
fi

echo "test 3: the DHCP renewal rule is closed to the crawler (as crawler with CAP_NET_RAW alone, inside the capture)"
DHCP=pass
GATEWAY=$(ip -4 route show default | awk '{print $3; exit}')
BROADCAST=$(ip -4 -o addr show dev "$DEV" | awk '{for (i = 1; i < NF; i++) if ($i == "brd") {print $(i + 1); exit}}')
DHCP_PROBE=$(dirname "$(readlink -f "$0")")/dhcp_probe.py
read -ra TWIN <<<"$(dhcp_twin)"
DHCP_TWIN=none
if [ ${#TWIN[@]} -gt 0 ]; then
    iptables -I OUTPUT 1 "${TWIN[@]}"
    trap 'iptables -D OUTPUT "${TWIN[@]}" 2>/dev/null; capture_cleanup' EXIT
fi
if ! roots_alone "$DHCP_PROBE" "$(dirname "$DHCP_PROBE")"; then
    echo "      $DHCP_PROBE is not root's alone, so it is not run"
    DHCP=fail
elif ! setpriv --reuid crawler --regid crawler --init-groups --inh-caps -all,+net_raw --ambient-caps -all,+net_raw \
        --bounding-set -all,+net_raw -- python3 -I "$DHCP_PROBE" "gateway=$GATEWAY" "subnet-broadcast=$BROADCAST" \
        limited-broadcast=255.255.255.255 2>&1 | sed 's/^/      /'; then
    DHCP=fail
fi
if [ ${#TWIN[@]} -gt 0 ]; then
    DHCP_TWIN=$(iptables -L OUTPUT 1 -v -x -n | awk '{print $1}')
    iptables -D OUTPUT "${TWIN[@]}"
fi

echo "test 3: traffic during the window comes from the fetcher probe (steps 2 to 4)"
# A probe that never fetched leaves a quiet capture, and a quiet capture proves nothing about the fetcher, so a
# probe that fails or overruns fails test 3. exec makes the probe timeout's own child, so the kill reaches it.
PROBE=pass
if ! as_crawler timeout -k 10 "$PROBE_SECONDS" bash -c "cd $APP && exec $PY -m tests.live.probe /home/crawler/settings.toml" \
        2>&1 | sed 's/^/      /'; then
    PROBE=fail
    echo "      the fetcher probe failed or ran past ${PROBE_SECONDS}s"
fi
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
judged clearnet-block report "test 1 clearnet block" "$T1"

# Each probe datagram was refused by netfilter (the probe exits 1 otherwise), the two inside the rule's subnet matched
# it in every field but the owner, and none of the probe's 24-byte datagrams reached the wire.
dhcp_judge() {
    local wire
    wire=$(captured "udp dst port 67 and udp[4:2] = 24")
    echo "      crawler datagrams matching the DHCP rule but for the owner: $DHCP_TWIN (2: gateway, subnet broadcast)"
    echo "      the probe's datagrams on the wire: $wire"
    { [ "$DHCP_TWIN" = 2 ] || [ "$DHCP_TWIN" = none ]; } && [ "$wire" = 0 ] || DHCP=fail
    report "$1" "$DHCP"
}

judge_test3() {
    dhcp_judge "$1: the DHCP renewal rule is closed to the crawler"
    if [ "$PROBE" = pass ]; then
        capture_judge "$1"
    else
        capture_judge "$1 (traffic only)"
        report "$1: the fetcher probe did not finish, so the capture shows no fetch" fail
    fi
}
judged packet-capture judge_test3 "test 3 packet capture: only tor talks to the network"
write_result
exit $FAILED
